"""The Store: all durable state lives under one data dir as folders, marker
files, and symlinks. Every mutation is an atomic create/rename/unlink so
readers never observe partial state. This module is the on-disk data model."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import shutil
import threading
import time
from pathlib import Path

from .config import (GID_RE, MID_RE, USER_RE, PBKDF2_ITERS, SESSION_IDLE_DAYS)
from .errors import ApiError
from .roster import Roster
from .util import now_ms, mid_date, msg_dirs_newest_first

class Store:
    """All state lives under one data dir; every mutation is an atomic
    create/rename/unlink so readers never see partial state."""

    def __init__(self, root, iters: int = PBKDF2_ITERS, roster=None):
        self.root = Path(root).resolve()
        self.iters = iters
        # THE user database: one passwd-style file, password hash last field
        # (see roster.py). Defaults to <data>/passwd; --roster overrides.
        # Absent file = zero users until it exists.
        self.roster = Roster(Path(roster) if roster else self.root / "passwd")
        self._id_lock = threading.Lock()
        self._quota_lock = threading.Lock()
        # Held by the router across the ONE rename that moves a message out of
        # incoming/, and by recount_all_storage across its walk of incoming/.
        # Without it the walk and the rename race: the walk lists a message in
        # incoming/, the router moves it, the walk's read fails and counts 0 —
        # or the walk counts it AND the later groups/ walk counts it again.
        self._route_lock = threading.Lock()
        for name in ("tmp", "incoming", "users", "groups", "archive", "rejected"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        # High-water mark for the message-id clock, persisted so a restart
        # after an NTP step back still issues strictly increasing ids.
        self._hwm_path = self.root / "id_hwm"
        try:
            self._last_ms = int(self._hwm_path.read_text())
        except (OSError, ValueError):
            self._last_ms = 0
        # Defence in depth: the hwm write is best-effort, so a lost/stale hwm
        # plus a backward clock step could issue ids BELOW existing on-disk
        # stamps. Below a join stamp, new messages are silently hidden behind
        # the join-gate; below existing message ids, history order corrupts and
        # a new message can land in a day folder old enough for the janitor to
        # archive it immediately. Seed the floor from both: every join stamp
        # (one small file per membership) and the newest message id per group
        # (msg_dirs_newest_first is lazy — day names plus one day's entries).
        self._last_ms = max(self._last_ms, self._clock_floor())

    def _clock_floor(self) -> int:
        floor = 0
        groups = self.root / "groups"
        try:
            gdirs = list(groups.iterdir())
        except OSError:
            return floor
        for gdir in gdirs:
            try:
                for mf in (gdir / "members").iterdir():
                    try:
                        floor = max(floor, int(mf.read_text().strip() or 0))
                    except (OSError, ValueError):
                        pass
            except OSError:
                pass
            newest = next(msg_dirs_newest_first(gdir), None)
            if newest is not None:
                try:
                    floor = max(floor, int(newest.name[:13]))
                except ValueError:
                    pass
        return floor

    def next_ts(self) -> int:
        """A strictly-increasing millisecond stamp on ONE clock — persisted and
        monotonic even across a restart or an NTP step back. Message ids AND
        member join stamps both draw from this, so they are directly comparable
        (the join-time history/tick gate can't be fooled by clock skew)."""
        with self._id_lock:
            ms = max(now_ms(), self._last_ms + 1)
            self._last_ms = ms
            try:
                self.write_atomic(self._hwm_path, str(ms).encode())
            except OSError:
                pass  # persistence is best-effort; ordering still holds in-process
        return ms

    def next_mid(self) -> str:
        return f"{self.next_ts():013d}-{secrets.token_hex(6)}"

    # ---- paths -----------------------------------------------------------
    def user_dir(self, user: str) -> Path:
        return self.root / "users" / user

    def queue_dir(self, user: str) -> Path:
        return self.user_dir(user) / "queue"

    def group_dir(self, gid: str) -> Path:
        return self.root / "groups" / gid

    def msg_dir(self, gid: str, mid: str) -> Path:
        return self.group_dir(gid) / mid_date(mid) / mid

    def gid_of(self, msg_path) -> str | None:
        try:
            rel = Path(msg_path).resolve().relative_to(self.root)
        except ValueError:
            return None
        parts = rel.parts
        if len(parts) >= 2 and parts[0] == "groups" and GID_RE.match(parts[1]):
            return parts[1]
        return None

    def write_atomic(self, path: Path, data: bytes) -> None:
        tmp = self.root / "tmp" / f"w-{secrets.token_hex(8)}"
        tmp.write_bytes(data)
        os.replace(tmp, path)

    # ---- per-user storage accounting -------------------------------------
    # A running byte total per user, kept as a fast counter so an upload can
    # check the quota without walking the tree. The counter is a CACHE, not a
    # ledger: the janitor periodically recomputes it from the files themselves
    # (recount_storage), so a missed credit-back can only ever cost one janitor
    # interval instead of permanently inflating a user's usage until they are
    # locked out. That makes the immediate credit-backs an optimization rather
    # than a correctness requirement every future code path must remember.
    def storage_used(self, user: str) -> int:
        try:
            return int((self.user_dir(user) / "storage_used").read_text())
        except (OSError, ValueError):
            return 0

    def recount_all_storage(self) -> dict:
        """Re-derive EVERY user's usage in ONE walk of the tree, and write the
        counters. Doing this per user re-walked the same messages once per
        account — with 25 users that was literally 25x the work for the same
        answer, every janitor sweep.

        Bytes are attributed to whoever uploaded them, in whatever group they
        still live in: leaving a group does not un-count attachments that are
        still on disk (and still visible to the members who remain)."""
        totals: dict = {}
        users_root = self.root / "users"
        try:
            names = [p.name for p in users_root.iterdir() if p.is_dir()]
        except FileNotFoundError:
            return {}
        for user in names:
            total = 0
            try:
                for p in (users_root / user / "staged").iterdir():
                    if p.name.endswith(".meta"):
                        continue
                    try:
                        total += p.stat().st_size
                    except OSError:
                        pass
            except FileNotFoundError:
                pass
            totals[user] = total
        groups = []
        for root in (self.root / "groups", self.root / "archive"):
            try:
                groups.extend(root.iterdir())   # archived bytes are still bytes
            except FileNotFoundError:
                pass
        def count_msg(mdir: Path) -> None:
            try:
                sender = (mdir / "from").read_text().strip()
                if sender not in totals:
                    return                # unknown/removed account
                for blob in (mdir / "attachments").iterdir():
                    if not blob.name.endswith(".meta"):
                        totals[sender] += blob.stat().st_size
            except OSError:
                return

        # incoming/ FIRST, under the route lock: send() returns the moment a
        # message is spooled and the router is woken, so its bytes live here
        # until the router thread gets scheduled — under load, long enough for
        # a recount to run in between and refund the sender for a message that
        # is durable and about to be delivered. The lock pins every message
        # listed here in place while it is counted; the mids are remembered so
        # the groups/ walk below, which runs after the lock is released and
        # may find the same message freshly routed, cannot count it twice.
        counted: set[str] = set()
        with self._route_lock:
            try:
                for mdir in (self.root / "incoming").iterdir():
                    if mdir.is_dir():
                        count_msg(mdir)
                        counted.add(mdir.name)
            except FileNotFoundError:
                pass
        for gdir in groups:
            for mdir in msg_dirs_newest_first(gdir):
                if mdir.name not in counted:
                    count_msg(mdir)
        # rejected/: bounced messages, which nothing reclaimed. Leaving them
        # out meant the hourly recount refunded the sender while the blobs
        # stayed forever — race a send against leaving the group, park up to
        # 8x50MB per win, get the allowance back an hour later. Message dirs,
        # not group dirs, so walked directly; a bounce is a rename too, hence
        # the same mid guard.
        try:
            for mdir in (self.root / "rejected").iterdir():
                if mdir.is_dir() and mdir.name not in counted:
                    count_msg(mdir)
        except FileNotFoundError:
            pass
        for user, total in totals.items():
            with self._quota_lock:
                try:
                    self.write_atomic(self.user_dir(user) / "storage_used",
                                      str(total).encode())
                except OSError:
                    pass
        return totals

    def recount_storage(self, user: str) -> int:
        """One user's authoritative total (admin/tests). Shares the single walk
        rather than duplicating it — see recount_all_storage."""
        return self.recount_all_storage().get(user, 0)

    def add_storage(self, user: str, delta: int) -> None:
        with self._quota_lock:
            new = max(0, self.storage_used(user) + delta)
            self.write_atomic(self.user_dir(user) / "storage_used",
                              str(new).encode())

    def reserve_storage(self, user: str, length: int, quota: int) -> None:
        """Atomic check-and-reserve so parallel uploads can't overshoot."""
        with self._quota_lock:
            used = self.storage_used(user)
            if used + length > quota:
                raise ApiError(413, "storage quota exceeded")
            self.write_atomic(self.user_dir(user) / "storage_used",
                              str(used + length).encode())

    # ---- users / auth ----------------------------------------------------
    # The user FILE (see roster.py) is the entire user database: identity,
    # display, flags, and the password hash as its last field. There is no
    # per-account credential file, and no manual provisioning step: an
    # account's directory tree is created on FIRST CONTACT — the first
    # successful login, or the first message routed to the user.

    def add_user(self, user: str, password: str, display: str | None = None,
                 must_change: bool = True) -> None:
        """Append the user to the file (nothing else): the directory follows
        on first contact. Hashing happens before any write, so a failure
        anywhere can never leave a half-made entry behind."""
        from .roster import make_hash
        self.roster.add_entry(user, display, make_hash(password, self.iters),
                              must_change=must_change)

    def provision(self, user: str) -> None:
        """Create the account's directory tree, idempotently. Built whole in
        tmp/ and renamed in atomically: a crash leaves only a tmp orphan
        (janitor-pruned) and a concurrent first-contact race is settled by
        the rename — the loser just uses the winner's tree."""
        d = self.user_dir(user)
        if d.is_dir():
            return
        tmp = self.root / "tmp" / f"u-{user}-{secrets.token_hex(4)}"
        for sub in ("sessions", "queue", "staged", "nonces", "starred"):
            (tmp / sub).mkdir(parents=True)
        try:
            os.rename(tmp, d)
        except OSError as e:
            shutil.rmtree(tmp, ignore_errors=True)
            if e.errno in (errno.EEXIST, errno.ENOTEMPTY, errno.ENOTDIR):
                return                    # someone else provisioned: done
            raise ApiError(503, "user provisioning failed, please retry")

    def user_exists(self, user: str) -> bool:
        """Listed in the user file, disabled or not. Admin paths (passwd
        reset, bouncing a message back to its sender) act on listed users
        whether or not they may currently connect."""
        return (bool(USER_RE.match(user))
                and self.roster.entry(user) is not None)

    def may_connect(self, user: str) -> bool:
        """Listed AND not disabled — someone who can actually be a party to
        a conversation. The predicate every "is that a real user?" check in
        the API wants: a disabled/removed account must not be DM-able or
        addable to a group, because nothing sent to it can ever be read."""
        return bool(USER_RE.match(user)) and self.roster.allows(user)

    def verify_password(self, user: str, password: str):
        """The file's entry when the password matches, else None. Timing is
        flat across every failure shape: unknown user, password-less entry,
        malformed hash spec, and wrong password all cost one PBKDF2; the
        `disabled` check runs AFTER the hash for the same reason."""
        from .roster import check_hash, burn
        e = self.roster.entry(user)
        # what a REAL verify against this file costs — not self.iters, which
        # is what the next hash we WRITE will cost. The two differ for as long
        # as it takes everyone to change their password after an operator
        # raises PBKDF2_ITERS, and burning the wrong one makes an unknown
        # username measurably slower (or faster) than a known one.
        cost = self.roster.hash_cost(self.iters)
        if e is None or not e.password:
            burn(cost)
            return None
        if not check_hash(password, e.password, cost):
            return None
        return None if e.disabled else e

    def set_password(self, user: str, password: str,
                     must_change: bool = False) -> None:
        from .roster import make_hash
        self.roster.set_password(user, make_hash(password, self.iters),
                                 must_change=must_change)

    # ---- sessions (token = "<user>:<secret>", stored as sha256 marker) ----
    def new_session(self, user: str) -> str:
        # first contact, post successful auth: the account's tree appears the
        # first time a session is actually issued
        self.provision(user)
        token = f"{user}:{secrets.token_urlsafe(32)}"
        (self.user_dir(user) / "sessions" /
         hashlib.sha256(token.encode()).hexdigest()).touch()
        return token

    def session_user(self, token: str) -> str | None:
        user, sep, _ = token.partition(":")
        if not sep or not USER_RE.match(user):
            return None
        # Revocation has to reach ALREADY-ISSUED tokens, or removing someone
        # from the roster wouldn't remove them from the server — it would
        # only stop them logging in again. Checked before the session marker
        # is touched, so a revoked token's mtime is never refreshed either.
        # The marker is NOT deleted: a transiently unreadable roster denies
        # (fail closed) but must not log everybody out permanently.
        if not self.roster.allows(user):
            return None
        p = (self.user_dir(user) / "sessions" /
             hashlib.sha256(token.encode()).hexdigest())
        try:
            st = p.stat()
        except OSError:
            return None
        age = time.time() - st.st_mtime
        if age > SESSION_IDLE_DAYS * 86400:
            p.unlink(missing_ok=True)
            return None
        if age > 3600:  # mtime = last use, refreshed at most hourly
            try:
                os.utime(p)
            except OSError:
                return None  # session revoked concurrently (logout/passwd)
        return user

    def drop_session(self, token: str) -> None:
        user, _, _ = token.partition(":")
        if USER_RE.match(user):
            (self.user_dir(user) / "sessions" /
             hashlib.sha256(token.encode()).hexdigest()).unlink(missing_ok=True)

    # ---- groups ------------------------------------------------------------
    def members(self, gid: str) -> list[str]:
        md = self.group_dir(gid) / "members"
        try:
            return sorted(p.name for p in md.iterdir())
        except FileNotFoundError:
            raise ApiError(404, "no such group")

    def is_member(self, gid: str, user: str) -> bool:
        return (self.group_dir(gid) / "members" / user).exists()

    def group_name(self, gid: str) -> str | None:
        f = self.group_dir(gid) / "name"
        return f.read_text() if f.is_file() else None

    def joined_at(self, gid: str, user: str) -> int:
        """Join timestamp on the SAME clock as message ids (members see history
        only from their join onward — WhatsApp group semantics). The marker
        file holds the stamp; an empty legacy marker falls back to its mtime."""
        p = self.group_dir(gid) / "members" / user
        try:
            txt = p.read_text().strip()
        except OSError:
            return 0
        if txt:
            return int(txt)
        try:
            return int(p.stat().st_mtime * 1000)   # pre-stamp marker
        except OSError:
            return 0

    def _publish_group(self, gid: str, name: str, members: set[str]) -> bool:
        """Build the group dir in tmp/, then atomically rename into place."""
        b = self.root / "tmp" / f"g-{secrets.token_hex(8)}"
        (b / "members").mkdir(parents=True)
        stamp = str(self.next_ts())   # all founding members join "now"
        for u in sorted(members):
            (b / "members" / u).write_text(stamp)
        if name:
            (b / "name").write_text(name)
        try:
            os.rename(b, self.group_dir(gid))
            return True
        except OSError:  # already exists (concurrent create)
            shutil.rmtree(b, ignore_errors=True)
            return False

    def create_group(self, name: str, members: set[str]) -> str:
        while True:
            gid = "g-" + secrets.token_hex(4)
            if self._publish_group(gid, name, members):
                return gid

    def ensure_dm(self, a: str, b: str) -> str:
        """Deterministic DM id. Usernames may contain '-', so the readable
        'd-<a>-<b>' form can collide for distinct pairs (e.g. {a,b-c} and
        {a-b,c}). The common case keeps the readable id; on an actual collision
        (existing group whose members differ) we fall back to a hash-suffixed
        id so the second pair still gets its own DM instead of a 403."""
        want = {a, b}
        gid = "d-" + "-".join(sorted((a, b)))
        gdir = self.group_dir(gid)
        if not gdir.exists():
            if self._publish_group(gid, "", want):
                return gid
        if set(self.members(gid)) == want:
            return gid
        # collision: disambiguate with a stable hash of the exact pair
        h = hashlib.sha256("\x00".join(sorted(want)).encode()).hexdigest()[:12]
        gid = f"d-{h}"
        if not self.group_dir(gid).exists():
            self._publish_group(gid, "", want)
        return gid

    # ---- queue -------------------------------------------------------------
    def queue_add(self, user: str, entry: str, target: Path) -> None:
        link = self.queue_dir(user) / entry
        rel = os.path.relpath(target, link.parent)
        try:
            os.symlink(rel, link)
        except FileExistsError:
            pass
        except FileNotFoundError:
            # Either the user was deleted underneath us, or they are LISTED
            # but have never logged in: first contact can be a message routed
            # TO someone (a DM to a colleague who hasn't installed the app
            # yet must queue, not vanish). Provision and retry once.
            if self.roster.entry(user) is None:
                return
            try:
                self.provision(user)
                os.symlink(rel, link)
            except (OSError, ApiError):
                pass

    # ---- messages ----------------------------------------------------------
    def _spool_dir(self, mid: str, gid: str, sender: str, text: str) -> Path:
        b = self.root / "tmp" / f"m-{mid}"
        (b / "attachments").mkdir(parents=True)
        (b / "to").write_text(gid)
        (b / "from").write_text(sender)
        (b / "message.txt").write_text(text)
        return b

    def spool_message(self, sender: str, gid: str, text: str,
                      staged: list[str], nonce: str,
                      reply_to: str | None = None) -> str:
        nf = self.user_dir(sender) / "nonces" / nonce
        # Claim the nonce atomically as an EMPTY file before any work. The mid
        # is written into it only after the message is durably spooled, so a
        # concurrent/later retry either (a) reads the mid and returns it — no
        # duplicate, no double-consumed attachments — or (b) sees the claim
        # released because the first attempt aborted, and retries cleanly.
        try:
            os.close(os.open(nf, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        except FileExistsError:
            return self._await_nonce(nf)
        try:
            mid = self.next_mid()
            udir = self.user_dir(sender)
            # Validate every staged input before moving ANY, so a bad/expired
            # id can't destroy attachments already moved for earlier ids.
            srcs = []
            for fid in staged:
                src = udir / "staged" / fid
                meta = udir / "staged" / (fid + ".meta")
                if not (src.is_file() and meta.is_file()):
                    raise ApiError(400, "unknown file id (upload first)")
                srcs.append((src, meta))
            b = self._spool_dir(mid, gid, sender, text)
            if reply_to:   # validated by the api layer before spooling
                (b / "reply_to").write_text(reply_to)
            try:
                for i, (src, meta) in enumerate(srcs, 1):
                    os.replace(src, b / "attachments" / str(i))
                    os.replace(meta, b / "attachments" / f"{i}.meta")
                    # The optional preview rides along ONLY if the meta commits
                    # to it. upload_thumb writes the .thumb file BEFORE recording
                    # it in the meta, so a "thumb" key implies the file; a
                    # .thumb without the key is an upload still in flight —
                    # leaving it in staged lets upload_thumb's own meta-gone path
                    # (or the janitor) reclaim it, instead of stranding an
                    # un-servable orphan whose bytes drift the quota counter.
                    tsrc = src.with_name(src.name + ".thumb")
                    if tsrc.is_file():
                        try:
                            committed = "thumb" in json.loads(
                                (b / "attachments" / f"{i}.meta").read_text())
                        except (OSError, ValueError):
                            committed = False
                        if committed:
                            os.replace(tsrc, b / "attachments" / f"{i}.thumb")
                os.replace(b, self.root / "incoming" / mid)
            except OSError:  # janitor pruned a staged file mid-move, or fs error
                shutil.rmtree(b, ignore_errors=True)
                raise ApiError(503, "send failed, please retry")
        except Exception:
            nf.unlink(missing_ok=True)  # release the claim so a retry can work
            raise
        try:
            self.write_atomic(nf, mid.encode())  # publish the mid last
        except OSError:
            # The message is already durable in incoming/ and WILL deliver once;
            # we just couldn't record the dedup mid. Releasing the empty claim
            # beats leaving it: a lingering empty nonce 503s every retry for an
            # hour (until the janitor prunes it) and then duplicates the send.
            # The message is sent, so hand back its id. A client retry that
            # races this narrow window could still duplicate — far rarer than
            # the guaranteed wedge-then-duplicate it replaces.
            nf.unlink(missing_ok=True)
        return mid

    def _await_nonce(self, nf: Path) -> str:
        """A concurrent request holds the claim. Wait for it to fill the nonce
        with its mid (dedup), or for it to release the claim on failure (in
        which case the caller should retry)."""
        for _ in range(100):
            try:
                mid = nf.read_text()
            except FileNotFoundError:
                raise ApiError(503, "send failed, please retry")  # claimer aborted
            if mid:
                return mid
            time.sleep(0.01)
        raise ApiError(503, "send in progress, please retry")

    def spool_system(self, actor: str, gid: str, text: str, event: dict) -> str:
        """Group lifecycle (created/join/leave) is announced in-band: a system
        event is just a message dir with a `system` marker, so members learn
        about new groups and roster changes through the one queue they already
        poll. Only server code writes the marker — clients cannot inject it."""
        mid = self.next_mid()
        b = self._spool_dir(mid, gid, actor, text)
        (b / "system").write_text(json.dumps(event))
        os.replace(b, self.root / "incoming" / mid)
        return mid


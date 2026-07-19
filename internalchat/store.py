"""The Store: all durable state lives under one data dir as folders, marker
files, and symlinks. Every mutation is an atomic create/rename/unlink so
readers never observe partial state. This module is the on-disk data model."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import (GID_RE, MID_RE, USER_RE, PBKDF2_ITERS, SESSION_IDLE_DAYS)
from .errors import ApiError
from .util import now_ms, mid_date, msg_dirs_newest_first

class Store:
    """All state lives under one data dir; every mutation is an atomic
    create/rename/unlink so readers never see partial state."""

    def __init__(self, root, iters: int = PBKDF2_ITERS):
        self.root = Path(root).resolve()
        self.iters = iters
        self._id_lock = threading.Lock()
        for name in ("tmp", "incoming", "users", "groups", "archive", "rejected"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        # High-water mark for the message-id clock, persisted so a restart
        # after an NTP step back still issues strictly increasing ids.
        self._hwm_path = self.root / "id_hwm"
        try:
            self._last_ms = int(self._hwm_path.read_text())
        except (OSError, ValueError):
            self._last_ms = 0

    def next_mid(self) -> str:
        """Sorted listings are the timeline, so ids must be STRICTLY
        increasing — even across a restart or an NTP step back. The high-water
        mark is persisted, and each id is at least the previous + 1ms, so two
        sends never share a timestamp prefix (deterministic ordering)."""
        with self._id_lock:
            ms = max(now_ms(), self._last_ms + 1)
            self._last_ms = ms
            try:
                self.write_atomic(self._hwm_path, str(ms).encode())
            except OSError:
                pass  # persistence is best-effort; ordering still holds in-process
        return f"{ms:013d}-{secrets.token_hex(6)}"

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

    # ---- users / auth ----------------------------------------------------
    def add_user(self, user: str, password: str, display: str | None = None,
                 must_change: bool = True) -> None:
        if not USER_RE.match(user):
            raise ApiError(400, "bad username (allowed: [a-z0-9_.-]{1,32})")
        d = self.user_dir(user)
        if d.exists():
            raise ApiError(409, "user exists")
        for sub in ("sessions", "queue", "staged", "nonces"):
            (d / sub).mkdir(parents=True)
        salt = secrets.token_bytes(16)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, self.iters)
        auth = {"display": display or user, "salt": salt.hex(), "hash": h.hex(),
                "iters": self.iters, "must_change": must_change, "created": now_ms()}
        self.write_atomic(d / "auth.json", json.dumps(auth).encode())

    def user_exists(self, user: str) -> bool:
        return bool(USER_RE.match(user)) and (self.user_dir(user) / "auth.json").is_file()

    def verify_password(self, user: str, password: str) -> dict | None:
        try:
            auth = json.loads((self.user_dir(user) / "auth.json").read_text())
        except (FileNotFoundError, ValueError):
            # burn comparable time so unknown users aren't distinguishable
            hashlib.pbkdf2_hmac("sha256", password.encode(), b"x" * 16, self.iters)
            return None
        h = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                bytes.fromhex(auth["salt"]), auth["iters"])
        return auth if hmac.compare_digest(h.hex(), auth["hash"]) else None

    def set_password(self, user: str, password: str,
                     must_change: bool = False) -> None:
        auth = json.loads((self.user_dir(user) / "auth.json").read_text())
        salt = secrets.token_bytes(16)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, self.iters)
        auth.update(salt=salt.hex(), hash=h.hex(), iters=self.iters,
                    must_change=must_change)
        self.write_atomic(self.user_dir(user) / "auth.json", json.dumps(auth).encode())

    # ---- sessions (token = "<user>:<secret>", stored as sha256 marker) ----
    def new_session(self, user: str) -> str:
        token = f"{user}:{secrets.token_urlsafe(32)}"
        (self.user_dir(user) / "sessions" /
         hashlib.sha256(token.encode()).hexdigest()).touch()
        return token

    def session_user(self, token: str) -> str | None:
        user, sep, _ = token.partition(":")
        if not sep or not USER_RE.match(user):
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
        """The membership marker's mtime IS the join timestamp; members only
        see history from their join onward (WhatsApp group semantics)."""
        try:
            return int((self.group_dir(gid) / "members" / user).stat().st_mtime * 1000)
        except OSError:
            return 0

    def _publish_group(self, gid: str, name: str, members: set[str]) -> bool:
        """Build the group dir in tmp/, then atomically rename into place."""
        b = self.root / "tmp" / f"g-{secrets.token_hex(8)}"
        (b / "members").mkdir(parents=True)
        for u in sorted(members):
            (b / "members" / u).touch()
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
            pass  # user deleted underneath us

    # ---- messages ----------------------------------------------------------
    def _spool_dir(self, mid: str, gid: str, sender: str, text: str) -> Path:
        b = self.root / "tmp" / f"m-{mid}"
        (b / "attachments").mkdir(parents=True)
        (b / "to").write_text(gid)
        (b / "from").write_text(sender)
        (b / "message.txt").write_text(text)
        return b

    def spool_message(self, sender: str, gid: str, text: str,
                      staged: list[str], nonce: str) -> str:
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
            try:
                for i, (src, meta) in enumerate(srcs, 1):
                    os.replace(src, b / "attachments" / str(i))
                    os.replace(meta, b / "attachments" / f"{i}.meta")
                os.replace(b, self.root / "incoming" / mid)
            except OSError:  # janitor pruned a staged file mid-move, or fs error
                shutil.rmtree(b, ignore_errors=True)
                raise ApiError(503, "send failed, please retry")
        except Exception:
            nf.unlink(missing_ok=True)  # release the claim so a retry can work
            raise
        self.write_atomic(nf, mid.encode())  # publish the mid last
        return mid

    def _await_nonce(self, nf: Path) -> str:
        """A concurrent request holds the claim. Wait for it to fill the nonce
        with its mid (dedup), or for it to release the claim on failure (in
        which case the caller should retry)."""
        for _ in range(100):
            if not nf.exists():
                raise ApiError(503, "send failed, please retry")  # claimer aborted
            mid = nf.read_text()
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


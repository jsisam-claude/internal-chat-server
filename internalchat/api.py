"""The Api: all request-handling business logic, independent of HTTP. The
web layer (server.py) is a thin shell that parses a request, calls one of
these methods, and serializes the result."""
from __future__ import annotations

import hashlib
import heapq
import json
import os
import secrets
import shutil
import threading
import time
from pathlib import Path

from .config import (
    GID_RE, MID_RE, USER_RE, NONCE_RE, FID_RE, ENTRY_RE,
    MAX_TEXT, MAX_FILE, MAX_ATTACHMENTS, MAX_STAGED, MAX_WAIT,
    MAX_GROUP_MEMBERS, SEND_LIMIT, SEND_WINDOW, UPLOAD_LIMIT, UPLOAD_WINDOW,
    LOGIN_WINDOW, LOGIN_USER_LIMIT, LOGIN_IP_LIMIT, USER_STORAGE_QUOTA,
    GROUP_OP_LIMIT, GROUP_OP_WINDOW, MAX_POLLS_PER_USER,
    SEARCH_LIMIT, SEARCH_WINDOW, SEARCH_SCAN_CAP, MAX_SEARCH_Q,
    MAX_REACTION, MAX_STARS, TYPING_TTL, TYPING_CAP,
    PRESENCE_ONLINE_SECS, LASTSEEN_PERSIST_SECS)
from .errors import ApiError
from .util import (now_ms, sanitize_filename, msg_dirs_newest_first,
                   image_mime, audio_mime)
from .ratelimit import RateLimiter
from .store import Store
from .notifier import Notifier
from .router import Router

class Api:
    """Business logic; the HTTP handler is a thin shell around this."""

    def __init__(self, store: Store, notifier: Notifier, router: Router):
        self.store = store
        self.notifier = notifier
        self.router = router
        self.login_limiter = RateLimiter(limit=LOGIN_USER_LIMIT, window=LOGIN_WINDOW)
        self.login_ip_limiter = RateLimiter(limit=LOGIN_IP_LIMIT, window=LOGIN_WINDOW)
        self.send_limiter = RateLimiter(limit=SEND_LIMIT, window=SEND_WINDOW)
        self.upload_limiter = RateLimiter(limit=UPLOAD_LIMIT, window=UPLOAD_WINDOW)
        self.group_limiter = RateLimiter(limit=GROUP_OP_LIMIT,
                                         window=GROUP_OP_WINDOW)
        self.search_limiter = RateLimiter(limit=SEARCH_LIMIT,
                                          window=SEARCH_WINDOW)
        self.limiters = [self.login_limiter, self.login_ip_limiter,
                         self.send_limiter, self.upload_limiter,
                         self.group_limiter, self.search_limiter]
        # per-INSTANCE (not class) so two servers in one process don't share
        # a global parked-poll counter
        self._poll_lock = threading.Lock()
        self._polls: dict = {}   # user -> number of currently-parked long-polls
        # Ephemeral state deliberately lives in MEMORY, not files: typing and
        # presence are signals that expire in seconds — writing markers for
        # them would churn the disk for state nobody should ever recover.
        self._typing_lock = threading.Lock()
        self._typing: dict = {}      # (gid, user) -> expiry (time.time())
        self._seen: dict = {}        # user -> last authenticated activity
        self._seen_persisted: dict = {}   # user -> last time we wrote lastseen

    # ---- auth --------------------------------------------------------------
    def login(self, ip: str, body: dict) -> dict:
        user = body.get("user", "")
        password = body.get("password", "")
        if not (isinstance(user, str) and isinstance(password, str)
                and USER_RE.match(user)):
            raise ApiError(400, "bad credentials")
        self.login_ip_limiter.check(ip)          # caps distinct-username floods
        self.login_limiter.check(f"{ip}/{user}")  # caps guessing one account
        auth = self.store.verify_password(user, password)
        if auth is None:
            raise ApiError(401, "bad credentials")
        return {"token": self.store.new_session(user), "user": user,
                "display": auth["display"], "must_change": auth["must_change"]}

    def change_password(self, user: str, body: dict, keep_token: str) -> dict:
        old, new = body.get("old", ""), body.get("new", "")
        if not isinstance(old, str):        # a non-string old must 400, not 500
            raise ApiError(400, "bad old password")
        if not isinstance(new, str) or len(new) < 8 or len(new) > 128:
            raise ApiError(400, "new password must be 8..128 chars")
        if self.store.verify_password(user, old) is None:
            raise ApiError(403, "old password wrong")
        self.store.set_password(user, new)
        # a password change ends every session except the one making it
        keep = hashlib.sha256(keep_token.encode()).hexdigest()
        for s in (self.store.user_dir(user) / "sessions").iterdir():
            if s.name != keep:
                s.unlink(missing_ok=True)
        return {"ok": True}

    # ---- presence (ephemeral, in-memory) -----------------------------------
    def touch_seen(self, user: str) -> None:
        """Called on every authenticated request. Memory is the truth;
        users/<u>/lastseen is written at most every LASTSEEN_PERSIST_SECS so a
        restart still knows a coarse last-seen without per-request disk churn."""
        now = time.time()
        self._seen[user] = now
        if now - self._seen_persisted.get(user, 0) > LASTSEEN_PERSIST_SECS:
            self._seen_persisted[user] = now
            try:
                self.store.write_atomic(self.store.user_dir(user) / "lastseen",
                                        str(int(now * 1000)).encode())
            except OSError:
                pass

    def _last_seen_ms(self, user: str) -> int | None:
        ts = self._seen.get(user)
        if ts:
            return int(ts * 1000)
        try:
            return int((self.store.user_dir(user) / "lastseen").read_text())
        except (OSError, ValueError):
            return None

    def _online(self, user: str) -> bool:
        return (time.time() - self._seen.get(user, 0) < PRESENCE_ONLINE_SECS
                or self._polls.get(user, 0) > 0)

    # ---- typing (ephemeral, in-memory) --------------------------------------
    def typing(self, user: str, body: dict) -> dict:
        gid = body.get("gid", "")
        if not (isinstance(gid, str) and GID_RE.match(gid)):
            raise ApiError(400, "bad group id")
        if not self.store.is_member(gid, user):
            raise ApiError(403, "not a member")
        with self._typing_lock:
            now = time.time()
            for k in [k for k, exp in self._typing.items() if exp <= now]:
                del self._typing[k]
            if len(self._typing) < TYPING_CAP:
                self._typing[(gid, user)] = now + TYPING_TTL
        for u in self.store.members(gid):
            if u != user:
                self.notifier.notify(u)   # wake their parked polls
        return {"ok": True}

    def _typing_for(self, user: str) -> dict:
        """{gid: {typist: int(expiry)}} for groups `user` belongs to. The
        expiry is included so a parked poll detects a re-ping (same set, new
        expiry) as a change and keeps the watcher's indicator alive."""
        with self._typing_lock:
            now = time.time()
            snapshot = [(g, u, exp) for (g, u), exp in self._typing.items()
                        if exp > now and u != user]
        out: dict = {}
        member_of: dict = {}
        for g, u, exp in snapshot:
            if g not in member_of:
                member_of[g] = self.store.is_member(g, user)
            if member_of[g]:
                out.setdefault(g, {})[u] = int(exp)
        return out

    @staticmethod
    def _typing_payload(t: dict) -> dict:
        return {g: sorted(users) for g, users in t.items()}

    # ---- queue -------------------------------------------------------------
    def list_queue(self, user: str, wait: float) -> dict:
        deadline = time.time() + max(0.0, min(wait, MAX_WAIT))
        # First check is always cheap. Only PARKING (waiting) is capped per
        # user, so one account can't tie up unbounded worker threads by opening
        # many concurrent long-polls.
        items = self._queue_items(user)
        typing = self._typing_for(user)
        if items or time.time() >= deadline:
            return self._queue_resp(items, typing)
        with self._poll_lock:
            over = self._polls.get(user, 0) >= MAX_POLLS_PER_USER
            if not over:
                self._polls[user] = self._polls.get(user, 0) + 1
        if over:
            # too many parked: pause OUTSIDE the lock (holding it across the
            # sleep would serialize every user's poll-cap check) so a naive
            # client can't hot-spin, then return.
            time.sleep(0.5)
            return self._queue_resp(items, typing)
        try:
            while True:
                items = self._queue_items(user)
                cur = self._typing_for(user)
                # return on queue activity, deadline, or a typing-state CHANGE
                # (start/stop/re-ping) — steady silence keeps the poll parked
                if items or cur != typing or time.time() >= deadline:
                    return self._queue_resp(items, cur)
                self.notifier.wait(user, min(1.0, deadline - time.time()))
        finally:
            with self._poll_lock:
                n = self._polls.get(user, 1) - 1
                if n > 0:
                    self._polls[user] = n
                else:
                    self._polls.pop(user, None)   # don't grow the dict forever

    def _queue_resp(self, items: list, typing: dict) -> dict:
        resp = {"queue": items}
        if typing:
            resp["typing"] = self._typing_payload(typing)
        return resp

    def _queue_items(self, user: str) -> list[dict]:
        out = []
        for link in sorted(self.store.queue_dir(user).iterdir()):
            m = ENTRY_RE.match(link.name)
            if not m or not link.is_symlink():
                continue
            # A second device (or the janitor) may unlink this entry between
            # our checks; treat any such disappearance as "gone" rather than
            # letting a FileNotFoundError 500 the whole long-poll.
            try:
                mid, kind, uid = m.groups()
                target = Path(os.path.realpath(link))
                gid = self.store.gid_of(target)
                if kind is None and not target.is_dir():
                    link.unlink(missing_ok=True)  # target archived/gone: drop
                    continue
                at = int(link.lstat().st_mtime * 1000)
            except FileNotFoundError:
                continue
            item = {"entry": link.name,
                    "kind": {"d": "delivered", "r": "read", "x": "failed",
                             "a": "reaction", "u": "updated",
                             None: "msg"}[kind],
                    "id": mid, "gid": gid, "at": at}
            if uid:
                item["user"] = uid
            out.append(item)
        return out

    def peek(self, user: str, entry: str) -> dict:
        if not MID_RE.match(entry):
            raise ApiError(400, "bad message id")
        link = self.store.queue_dir(user) / entry
        if not link.is_symlink():
            raise ApiError(404, "not in your queue")
        mdir = Path(os.path.realpath(link))
        gid = self.store.gid_of(mdir)
        if gid is None or not mdir.is_dir():
            raise ApiError(404, "message gone")
        # A queue entry can outlive membership if a stale symlink survives a
        # leave (or a router/leave race), so authorize on live membership too —
        # never serve message content for a group the user is not in.
        if not self.store.is_member(gid, user):
            link.unlink(missing_ok=True)
            raise ApiError(403, "not a member")
        return self.render_msg(mdir)

    def _stamp(self, mdir: Path, user: str, kind: str) -> bool:
        """One code path for both flags: create the marker and queue the
        matching ~d~/~r~ event to the sender. Keeps 'read implies delivered'
        and 'no ticks on system announcements or own messages' in one place.
        Returns True if the marker was new."""
        marker = mdir / ("readby" if kind == "r" else "deliveredto") / user
        marker.parent.mkdir(exist_ok=True)
        if marker.exists():
            return False
        if kind == "r":
            self._stamp(mdir, user, "d")
        marker.touch()
        sender = (mdir / "from").read_text().strip()
        if sender != user and not (mdir / "system").exists():
            self.store.queue_add(sender, f"{mdir.name}~{kind}~{user}", mdir)
            self.notifier.notify(sender)
        return True

    def confirm(self, user: str, entries: list[str]) -> dict:
        """Dequeue-confirm: remove queue symlinks; for message entries also
        stamp the arrival flag and queue a ~d~ event to the sender."""
        confirmed = 0
        for name in entries[:500]:
            m = ENTRY_RE.match(name)
            if not m:
                raise ApiError(400, "bad queue entry")
            link = self.store.queue_dir(user) / name
            if not link.is_symlink():
                continue
            if m.group(2) is None:  # a message entry, not a flag event
                mdir = Path(os.path.realpath(link))
                gid = self.store.gid_of(mdir)
                # only stamp delivered if the user is genuinely still a member;
                # a stale entry for a left group is just unlinked
                if gid and mdir.is_dir() and self.store.is_member(gid, user):
                    self._stamp(mdir, user, "d")
            link.unlink(missing_ok=True)
            confirmed += 1
        return {"confirmed": confirmed}

    def viewed(self, user: str, body: dict) -> dict:
        gid = body.get("gid", "")
        ids = body.get("ids", [])
        if not (isinstance(gid, str) and GID_RE.match(gid)):
            raise ApiError(400, "bad group id")
        if not isinstance(ids, list):
            raise ApiError(400, "bad ids")
        if not self.store.is_member(gid, user):
            raise ApiError(403, "not a member")
        marked = 0
        for mid in ids[:500]:
            if not (isinstance(mid, str) and MID_RE.match(mid)):
                raise ApiError(400, "bad message id")
            mdir = self.store.msg_dir(gid, mid)
            if not mdir.is_dir():
                continue
            sender = (mdir / "from").read_text().strip()
            if sender == user or (mdir / "system").exists():
                continue
            if self._stamp(mdir, user, "r"):
                marked += 1
        return {"marked": marked}

    # ---- sending -----------------------------------------------------------
    def send(self, user: str, body: dict) -> dict:
        text = body.get("text", "")
        nonce = body.get("nonce", "")
        files = body.get("files", [])
        if not (isinstance(text, str) and len(text) <= MAX_TEXT):
            raise ApiError(400, "bad text")
        if not (isinstance(nonce, str) and NONCE_RE.match(nonce)):
            raise ApiError(400, "bad nonce (client must send 8..64 url-safe chars)")
        if not (isinstance(files, list) and len(files) <= MAX_ATTACHMENTS
                and all(isinstance(f, str) and FID_RE.match(f) for f in files)):
            raise ApiError(400, "bad files list")
        if len(set(files)) != len(files):   # a repeated fid would be consumed
            raise ApiError(400, "duplicate file id")  # once, then destroyed
        if not text.strip() and not files:
            raise ApiError(400, "empty message")
        to = body.get("to")
        gid = body.get("gid")
        if isinstance(to, str) and to:
            if not self.store.user_exists(to):
                raise ApiError(404, "no such user")
            if to == user:
                raise ApiError(400, "cannot message yourself")
            gid = self.store.ensure_dm(user, to)
        elif not (isinstance(gid, str) and GID_RE.match(gid)):
            raise ApiError(400, "need 'to' or 'gid'")
        if not self.store.is_member(gid, user):
            raise ApiError(403, "not a member")
        reply_to = body.get("reply_to")
        if reply_to is not None:
            if not (isinstance(reply_to, str) and MID_RE.match(reply_to)):
                raise ApiError(400, "bad reply_to")
            # the quoted message must exist in THIS group and be visible to
            # the sender (post-join) — no quoting across groups or history
            if (int(reply_to[:13]) < self.store.joined_at(gid, user)
                    or not self.store.msg_dir(gid, reply_to).is_dir()):
                raise ApiError(404, "reply target not found")
        self.send_limiter.check(user)  # cap message/fan-out floods per user
        mid = self.store.spool_message(user, gid, text, files, nonce, reply_to)
        self.router.wake.set()
        return {"id": mid, "gid": gid}

    def _visible_mdir(self, user: str, gid: str, mid: str) -> Path:
        """Resolve (gid, mid) to a message dir the user is allowed to touch:
        member of the group, message exists, and not from before their join."""
        if not (isinstance(gid, str) and GID_RE.match(gid)
                and isinstance(mid, str) and MID_RE.match(mid)):
            raise ApiError(400, "bad ids")
        if not self.store.is_member(gid, user):
            raise ApiError(403, "not a member")
        if int(mid[:13]) < self.store.joined_at(gid, user):
            raise ApiError(404, "no such message")   # pre-join: invisible
        mdir = self.store.msg_dir(gid, mid)
        if not mdir.is_dir():
            raise ApiError(404, "no such message")
        return mdir

    def _fanout_event(self, gid: str, mid: str, kind: str, actor: str,
                      mdir: Path) -> None:
        """Queue a payload-less ~a~/~u~ event to EVERY member (including the
        actor — their other devices need it too) and wake them. Receivers
        refetch the message state; the entry itself carries no data."""
        for u in self.store.members(gid):
            self.store.queue_add(u, f"{mid}~{kind}~{actor}", mdir)
            self.notifier.notify(u)

    # ---- reactions / edit / delete ------------------------------------------
    def react(self, user: str, body: dict) -> dict:
        gid, mid = body.get("gid", ""), body.get("mid", "")
        emoji = body.get("emoji") or ""
        if not isinstance(emoji, str):
            raise ApiError(400, "bad emoji")
        if emoji and not (len(emoji) <= MAX_REACTION
                          and len(emoji.encode()) <= 4 * MAX_REACTION
                          and emoji.isprintable()):
            raise ApiError(400, "bad emoji")
        mdir = self._visible_mdir(user, gid, mid)
        if (mdir / "system").exists():
            raise ApiError(400, "cannot react to a system message")
        self.send_limiter.check(user)   # reactions fan out like messages
        rdir = mdir / "reactions"
        rdir.mkdir(exist_ok=True)
        if emoji:
            self.store.write_atomic(rdir / user, emoji.encode())
        else:
            (rdir / user).unlink(missing_ok=True)   # empty = remove reaction
        self._fanout_event(gid, mid, "a", user, mdir)
        return {"ok": True, "reactions": self._reactions(mdir)}

    def edit_message(self, user: str, body: dict) -> dict:
        gid, mid = body.get("gid", ""), body.get("mid", "")
        text = body.get("text", "")
        if not (isinstance(text, str) and text.strip()
                and len(text) <= MAX_TEXT):
            raise ApiError(400, "bad text")
        mdir = self._visible_mdir(user, gid, mid)
        if (mdir / "from").read_text().strip() != user:
            raise ApiError(403, "not your message")
        if (mdir / "system").exists() or (mdir / "deleted").exists():
            raise ApiError(400, "cannot edit this message")
        self.send_limiter.check(user)
        self.store.write_atomic(mdir / "message.txt", text.encode())
        stamp = self.store.next_ts()
        self.store.write_atomic(mdir / "edited", str(stamp).encode())
        self._fanout_event(gid, mid, "u", user, mdir)
        return {"ok": True, "edited": stamp}

    def delete_message(self, user: str, body: dict) -> dict:
        gid, mid = body.get("gid", ""), body.get("mid", "")
        mdir = self._visible_mdir(user, gid, mid)
        if (mdir / "from").read_text().strip() != user:
            raise ApiError(403, "not your message")
        if (mdir / "system").exists():
            raise ApiError(400, "cannot delete a system message")
        if (mdir / "deleted").exists():
            return {"ok": True}   # idempotent
        self.send_limiter.check(user)
        # tombstone: blank the text, drop the attachment bytes (crediting the
        # sender's storage back), and mark. The dir itself stays so queue
        # entries, replies, and history render a coherent "deleted" stub.
        freed = 0
        adir = mdir / "attachments"
        if adir.is_dir():
            for metaf in adir.glob("*.meta"):
                try:
                    freed += json.loads(metaf.read_text()).get("size", 0)
                except (OSError, ValueError):
                    pass
            shutil.rmtree(adir, ignore_errors=True)
        self.store.write_atomic(mdir / "message.txt", b"")
        self.store.write_atomic(mdir / "deleted",
                                str(self.store.next_ts()).encode())
        if freed:
            self.store.add_storage(user, -freed)
        self._fanout_event(gid, mid, "u", user, mdir)
        return {"ok": True}

    def upload(self, user: str, rfile, length: int, rawname: str) -> dict:
        if length <= 0 or length > MAX_FILE:
            raise ApiError(413, f"file must be 1..{MAX_FILE} bytes")
        self.upload_limiter.check(user)   # cap upload rate per user
        udir = self.store.user_dir(user)
        staged = udir / "staged"
        if sum(1 for p in staged.iterdir() if not p.name.endswith(".meta")) >= MAX_STAGED:
            raise ApiError(429, "too many staged uploads; send or wait")
        # RESERVE the bytes under the lock before streaming, so concurrent
        # uploads can't collectively overshoot the quota; credited back if the
        # upload fails (and by the janitor when staged files expire).
        self.store.reserve_storage(user, length, USER_STORAGE_QUOTA)
        try:
            name = sanitize_filename(rawname)
            fid = secrets.token_hex(16)
            tmp = self.store.root / "tmp" / f"u-{fid}"
            digest = hashlib.sha256()
            remaining = length
            head = b""      # first bytes, for content-based (never name-based)
            with open(tmp, "wb") as f:              # image detection
                os.fchmod(f.fileno(), 0o600)
                while remaining:
                    chunk = rfile.read(min(65536, remaining))
                    if not chunk:
                        tmp.unlink(missing_ok=True)
                        raise ApiError(400, "truncated upload")
                    if len(head) < 16:
                        head += chunk[:16 - len(head)]
                    digest.update(chunk)
                    f.write(chunk)
                    remaining -= len(chunk)
            os.replace(tmp, staged / fid)
            meta = {"name": name, "size": length, "sha256": digest.hexdigest(),
                    "uploaded": now_ms()}
            mime = image_mime(head)
            amime = None if mime else audio_mime(head)
            if mime:
                meta["image"] = mime  # server-verified: the ONLY basis for inline
            if amime:
                meta["audio"] = amime  # ditto, for inline <audio> playback
            self.store.write_atomic(staged / (fid + ".meta"),
                                    json.dumps(meta).encode())
        except Exception:
            self.store.add_storage(user, -length)   # release the reservation
            raise
        out = {"file_id": fid, "name": name, "sha256": meta["sha256"]}
        if mime:
            out["image"] = mime
        if amime:
            out["audio"] = amime
        return out

    def _add_storage(self, udir: Path, delta: int) -> None:
        with self._quota_lock:
            new = max(0, self._storage_used(udir) + delta)
            self.store.write_atomic(udir / "storage_used", str(new).encode())

    def attachment(self, user: str, gid: str, mid: str, n: str):
        if not (GID_RE.match(gid) and MID_RE.match(mid) and n.isdigit()
                and 1 <= int(n) <= MAX_ATTACHMENTS):
            raise ApiError(400, "bad attachment path")
        if not self.store.is_member(gid, user):
            raise ApiError(403, "not a member")
        if int(mid[:13]) < self.store.joined_at(gid, user):
            raise ApiError(404, "no such attachment")  # pre-join: invisible
        mdir = self.store.msg_dir(gid, mid)
        blob = mdir / "attachments" / str(int(n))
        metaf = mdir / "attachments" / f"{int(n)}.meta"
        if not (blob.is_file() and metaf.is_file()):
            raise ApiError(404, "no such attachment")
        meta = json.loads(metaf.read_text())
        return blob, meta

    # ---- reading -----------------------------------------------------------
    def render_msg(self, mdir: Path) -> dict:
        mid = mdir.name
        atts = []
        adir = mdir / "attachments"
        if adir.is_dir():
            for metaf in sorted(adir.glob("*.meta")):
                try:
                    meta = json.loads(metaf.read_text())
                    a = {"n": int(metaf.name.split(".")[0]),
                         "name": meta["name"], "size": meta["size"],
                         "sha256": meta["sha256"]}
                    if meta.get("image"):   # server-verified at upload
                        a["image"] = meta["image"]
                    if meta.get("audio"):   # server-verified at upload
                        a["audio"] = meta["audio"]
                    atts.append(a)
                except (ValueError, KeyError):
                    continue
        gid = self.store.gid_of(mdir)
        sender = (mdir / "from").read_text().strip()
        at = int(mid[:13])
        # Intended recipients = members who had joined by the time this message
        # was sent (excluding the sender). Clients use this — NOT the live
        # roster — for tick aggregation, so adding a member later never
        # regresses an old message's read/delivered ticks.
        recipients = []
        if gid:
            for u in self.store.members(gid):
                if u != sender and self.store.joined_at(gid, u) <= at:
                    recipients.append(u)
        out = {"id": mid,
               "gid": gid,
               "from": sender,
               "at": at,
               "text": (mdir / "message.txt").read_text(),
               "attachments": atts,
               "recipients": recipients,
               "deliveredto": self._flags(mdir / "deliveredto"),
               "readby": self._flags(mdir / "readby")}
        reactions = self._reactions(mdir)
        if reactions:
            out["reactions"] = reactions
        try:
            out["edited"] = int((mdir / "edited").read_text())
        except (OSError, ValueError):
            pass
        if (mdir / "deleted").is_file():
            # belt and braces: a deleted message renders empty even if the
            # truncate raced or a stale attachment meta survived
            out.update(deleted=True, text="", attachments=[])
        rt = mdir / "reply_to"
        if rt.is_file():
            out["reply"] = self._resolve_reply(gid, rt)
        if (mdir / "system").is_file():
            try:
                out["system"] = json.loads((mdir / "system").read_text())
            except ValueError:
                out["system"] = {}
        return out

    def _resolve_reply(self, gid: str, rt: Path) -> dict:
        """Quoted-message stub, resolved fresh at read time so it tracks the
        target's current state (edits show, a deleted target shows as such)."""
        try:
            tid = rt.read_text().strip()
        except OSError:
            return {"gone": True}
        if not MID_RE.match(tid):        # corrupt marker: never build a path
            return {"gone": True}
        tdir = self.store.msg_dir(gid, tid)
        try:
            if (tdir / "deleted").is_file():
                return {"id": tid, "deleted": True}
            return {"id": tid,
                    "from": (tdir / "from").read_text().strip(),
                    "text": (tdir / "message.txt").read_text()[:160]}
        except OSError:
            return {"id": tid, "gone": True}   # archived/pruned target

    @staticmethod
    def _flags(folder: Path) -> dict:
        try:
            return {p.name: int(p.stat().st_mtime * 1000) for p in folder.iterdir()}
        except FileNotFoundError:
            return {}

    @staticmethod
    def _reactions(mdir: Path) -> dict:
        try:
            return {p.name: p.read_text() for p in (mdir / "reactions").iterdir()
                    if USER_RE.match(p.name)}
        except (FileNotFoundError, OSError):
            return {}

    def state(self, user: str, gid: str, mid: str) -> dict:
        """Full current render of one message. This is what clients refetch on
        a ~a~/~u~ (reaction/update) queue event; it is a superset of the old
        flags-only response, under the same authorization."""
        if not (GID_RE.match(gid) and MID_RE.match(mid)):
            raise ApiError(400, "bad ids")
        return self.render_msg(self._visible_mdir(user, gid, mid))

    def history(self, user: str, gid: str, before: str | None, limit: int) -> dict:
        if not GID_RE.match(gid):
            raise ApiError(400, "bad group id")
        if not self.store.is_member(gid, user):
            raise ApiError(403, "not a member")
        if before and not MID_RE.match(before):
            raise ApiError(400, "bad 'before'")
        limit = max(1, min(limit, 200))
        joined = self.store.joined_at(gid, user)
        out: list[dict] = []
        for mdir in msg_dirs_newest_first(self.store.group_dir(gid)):
            if int(mdir.name[:13]) < joined:
                break  # newest-first: everything after this predates the join
            if before and mdir.name >= before:
                continue
            out.append(self.render_msg(mdir))
            if len(out) >= limit:
                break
        return {"messages": out}

    # ---- starred (per-user, private — no fan-out) ---------------------------
    def _starred_dir(self, user: str) -> Path:
        d = self.store.user_dir(user) / "starred"
        d.mkdir(exist_ok=True)   # users provisioned before this feature
        return d

    def star(self, user: str, body: dict) -> dict:
        gid, mid = body.get("gid", ""), body.get("mid", "")
        on = bool(body.get("on", True))
        sdir = self._starred_dir(user)
        marker = sdir / f"{gid}~{mid}"   # '~' can't appear in a gid or mid
        if on:
            self._visible_mdir(user, gid, mid)   # must be able to see it now
            if sum(1 for _ in sdir.iterdir()) >= MAX_STARS:
                raise ApiError(429, "too many starred messages")
            marker.touch()
        else:
            if not (isinstance(gid, str) and GID_RE.match(gid)
                    and isinstance(mid, str) and MID_RE.match(mid)):
                raise ApiError(400, "bad ids")
            marker.unlink(missing_ok=True)
        return {"ok": True, "starred": on}

    def starred(self, user: str) -> dict:
        """The user's starred messages, newest first. Markers whose message is
        gone (archived, deleted group, we left) are pruned as we encounter
        them — the list is self-healing, like the queue."""
        out = []
        for marker in sorted(self._starred_dir(user).iterdir(),
                             key=lambda p: p.name.split("~", 1)[-1],
                             reverse=True):
            gid, _, mid = marker.name.partition("~")
            if not (GID_RE.match(gid) and MID_RE.match(mid)):
                continue
            mdir = self.store.msg_dir(gid, mid)
            if (not self.store.is_member(gid, user) or not mdir.is_dir()
                    or (mdir / "deleted").is_file()):
                marker.unlink(missing_ok=True)
                continue
            out.append(self.render_msg(mdir))
            if len(out) >= 200:
                break
        return {"messages": out}

    # ---- search --------------------------------------------------------------
    def search(self, user: str, q: str, gid: str | None, limit: int) -> dict:
        """Case-insensitive substring scan over message text and attachment
        names — literally walking the folders, newest first across every group
        the user belongs to (or one gid). Join-time visibility is enforced per
        group; work is bounded by SEARCH_SCAN_CAP dirs, and `truncated` tells
        the client when the bound was hit before history was exhausted."""
        if not (isinstance(q, str) and 1 <= len(q) <= MAX_SEARCH_Q):
            raise ApiError(400, "bad query")
        self.search_limiter.check(user)
        limit = max(1, min(limit, 50))
        if gid is not None:
            if not GID_RE.match(gid):
                raise ApiError(400, "bad group id")
            if not self.store.is_member(gid, user):
                raise ApiError(403, "not a member")
            gids = [gid]
        else:
            gids = [g.name for g in (self.store.root / "groups").iterdir()
                    if (g / "members" / user).exists()]
        joined = {g: self.store.joined_at(g, user) for g in gids}

        def visible(g):
            for mdir in msg_dirs_newest_first(self.store.group_dir(g)):
                if int(mdir.name[:13]) < joined[g]:
                    break
                yield mdir
        # merge the per-group newest-first streams into one global
        # newest-first stream (mids are ordered by their timestamp prefix)
        merged = heapq.merge(*(visible(g) for g in gids),
                             key=lambda p: p.name, reverse=True)
        ql = q.lower()
        results, scanned, truncated = [], 0, False
        for mdir in merged:
            scanned += 1
            if scanned > SEARCH_SCAN_CAP:
                truncated = True
                break
            try:
                if (mdir / "deleted").is_file() or (mdir / "system").is_file():
                    continue
                text = (mdir / "message.txt").read_text()
                hit = ql in text.lower()
                att_hit = None
                if not hit:
                    for metaf in (mdir / "attachments").glob("*.meta"):
                        name = json.loads(metaf.read_text()).get("name", "")
                        if ql in name.lower():
                            att_hit = name
                            break
                    if att_hit is None:
                        continue
                results.append({
                    "id": mdir.name,
                    "gid": self.store.gid_of(mdir),
                    "from": (mdir / "from").read_text().strip(),
                    "at": int(mdir.name[:13]),
                    "snippet": ("\U0001F4CE " + att_hit) if att_hit
                               else self._snippet(text, ql)})
                if len(results) >= limit:
                    break
            except OSError:
                continue   # janitor archived it mid-scan
        return {"results": results, "truncated": truncated}

    @staticmethod
    def _snippet(text: str, ql: str) -> str:
        i = text.lower().find(ql)
        if i < 0:
            return text[:120]
        start, end = max(0, i - 60), min(len(text), i + len(ql) + 60)
        return (("…" if start else "") + text[start:end]
                + ("…" if end < len(text) else ""))

    # ---- groups / directory --------------------------------------------------
    def list_groups(self, user: str) -> dict:
        res = []
        for gdir in (self.store.root / "groups").iterdir():
            if not (gdir / "members" / user).exists():
                continue
            gid = gdir.name
            res.append({"gid": gid, "name": self.store.group_name(gid),
                        "members": self.store.members(gid),
                        "last": self._last_msg(gdir,
                                               self.store.joined_at(gid, user))})
        res.sort(key=lambda g: (g["last"] or {}).get("at", 0), reverse=True)
        return {"groups": res}

    def _last_msg(self, gdir: Path, since: int = 0) -> dict | None:
        for mdir in msg_dirs_newest_first(gdir):
            if int(mdir.name[:13]) < since:
                return None
            try:
                text = (mdir / "message.txt").read_text()
            except OSError:
                continue
            last = {"id": mdir.name, "at": int(mdir.name[:13]),
                    "from": (mdir / "from").read_text().strip(),
                    "text": text[:80],
                    "attachments": len(list((mdir / "attachments").glob("*.meta")))}
            if (mdir / "deleted").is_file():
                last["deleted"] = True
            return last
        return None

    def create_group(self, user: str, body: dict) -> dict:
        self.group_limiter.check(user)   # group creation fans out system msgs
        name = body.get("name", "")
        members = body.get("members", [])
        if not (isinstance(name, str) and 1 <= len(name) <= 64 and name.isprintable()):
            raise ApiError(400, "bad group name (1..64 printable chars)")
        if not (isinstance(members, list)
                and all(isinstance(u, str) and USER_RE.match(u) for u in members)):
            raise ApiError(400, "bad members list")
        roster = set(members) | {user}
        if not 2 <= len(roster) <= MAX_GROUP_MEMBERS:
            raise ApiError(400, f"groups need 2..{MAX_GROUP_MEMBERS} members")
        for u in roster:
            if not self.store.user_exists(u):
                raise ApiError(404, f"no such user: {u}")
        gid = self.store.create_group(name, roster)
        # announce in-band: this is how the other members' clients learn the
        # group exists at all (it lands in their queues like any message)
        self.store.spool_system(user, gid, f"{user} created “{name}”",
                                {"event": "created", "name": name, "by": user})
        self.router.wake.set()
        return {"gid": gid, "members": sorted(roster)}

    def modify_members(self, user: str, gid: str, body: dict) -> dict:
        if not GID_RE.match(gid) or gid.startswith("d-"):
            raise ApiError(400, "bad group id")
        if not self.store.is_member(gid, user):
            raise ApiError(403, "not a member")
        self.group_limiter.check(user)   # membership changes fan out system msgs
        add = body.get("add", [])
        remove = body.get("remove", [])
        if not (isinstance(add, list) and isinstance(remove, list)):
            raise ApiError(400, "bad body")
        # validate EVERYTHING before mutating anything, so a bad `remove` can't
        # leave the `add`s (and their join announcements) half-committed
        for u in add:
            if not (isinstance(u, str) and self.store.user_exists(u)):
                raise ApiError(404, f"no such user: {u}")
        for u in remove:
            if u != user:
                raise ApiError(403, "members can only remove themselves")
        md = self.store.group_dir(gid) / "members"
        for u in add:
            if len(self.store.members(gid)) >= MAX_GROUP_MEMBERS:
                raise ApiError(400, "group full")
            if (md / u).exists():
                continue
            # stamp the join time first (on the shared clock), so the join
            # announcement's id — minted next — is strictly after it
            (md / u).write_text(str(self.store.next_ts()))
            self.store.spool_system(
                user, gid, f"{user} added {u}",
                {"event": "join", "user": u, "by": user})
        for u in remove:
            if not (md / u).exists():
                continue
            self.store.spool_system(u, gid, f"{u} left",
                                    {"event": "leave", "user": u})
            (md / u).unlink(missing_ok=True)
            # leaving sweeps this group's entries out of the leaver's queue
            for link in self.store.queue_dir(u).iterdir():
                if (link.is_symlink()
                        and self.store.gid_of(os.path.realpath(link)) == gid):
                    link.unlink(missing_ok=True)
        self.router.wake.set()
        return {"members": self.store.members(gid)}

    def group_info(self, user: str, gid: str) -> dict:
        """Single-group lookup — how a client resolves a gid it just learned
        about from a system announcement in its queue."""
        if not GID_RE.match(gid):
            raise ApiError(400, "bad group id")
        if not self.store.is_member(gid, user):
            raise ApiError(403, "not a member")
        return {"gid": gid, "name": self.store.group_name(gid),
                "members": self.store.members(gid),
                "joined_at": self.store.joined_at(gid, user)}

    def list_users(self) -> dict:
        res = []
        for udir in sorted((self.store.root / "users").iterdir()):
            try:
                auth = json.loads((udir / "auth.json").read_text())
            except (OSError, ValueError):
                continue
            u = {"user": udir.name, "display": auth.get("display", udir.name),
                 "online": self._online(udir.name)}
            seen = self._last_seen_ms(udir.name)
            if seen:
                u["last_seen"] = seen
            res.append(u)
        return {"users": res}


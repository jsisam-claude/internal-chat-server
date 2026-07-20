"""The Api: all request-handling business logic, independent of HTTP. The
web layer (server.py) is a thin shell that parses a request, calls one of
these methods, and serializes the result."""
from __future__ import annotations

import hashlib
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
    LOGIN_IP_LIMIT, USER_STORAGE_QUOTA)
from .errors import ApiError
from .util import now_ms, sanitize_filename, msg_dirs_newest_first, image_mime
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
        self.login_limiter = RateLimiter(limit=10, window=300)
        self.login_ip_limiter = RateLimiter(limit=LOGIN_IP_LIMIT, window=300)
        self.send_limiter = RateLimiter(limit=SEND_LIMIT, window=SEND_WINDOW)
        self.upload_limiter = RateLimiter(limit=UPLOAD_LIMIT, window=UPLOAD_WINDOW)
        self.limiters = [self.login_limiter, self.login_ip_limiter,
                         self.send_limiter, self.upload_limiter]

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

    # ---- queue -------------------------------------------------------------
    def list_queue(self, user: str, wait: float) -> dict:
        deadline = time.time() + max(0.0, min(wait, MAX_WAIT))
        while True:
            items = self._queue_items(user)
            if items or time.time() >= deadline:
                return {"queue": items}
            self.notifier.wait(user, min(1.0, deadline - time.time()))

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
        self.send_limiter.check(user)  # cap message/fan-out floods per user
        mid = self.store.spool_message(user, gid, text, files, nonce)
        self.router.wake.set()
        return {"id": mid, "gid": gid}

    def upload(self, user: str, rfile, length: int, rawname: str) -> dict:
        if length <= 0 or length > MAX_FILE:
            raise ApiError(413, f"file must be 1..{MAX_FILE} bytes")
        self.upload_limiter.check(user)   # cap upload rate per user
        udir = self.store.user_dir(user)
        # per-user storage quota (best-effort accounting; see _storage_used)
        if self._storage_used(udir) + length > USER_STORAGE_QUOTA:
            raise ApiError(413, "storage quota exceeded")
        staged = udir / "staged"
        if sum(1 for p in staged.iterdir() if not p.name.endswith(".meta")) >= MAX_STAGED:
            raise ApiError(429, "too many staged uploads; send or wait")
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
        if mime:
            meta["image"] = mime  # server-verified: the ONLY basis for inline
        self.store.write_atomic(staged / (fid + ".meta"), json.dumps(meta).encode())
        self._add_storage(udir, length)
        out = {"file_id": fid, "name": name, "sha256": meta["sha256"]}
        if mime:
            out["image"] = mime
        return out

    _quota_lock = threading.Lock()

    def _storage_used(self, udir: Path) -> int:
        try:
            return int((udir / "storage_used").read_text())
        except (OSError, ValueError):
            return 0

    def _add_storage(self, udir: Path, delta: int) -> None:
        # Conservative running total of a user's uploaded bytes. Monotonic for
        # now (retention could credit it back later); the quota is a soft cap.
        with self._quota_lock:
            self.store.write_atomic(udir / "storage_used",
                                    str(self._storage_used(udir) + delta).encode())

    def attachment(self, user: str, gid: str, mid: str, n: str):
        if not (GID_RE.match(gid) and MID_RE.match(mid) and n.isdigit()
                and 1 <= int(n) <= MAX_ATTACHMENTS):
            raise ApiError(400, "bad attachment path")
        if not self.store.is_member(gid, user):
            raise ApiError(403, "not a member")
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
        if (mdir / "system").is_file():
            try:
                out["system"] = json.loads((mdir / "system").read_text())
            except ValueError:
                out["system"] = {}
        return out

    @staticmethod
    def _flags(folder: Path) -> dict:
        try:
            return {p.name: int(p.stat().st_mtime * 1000) for p in folder.iterdir()}
        except FileNotFoundError:
            return {}

    def state(self, user: str, gid: str, mid: str) -> dict:
        if not (GID_RE.match(gid) and MID_RE.match(mid)):
            raise ApiError(400, "bad ids")
        if not self.store.is_member(gid, user):
            raise ApiError(403, "not a member")
        mdir = self.store.msg_dir(gid, mid)
        if not mdir.is_dir():
            raise ApiError(404, "no such message")
        return {"deliveredto": self._flags(mdir / "deliveredto"),
                "readby": self._flags(mdir / "readby")}

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
            return {"id": mdir.name, "at": int(mdir.name[:13]),
                    "from": (mdir / "from").read_text().strip(),
                    "text": text[:80],
                    "attachments": len(list((mdir / "attachments").glob("*.meta")))}
        return None

    def create_group(self, user: str, body: dict) -> dict:
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
        add = body.get("add", [])
        remove = body.get("remove", [])
        if not (isinstance(add, list) and isinstance(remove, list)):
            raise ApiError(400, "bad body")
        md = self.store.group_dir(gid) / "members"
        for u in add:
            if not (isinstance(u, str) and self.store.user_exists(u)):
                raise ApiError(404, f"no such user: {u}")
            if len(self.store.members(gid)) >= MAX_GROUP_MEMBERS:
                raise ApiError(400, "group full")
            if (md / u).exists():
                continue
            (md / u).touch()  # marker first: the join announcement below must
            self.store.spool_system(  # not predate the join timestamp
                user, gid, f"{user} added {u}",
                {"event": "join", "user": u, "by": user})
        for u in remove:
            if u != user:
                raise ApiError(403, "members can only remove themselves")
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
            res.append({"user": udir.name, "display": auth.get("display", udir.name)})
        return {"users": res}


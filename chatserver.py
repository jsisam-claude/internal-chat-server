#!/usr/bin/env python3
"""internal-chat server: Python stdlib only, no database.

Messages are directories, flags are marker files, queues are folders of
symlinks; every state change is a file appearing or moving. See DESIGN.md
in the internal-chat repo for the full design.

Usage:
    python3 chatserver.py adduser <name> [--data DIR]
    python3 chatserver.py serve [--data DIR] [--host H] [--port N]
                                [--cert server.pem] [--static DIR]
                                [--retain-days N]
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import ssl
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

USER_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")
GID_RE = re.compile(r"^[gd]-[a-z0-9_.-]{1,72}$")
MID_RE = re.compile(r"^\d{13}-[0-9a-f]{12}$")
# queue entry: "<msg-id>" (a message), "<msg-id>~d~<user>" / "<msg-id>~r~<user>"
# (delivered/read flag events for a message the queue's owner sent), or
# "<msg-id>~x~server" (routing failed; the owner's message bounced)
ENTRY_RE = re.compile(r"^(\d{13}-[0-9a-f]{12})(?:~([drx])~([a-z0-9_.-]{1,32}))?$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
FID_RE = re.compile(r"^[0-9a-f]{32}$")

MAX_JSON = 64 * 1024
MAX_TEXT = 8192
MAX_FILE = 50 * 1024 * 1024
MAX_ATTACHMENTS = 8
MAX_STAGED = 16
MAX_WAIT = 30
MAX_GROUP_MEMBERS = 64
SESSION_IDLE_DAYS = 30
PBKDF2_ITERS = 600_000

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'")

STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".apk": "application/vnd.android.package-archive",
}


def log(msg: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def now_ms() -> int:
    return int(time.time() * 1000)


def mid_date(mid: str) -> str:
    """Day folder for a message id — derived from the id's timestamp prefix,
    so the path is computable from (gid, mid) alone."""
    ts = int(mid[:13]) / 1000
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def sanitize_filename(raw: str) -> str:
    """Original filenames are metadata only and never become paths, but they
    are still displayed on clients — strip anything surprising. Accepts the
    raw header value: headers arrive latin-1, native clients send utf-8
    bytes, browsers percent-encode."""
    try:
        raw = (raw or "").encode("latin-1").decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError):
        raw = raw or ""
    name = unquote(raw).replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '<>:"|?*')
    name = name.strip(". ")
    return name[:120] or "file"


def msg_dirs_newest_first(gdir: Path):
    """All message dirs of a group, newest first — the one directory-walk
    used by history, previews, and recovery."""
    for day in sorted((d for d in gdir.iterdir() if DATE_RE.match(d.name)),
                      key=lambda p: p.name, reverse=True):
        for mdir in sorted(day.iterdir(), reverse=True):
            if MID_RE.match(mdir.name):
                yield mdir


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Store:
    """All state lives under one data dir; every mutation is an atomic
    create/rename/unlink so readers never see partial state."""

    def __init__(self, root, iters: int = PBKDF2_ITERS):
        self.root = Path(root).resolve()
        self.iters = iters
        self._id_lock = threading.Lock()
        self._last_ms = 0
        for name in ("tmp", "incoming", "users", "groups", "archive", "rejected"):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def next_mid(self) -> str:
        """Sorted listings are the timeline, so ids must never go backwards —
        even if NTP steps the clock. Monotonic within this process."""
        with self._id_lock:
            ms = max(now_ms(), self._last_ms)
            self._last_ms = ms
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
            os.utime(p)
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
        gid = "d-" + "-".join(sorted((a, b)))
        if not self.group_dir(gid).exists():
            self._publish_group(gid, "", {a, b})
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
        try:
            return nf.read_text()  # retried send: same nonce -> same message
        except FileNotFoundError:
            pass
        mid = self.next_mid()
        b = self._spool_dir(mid, gid, sender, text)
        for i, fid in enumerate(staged, 1):
            src = self.user_dir(sender) / "staged" / fid
            meta = self.user_dir(sender) / "staged" / (fid + ".meta")
            if not (src.is_file() and meta.is_file()):
                shutil.rmtree(b, ignore_errors=True)
                raise ApiError(400, "unknown file id (upload first)")
            os.replace(src, b / "attachments" / str(i))
            os.replace(meta, b / "attachments" / f"{i}.meta")
        os.replace(b, self.root / "incoming" / mid)
        self.write_atomic(nf, mid.encode())
        return mid

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


class Notifier:
    """Per-user condition variables so empty-queue polls park instead of spin."""

    def __init__(self):
        self._lock = threading.Lock()
        self._conds: dict[str, threading.Condition] = {}

    def _cond(self, user: str) -> threading.Condition:
        with self._lock:
            return self._conds.setdefault(user, threading.Condition())

    def notify(self, user: str) -> None:
        c = self._cond(user)
        with c:
            c.notify_all()

    def wait(self, user: str, timeout: float) -> None:
        c = self._cond(user)
        with c:
            c.wait(timeout)


class Router(threading.Thread):
    """Sole mover of messages out of incoming/. Routing = one rename into the
    group's day folder + one symlink per recipient queue; every step is
    idempotent, so a crash anywhere is healed by re-running."""

    def __init__(self, store: Store, notifier: Notifier):
        super().__init__(daemon=True, name="router")
        self.store = store
        self.notifier = notifier
        self.wake = threading.Event()
        self.stopping = threading.Event()

    def run(self) -> None:
        self._recover()
        while not self.stopping.is_set():
            self.wake.wait(timeout=2.0)
            self.wake.clear()
            self.drain()

    def drain(self) -> None:
        inc = self.store.root / "incoming"
        for src in sorted(inc.iterdir()):
            try:
                self._route(src)
            except Exception as e:
                log(f"router: rejecting {src.name}: {e}")
                self._bounce(src)

    def _bounce(self, src: Path) -> None:
        """A rejected message must not leave the sender's ✓ lying: park the
        message dir in rejected/ and queue a ~x~ failure event to the sender."""
        dst = self.store.root / "rejected" / src.name
        try:
            os.replace(src, dst)
        except OSError:
            shutil.rmtree(src, ignore_errors=True)
            return
        try:
            sender = (dst / "from").read_text().strip()
            if self.store.user_exists(sender):
                self.store.queue_add(sender, f"{src.name}~x~server", dst)
                self.notifier.notify(sender)
        except OSError:
            pass

    def _route(self, src: Path) -> None:
        mid = src.name
        gid = (src / "to").read_text().strip()
        sender = (src / "from").read_text().strip()
        if not (MID_RE.match(mid) and GID_RE.match(gid) and USER_RE.match(sender)):
            raise ValueError("bad ids")
        members = self.store.members(gid)
        # system messages (server-written only) may announce the sender's own
        # departure, so their sender need not still be a member
        if sender not in members and not (src / "system").exists():
            raise ValueError("sender not a member")
        dest = self.store.msg_dir(gid, mid)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            shutil.rmtree(src)  # duplicate of an already-routed message
        else:
            os.replace(src, dest)
        self._finish(dest, mid, sender, members)

    def _finish(self, dest: Path, mid: str, sender: str, members: list[str]) -> None:
        (dest / "deliveredto").mkdir(exist_ok=True)
        (dest / "readby").mkdir(exist_ok=True)
        for uid in members:
            if uid != sender:
                self.store.queue_add(uid, mid, dest)
                self.notifier.notify(uid)
        (dest / ".routed").touch()

    def _recover(self) -> None:
        """Finish messages that were renamed into a group but crashed before
        their queue symlinks / .routed marker were created. Only the last two
        days can be affected, so stop the newest-first walk there."""
        cutoff = (datetime.now(timezone.utc)
                  - timedelta(days=2)).strftime("%Y-%m-%d")
        for gdir in (self.store.root / "groups").iterdir():
            for mdir in msg_dirs_newest_first(gdir):
                if mdir.parent.name < cutoff:
                    break
                if (mdir / ".routed").exists():
                    continue
                try:
                    sender = (mdir / "from").read_text().strip()
                    self._finish(mdir, mdir.name, sender,
                                 self.store.members(gdir.name))
                    log(f"router: recovered {mdir.name}")
                except Exception as e:
                    log(f"router: recovery failed for {mdir}: {e}")


class Janitor(threading.Thread):
    def __init__(self, store: Store, retain_days: int = 0, interval: float = 3600):
        super().__init__(daemon=True, name="janitor")
        self.store = store
        self.retain_days = retain_days
        self.interval = interval
        self.stopping = threading.Event()

    def run(self) -> None:
        while not self.stopping.wait(self.interval):
            try:
                self.clean()
            except Exception:
                log("janitor: " + traceback.format_exc())

    def clean(self) -> None:
        now = time.time()

        def prune(folder: Path, max_age: float, dirs: bool = False) -> None:
            try:
                entries = list(folder.iterdir())
            except FileNotFoundError:
                return
            for p in entries:
                try:
                    if now - p.lstat().st_mtime > max_age:
                        shutil.rmtree(p, ignore_errors=True) if dirs and p.is_dir() \
                            else p.unlink(missing_ok=True)
                except OSError:
                    pass

        prune(self.store.root / "tmp", 3600, dirs=True)
        for udir in (self.store.root / "users").iterdir():
            prune(udir / "staged", 86400)
            prune(udir / "nonces", 7 * 86400)
            prune(udir / "sessions", SESSION_IDLE_DAYS * 86400)
            # queue symlinks whose message was archived/deleted are dead;
            # without this an always-offline user's queue would grow forever
            try:
                for link in (udir / "queue").iterdir():
                    if link.is_symlink() and not os.path.exists(
                            os.path.realpath(link)):
                        link.unlink(missing_ok=True)
            except FileNotFoundError:
                pass
        if self.retain_days > 0:
            cutoff = (datetime.now(timezone.utc)
                      - timedelta(days=self.retain_days)).strftime("%Y-%m-%d")
            for gdir in (self.store.root / "groups").iterdir():
                for day in gdir.iterdir():
                    if DATE_RE.match(day.name) and day.name < cutoff:
                        dst = self.store.root / "archive" / gdir.name
                        dst.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(day), dst / day.name)


class RateLimiter:
    def __init__(self, limit: int = 10, window: float = 300):
        self.limit, self.window = limit, window
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def check(self, key: str) -> None:
        now = time.time()
        with self._lock:
            q = self._hits.setdefault(key, [])
            q[:] = [t for t in q if now - t < self.window]
            if len(q) >= self.limit:
                raise ApiError(429, "too many attempts, slow down")
            q.append(now)


class Api:
    """Business logic; the HTTP handler is a thin shell around this."""

    def __init__(self, store: Store, notifier: Notifier, router: Router):
        self.store = store
        self.notifier = notifier
        self.router = router
        self.login_limiter = RateLimiter(limit=10, window=300)

    # ---- auth --------------------------------------------------------------
    def login(self, ip: str, body: dict) -> dict:
        user = body.get("user", "")
        password = body.get("password", "")
        if not (isinstance(user, str) and isinstance(password, str)
                and USER_RE.match(user)):
            raise ApiError(400, "bad credentials")
        self.login_limiter.check(f"{ip}/{user}")
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
            mid, kind, uid = m.groups()
            target = Path(os.path.realpath(link))
            gid = self.store.gid_of(target)
            if kind is None and not target.is_dir():
                link.unlink(missing_ok=True)  # target archived/gone: drop
                continue
            item = {"entry": link.name,
                    "kind": {"d": "delivered", "r": "read", "x": "failed",
                             None: "msg"}[kind],
                    "id": mid, "gid": gid,
                    "at": int(link.lstat().st_mtime * 1000)}
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
        if self.store.gid_of(mdir) is None or not mdir.is_dir():
            raise ApiError(404, "message gone")
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
                if self.store.gid_of(mdir) and mdir.is_dir():
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
        mid = self.store.spool_message(user, gid, text, files, nonce)
        self.router.wake.set()
        return {"id": mid, "gid": gid}

    def upload(self, user: str, rfile, length: int, rawname: str) -> dict:
        if length <= 0 or length > MAX_FILE:
            raise ApiError(413, f"file must be 1..{MAX_FILE} bytes")
        staged = self.store.user_dir(user) / "staged"
        if sum(1 for p in staged.iterdir() if not p.name.endswith(".meta")) >= MAX_STAGED:
            raise ApiError(429, "too many staged uploads; send or wait")
        name = sanitize_filename(rawname)
        fid = secrets.token_hex(16)
        tmp = self.store.root / "tmp" / f"u-{fid}"
        digest = hashlib.sha256()
        remaining = length
        with open(tmp, "wb") as f:
            os.fchmod(f.fileno(), 0o600)
            while remaining:
                chunk = rfile.read(min(65536, remaining))
                if not chunk:
                    tmp.unlink(missing_ok=True)
                    raise ApiError(400, "truncated upload")
                digest.update(chunk)
                f.write(chunk)
                remaining -= len(chunk)
        os.replace(tmp, staged / fid)
        meta = {"name": name, "size": length, "sha256": digest.hexdigest(),
                "uploaded": now_ms()}
        self.store.write_atomic(staged / (fid + ".meta"), json.dumps(meta).encode())
        return {"file_id": fid, "name": name, "sha256": meta["sha256"]}

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
                    atts.append({"n": int(metaf.name.split(".")[0]),
                                 "name": meta["name"], "size": meta["size"],
                                 "sha256": meta["sha256"]})
                except (ValueError, KeyError):
                    continue
        out = {"id": mid,
               "gid": self.store.gid_of(mdir),
               "from": (mdir / "from").read_text().strip(),
               "at": int(mid[:13]),
               "text": (mdir / "message.txt").read_text(),
               "attachments": atts,
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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 75  # must exceed MAX_WAIT so long-polls aren't cut off
    server_version = "internal-chat"
    api: Api  # bound by build_server()
    static_dir: Path | None = None

    # ---- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *args):  # quiet 2xx; log the rest
        pass

    def log_request(self, code="-", size="-"):
        if isinstance(code, int) and code >= 400:
            log(f"{self.client_address[0]} {self.command} "
                f"{self.path.split('?')[0]} -> {code}")

    def _send_json(self, obj, status: int = 200) -> None:
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not 0 < length <= MAX_JSON:
            raise ApiError(400, "missing or oversized body")
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "bad json")
        if not isinstance(body, dict):
            raise ApiError(400, "bad json")
        return body

    def _user(self) -> str:
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            raise ApiError(401, "auth required")
        self._token = h[7:].strip()
        user = self.api.store.session_user(self._token)
        if not user:
            raise ApiError(401, "invalid or expired session")
        return user

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        try:
            url = urlsplit(self.path)
            parts = [p for p in url.path.split("/") if p]
            if any(p in (".", "..") for p in parts):
                raise ApiError(400, "bad path")
            self._route(method, parts, parse_qs(url.query))
        except ApiError as e:
            self.close_connection = True
            try:
                self._send_json({"error": e.message}, e.status)
            except OSError:
                pass
        except (ConnectionError, BrokenPipeError, TimeoutError):
            self.close_connection = True
        except Exception:
            log("handler: " + traceback.format_exc())
            self.close_connection = True
            try:
                self._send_json({"error": "internal error"}, 500)
            except OSError:
                pass

    # ---- routing -----------------------------------------------------------
    def _route(self, method: str, p: list[str], q: dict) -> None:
        api = self.api
        if not p or p[0] != "api":
            if method == "GET":
                return self._static(p)
            raise ApiError(404, "not found")
        p = p[1:]

        if method == "POST":
            if p == ["login"]:
                return self._send_json(api.login(self.client_address[0],
                                                 self._json_body()))
            if p == ["logout"]:
                self._user()
                api.store.drop_session(self._token)
                return self._send_json({"ok": True})
            if p == ["password"]:
                user = self._user()
                return self._send_json(api.change_password(user, self._json_body(),
                                                           self._token))
            if p == ["messages"]:
                return self._send_json(api.send(self._user(), self._json_body()))
            if len(p) == 4 and p[:3] == ["message", "dequeue", "read"]:
                return self._send_json(api.confirm(self._user(), p[3].split(",")))
            if p == ["message", "viewed"]:
                return self._send_json(api.viewed(self._user(), self._json_body()))
            if p == ["files"]:
                user = self._user()
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                return self._send_json(api.upload(
                    user, self.rfile, length,
                    self.headers.get("X-File-Name", "file")))
            if p == ["groups"]:
                return self._send_json(api.create_group(self._user(),
                                                        self._json_body()))
            if len(p) == 3 and p[0] == "groups" and p[2] == "members":
                return self._send_json(api.modify_members(self._user(), p[1],
                                                          self._json_body()))
            raise ApiError(404, "not found")

        # GET
        if p == ["messages"]:
            try:
                wait = float(q.get("wait", ["0"])[0])
            except ValueError:
                wait = 0.0
            return self._send_json(api.list_queue(self._user(), wait))
        if len(p) == 3 and p[:2] == ["message", "dequeue"]:
            return self._send_json(api.peek(self._user(), p[2]))
        if len(p) == 4 and p[:2] == ["message", "state"]:
            return self._send_json(api.state(self._user(), p[2], p[3]))
        if p == ["groups"]:
            return self._send_json(api.list_groups(self._user()))
        if len(p) == 2 and p[0] == "groups":
            return self._send_json(api.group_info(self._user(), p[1]))
        if len(p) == 3 and p[0] == "groups" and p[2] == "messages":
            try:
                limit = int(q.get("limit", ["50"])[0])
            except ValueError:
                limit = 50
            before = q.get("before", [None])[0]
            return self._send_json(api.history(self._user(), p[1], before, limit))
        if p == ["users"]:
            self._user()
            return self._send_json(api.list_users())
        if len(p) == 4 and p[0] == "attachments":
            blob, meta = api.attachment(self._user(), p[1], p[2], p[3])
            return self._send_blob(blob, meta["name"], meta["size"])
        if p == ["client", "version"]:
            if self.static_dir and (self.static_dir / "version.json").is_file():
                return self._send_static(self.static_dir / "version.json")
            raise ApiError(404, "no client published")
        raise ApiError(404, "not found")

    # ---- byte responses ------------------------------------------------------
    def _send_blob(self, path: Path, name: str, size: int) -> None:
        """Attachments: always opaque bytes, always a download — never
        rendered from this origin, regardless of content."""
        ascii_name = name.encode("ascii", "replace").decode().replace('"', "_")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{ascii_name}"; '
                         f"filename*=UTF-8''{quote(name)}")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(path, "rb") as f:
            shutil.copyfileobj(f, self.wfile, 65536)

    def _static(self, parts: list[str]) -> None:
        if self.static_dir is None:
            raise ApiError(404, "no web client installed")
        if any(part.startswith(".") for part in parts):
            raise ApiError(404, "not found")  # never serve dotfiles (.git etc.)
        base = self.static_dir.resolve()
        target = base.joinpath(*parts) if parts else base / "index.html"
        target = target.resolve()
        if not (target.is_file() and target.is_relative_to(base)):
            raise ApiError(404, "not found")
        self._send_static(target)

    def _send_static(self, path: Path) -> None:
        ctype = STATIC_TYPES.get(path.suffix.lower())
        data = path.read_bytes()
        self.send_response(200)
        if ctype is None:
            ctype = "application/octet-stream"
            self.send_header("Content-Disposition", "attachment")
        self.send_header("Content-Type", ctype)
        self.send_header("X-Content-Type-Options", "nosniff")
        if path.suffix.lower() == ".html":
            self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def build_server(store: Store, host: str, port: int,
                 static_dir: Path | None = None, certfile: str | None = None):
    notifier = Notifier()
    router = Router(store, notifier)
    api = Api(store, notifier, router)
    handler = type("BoundHandler", (Handler,),
                   {"api": api, "static_dir": static_dir})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    router.start()
    return httpd, router, api


def cmd_serve(args) -> None:
    store = Store(args.data)
    static_dir = Path(args.static).resolve() if args.static else None
    if not args.cert:
        log("WARNING: no --cert given, serving PLAIN HTTP — dev use only")
    httpd, router, _ = build_server(store, args.host, args.port,
                                    static_dir, args.cert)
    Janitor(store, retain_days=args.retain_days).start()
    scheme = "https" if args.cert else "http"
    log(f"serving on {scheme}://{args.host}:{httpd.server_address[1]} "
        f"(data: {store.root})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        router.stopping.set()
        httpd.shutdown()


def cmd_adduser(args) -> None:
    store = Store(args.data)
    password = args.password or getpass.getpass(f"initial password for {args.user}: ")
    store.add_user(args.user, password, display=args.display,
                   must_change=not args.no_change)
    print(f"user {args.user!r} created (must change password on first login: "
          f"{not args.no_change})")


def cmd_passwd(args) -> None:
    store = Store(args.data)
    if not store.user_exists(args.user):
        raise ApiError(404, "no such user")
    password = args.password or getpass.getpass(f"new password for {args.user}: ")
    store.set_password(args.user, password, must_change=not args.no_change)
    for s in (store.user_dir(args.user) / "sessions").iterdir():
        s.unlink(missing_ok=True)  # admin reset logs the user out everywhere
    print(f"password reset for {args.user!r}; all sessions invalidated")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve", help="run the chat server")
    sp.add_argument("--data", default="./data")
    sp.add_argument("--host", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=8443)
    sp.add_argument("--cert", help="PEM with certificate + key (enables TLS)")
    sp.add_argument("--static", help="directory with the web client to serve")
    sp.add_argument("--retain-days", type=int, default=0,
                    help="archive day folders older than N days (0 = keep)")
    sp.set_defaults(func=cmd_serve)

    au = sub.add_parser("adduser", help="provision a user")
    au.add_argument("user")
    au.add_argument("--data", default="./data")
    au.add_argument("--display")
    au.add_argument("--password", help="set non-interactively (visible in ps!)")
    au.add_argument("--no-change", action="store_true",
                    help="don't force a password change on first login")
    au.set_defaults(func=cmd_adduser)

    pw = sub.add_parser("passwd", help="admin password reset (kills all sessions)")
    pw.add_argument("user")
    pw.add_argument("--data", default="./data")
    pw.add_argument("--password", help="set non-interactively (visible in ps!)")
    pw.add_argument("--no-change", action="store_true",
                    help="don't force a password change on next login")
    pw.set_defaults(func=cmd_passwd)

    args = ap.parse_args(argv)
    try:
        args.func(args)
    except ApiError as e:
        print(f"error: {e.message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

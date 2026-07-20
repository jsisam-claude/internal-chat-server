"""Background threads that move messages and reclaim space.

Router  — the SOLE mover of messages out of incoming/: it renames each into
          its group's day folder and fans a queue symlink out to every
          recipient. Idempotent, so a crash is healed by re-running.
Janitor — periodic retention: archive old days, prune stale temp/session/
          nonce files and dangling queue links, sweep rate-limiter memory."""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import DATE_RE, MID_RE, GID_RE, USER_RE, SESSION_IDLE_DAYS
from .util import log, msg_dirs_newest_first
from .store import Store
from .notifier import Notifier

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
        their queue symlinks / .routed marker were created.

        The single router thread routes one message at a time, so an unfinished
        message sits in a recent day folder (no new messages arrive during an
        outage, so its day is among the group's most recent regardless of how
        long the outage lasted). We scan the two newest day folders per group
        and finish EVERY message lacking `.routed` — not stopping at the first
        finished one, since a failed prior recovery could leave an older gap
        below a newer finished message."""
        for gdir in (self.store.root / "groups").iterdir():
            days = sorted((d for d in gdir.iterdir() if DATE_RE.match(d.name)),
                          key=lambda p: p.name, reverse=True)[:2]
            for day in days:
                for mdir in sorted(day.iterdir()):
                    if not MID_RE.match(mdir.name) or (mdir / ".routed").exists():
                        continue
                    try:
                        sender = (mdir / "from").read_text().strip()
                        self._finish(mdir, mdir.name, sender,
                                     self.store.members(gdir.name))
                        log(f"router: recovered {mdir.name}")
                    except Exception as e:
                        log(f"router: recovery failed for {mdir}: {e}")


class Janitor(threading.Thread):
    def __init__(self, store: Store, retain_days: int = 0, interval: float = 3600,
                 limiters: list | None = None):
        super().__init__(daemon=True, name="janitor")
        self.store = store
        self.retain_days = retain_days
        self.interval = interval
        self.limiters = limiters or []
        self.stopping = threading.Event()

    def run(self) -> None:
        while not self.stopping.wait(self.interval):
            try:
                self.clean()
            except Exception:
                log("janitor: " + traceback.format_exc())

    def clean(self) -> None:
        now = time.time()
        for lim in self.limiters:
            lim.sweep()  # release rate-limiter memory for idle keys

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
            self._prune_staged(udir, now)   # credits storage back on expiry
            # empty nonce files are aborted send-claims; reclaim them fast
            # (1h) so a crashed claim doesn't wedge that nonce for 7 days
            self._prune_nonces(udir, now)
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

    def _prune_staged(self, udir: Path, now: float) -> None:
        """Delete staged uploads older than 24h AND credit their bytes back to
        the user's quota — otherwise never-sent uploads consume it forever."""
        staged = udir / "staged"
        try:
            entries = list(staged.iterdir())
        except FileNotFoundError:
            return
        user = udir.name
        for p in entries:
            if p.name.endswith(".meta"):
                continue
            try:
                if now - p.lstat().st_mtime <= 86400:
                    continue
                size = 0
                metaf = staged / (p.name + ".meta")
                try:
                    size = json.loads(metaf.read_text()).get("size", 0)
                except (OSError, ValueError):
                    pass
                p.unlink(missing_ok=True)
                metaf.unlink(missing_ok=True)
                if size:
                    self.store.add_storage(user, -size)
            except OSError:
                pass

    def _prune_nonces(self, udir: Path, now: float) -> None:
        try:
            entries = list((udir / "nonces").iterdir())
        except FileNotFoundError:
            return
        for p in entries:
            try:
                age = now - p.lstat().st_mtime
                # empty = aborted claim (reclaim after 1h); filled = keep 7 days
                ttl = 3600 if p.stat().st_size == 0 else 7 * 86400
                if age > ttl:
                    p.unlink(missing_ok=True)
            except OSError:
                pass


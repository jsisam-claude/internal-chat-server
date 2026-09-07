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
        # Messages that are STORED but whose fan-out did not finish (one
        # recipient's queue_add hit ENOSPC/EDQUOT/EIO). Retried on every drain
        # tick — see _retry_unfinished. Capped because it is memory: past the
        # cap the message still lands on disk and _recover picks it up at the
        # next start, which is the pre-existing behaviour.
        self._unfinished: set[Path] = set()

    MAX_UNFINISHED = 256

    def run(self) -> None:
        self._recover()
        while not self.stopping.is_set():
            self.wake.wait(timeout=2.0)
            self.wake.clear()
            self.drain()

    def drain(self) -> None:
        self._retry_unfinished()
        inc = self.store.root / "incoming"
        for src in sorted(inc.iterdir()):
            try:
                self._route(src)
            except Exception as e:
                # Only a failure BEFORE the rename leaves anything in
                # incoming/, and only that one is genuinely a rejection. Once
                # the message has been renamed into its group it is STORED —
                # history and /api/groups serve it — so _bounce could not act
                # (src is gone, so os.replace raises and the rmtree is a
                # no-op) and calling it "rejecting" told the operator the
                # opposite of what happened.
                if src.exists():
                    log(f"router: rejecting {src.name}: {e}")
                    self._bounce(src)
                else:
                    log(f"router: {src.name} is stored but its fan-out did "
                        f"not finish: {e}")

    def _retry_unfinished(self) -> None:
        """Re-run the fan-out for messages that were stored but not fully
        queued. Every step of _finish is idempotent, so a retry costs one
        symlink attempt per recipient and heals the instant the disk does.
        Without it the missed push waits for a RESTART, and even then only if
        the message is still in one of its group's two newest day folders —
        _recover's window (see its docstring) assumes an outage stops traffic,
        which is exactly what a partial ENOSPC does not do."""
        for dest in sorted(self._unfinished):
            # Broad, like drain's own guard: this runs on the router thread's
            # only loop, which has no handler above it — an exception here
            # would kill message routing outright.
            try:
                gid = self.store.gid_of(dest)
                sender = (dest / "from").read_text().strip()
                self._finish(dest, dest.name, sender, self.store.members(gid))
            except Exception as e:
                if not dest.is_dir():
                    # archived by retention, or its group was removed: there
                    # is nothing left to deliver
                    self._unfinished.discard(dest)
                    log(f"router: giving up on {dest.name}: {e}")

    def _bounce(self, src: Path) -> None:
        """A rejected message must not leave the sender's ✓ lying: park the
        message dir in rejected/ and queue a ~x~ failure event to the sender."""
        dst = self.store.root / "rejected" / src.name
        try:
            # a bounce is a rename out of incoming/ too — same lock, same
            # reason as _route: recount must never see the in-between
            with self.store._route_lock:
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
        # the rename is the one instant a message is in neither incoming/ nor
        # its group; recount_all_storage takes the same lock around its walk
        # of incoming/ so it can never observe that instant (see Store)
        with self.store._route_lock:
            if dest.exists():
                shutil.rmtree(src)  # duplicate of an already-routed message
            else:
                os.replace(src, dest)
        self._finish(dest, mid, sender, members)

    def _finish(self, dest: Path, mid: str, sender: str, members: list[str]) -> None:
        (dest / "deliveredto").mkdir(exist_ok=True)
        (dest / "readby").mkdir(exist_ok=True)
        retrying = dest in self._unfinished
        complete = True
        for uid in members:
            if uid == sender:
                continue
            # ISOLATE each recipient. queue_add only swallows FileExistsError
            # and FileNotFoundError, so a full disk (ENOSPC), a per-user quota
            # (EDQUOT) or an I/O error on ONE queue used to abort the loop:
            # every member after them in the sorted list lost the message's
            # push too, and .routed was never written. One bad queue must cost
            # one recipient, not the rest of the group.
            try:
                self.store.queue_add(uid, mid, dest)
                self.notifier.notify(uid)
            except OSError as e:
                complete = False
                if not retrying:     # stay quiet on every 2s retry pass
                    log(f"router: {mid}: queueing to {uid} failed: {e}")
        if complete:
            # .routed is the "fan-out finished" marker _recover keys on, so it
            # must not be written while a recipient is still missing an entry
            (dest / ".routed").touch()
            if dest in self._unfinished:
                self._unfinished.discard(dest)
                log(f"router: {mid}: fan-out completed on retry")
        elif not retrying and len(self._unfinished) < self.MAX_UNFINISHED:
            self._unfinished.add(dest)

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
        # Bounced messages: nothing reclaimed them, so a failed send's
        # attachments sat on disk permanently. 3 days is long enough for the
        # sender's client to have surfaced the ~x~ failure. The stranded
        # <mid>~x~server queue symlinks left behind point at nothing and are
        # swept by the dangling-link pass below. Pruned BEFORE the recount, so
        # the recount sees the post-prune tree.
        prune(self.store.root / "rejected", 3 * 86400, dirs=True)
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
        # Re-derive every quota counter from the files themselves, in ONE walk
        # (per-user recounts repeated the same tree once per account). The
        # counter is only a cache, so any drift — a missed credit-back, a crash
        # mid-upload, an admin deleting files by hand — self-corrects here
        # instead of accumulating forever. Runs AFTER staged pruning so expired
        # uploads are already gone from the total.
        try:
            self.store.recount_all_storage()
        except OSError:
            pass
        # A group whose last member left is unreachable through every API path,
        # yet it was still walked by list_groups and the storage recount on
        # every call, forever. Park it in archive/ (non-destructive: the files
        # are still there for an admin, and the quota recount still counts
        # them) so it stops costing anything on the hot paths.
        try:
            for gdir in (self.store.root / "groups").iterdir():
                try:
                    if any((gdir / "members").iterdir()):
                        continue
                except FileNotFoundError:
                    pass          # no members/ at all is member-less too: the
                                  # router can recreate a bare skeleton for a
                                  # message that was mid-flight when we archived
                except OSError:
                    continue
                # A fresh, non-existent name every time: shutil.move nests
                # the source INTO an existing dir, which would hide the group's
                # attachments from the recount. (archive/<gid> may already hold
                # day folders parked by retain_days.)
                dst = self.store.root / "archive" / gdir.name
                suffix = 0
                while dst.exists():
                    suffix += 1
                    dst = self.store.root / "archive" / f"{gdir.name}-{int(now)}-{suffix}"
                try:
                    shutil.move(str(gdir), str(dst))
                    log(f"janitor: archived member-less group {gdir.name}")
                except OSError:
                    pass
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
                # A meta is normally removed alongside its blob below. One
                # whose blob is already gone never was: upload_thumb rewrites
                # <fid>.meta after a racing send has consumed the staged file
                # (API.md calls that race benign — it is, except for this
                # orphan), and nothing else would ever reclaim it. Same 24h
                # clock as everything else in staged/.
                try:
                    if (now - p.lstat().st_mtime > 86400
                            and not (staged / p.name[:-len(".meta")]).exists()):
                        p.unlink(missing_ok=True)
                except OSError:
                    pass
                continue
            try:
                if now - p.lstat().st_mtime <= 86400:
                    continue
                if p.name.endswith(".thumb"):
                    # a preview expires on its own clock (written seconds after
                    # its blob, so they age together); its bytes were reserved
                    # at upload and are credited from the file itself — the
                    # blob's .meta may already be gone from its own prune
                    size = p.stat().st_size
                    p.unlink(missing_ok=True)
                    if size:
                        self.store.add_storage(user, -size)
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


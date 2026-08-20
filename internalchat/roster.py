"""Optional passwd-style roster: the operator's list of who may connect.

One entry per line, ':'-separated; blank lines and '#' comments ignored:

    # who is allowed to use the chat server
    alice:Alice Anderson
    bob:Bob Brown
    carol:Carol Clark:disabled

Fields are `user[:display[:flags]]`. `display` overrides the name stored in
the account. `flags` is a comma-separated list; the only flag is `disabled`,
which keeps the record (and the account's data) but blocks the account —
the file's own equivalent of a `!` in shadow(5). A '#' starts a comment only
at the START of a line: `alice  # note` is not a comment, it is a malformed
username, and (fail-closed) alice is then denied.

Deliberately NOT a shadow file: passwords stay in each account's auth.json.
This roster is meant to be read, reviewed, diffed, and generated from
whatever the org already treats as the source of truth for "who works here",
so it must never hold a secret.

Three properties are worth stating plainly, because they are the whole point:

* Enforcement is decided ONCE, when the server starts (a file that exists
  arms the allowlist for the life of the process). Deciding it per read
  would mean `rm passwd` silently switches the control off. "Exists" here
  means "anything but a definite ENOENT" — a dangling symlink, a loop, or a
  permission error all ARM the control and then deny, because none of them
  is evidence that there is no allowlist.
* The CONTENTS are re-read whenever the file changes, so adding or removing
  a line takes effect on the very next request with no restart — including
  for sessions that are already logged in. The stat stamp can in principle
  miss a change (a mtime-preserving `rsync -a`/`cp -p`, or a coarse-mtime
  filesystem), and a missed REVOCATION is the dangerous direction, so the
  file is re-read at least every STALE_AFTER seconds regardless of the stamp.
* Every failure after arming — unreadable, unparseable, oversized, deleted,
  not a regular file — denies EVERY user instead of falling back to open: a
  roster that cannot be read is not evidence that everyone is allowed.

Nothing here may block: `allows()` is on the path of every authenticated
request, so the file is opened non-blocking and rejected unless it is a
regular file (a FIFO at this path would otherwise park every worker thread
forever), and no lock is held across the read.
"""
from __future__ import annotations

import os
import stat as statmod
import time
from pathlib import Path
from typing import NamedTuple

from .config import USER_RE
from .errors import ApiError
from .util import log

# ~30k entries at a typical line length. A mistyped --roster (a log file, a
# device node) must not be slurped into memory — checked against the file's
# size BEFORE reading, then again against what was actually read.
MAX_ROSTER_BYTES = 1 << 20
# Upper bound on how long a stat-stamp collision can hide a change (see above).
STALE_AFTER = 5.0


class Entry(NamedTuple):
    user: str
    display: str | None
    disabled: bool


class Roster:
    def __init__(self, path: Path | None):
        self.path = Path(path) if path else None
        self.enforcing = bool(self.path and _present(self.path))
        # (stamp, entries, error, read_at) swapped as ONE reference, so a
        # reader never sees a stamp that disagrees with its entries. No lock:
        # a change may be parsed twice concurrently, which is cheap — while a
        # lock held across the read is how one bad file wedges every thread.
        self._cache: tuple = (object(), {}, None, 0.0)
        self._logged: str | None = None
        if self.enforcing:
            n = len(self.entries())
            log(f"roster: enforcing {self.path} "
                f"({n} entr{'y' if n == 1 else 'ies'})")
        elif self.path:
            log(f"roster: no allowlist at {self.path} — every provisioned "
                "account may connect")

    @property
    def error(self) -> str | None:
        return self._cache[2]

    # ---- reading -----------------------------------------------------------
    def entries(self) -> dict[str, Entry]:
        """The parsed roster, re-read when the file changes (one stat per
        call) and at least every STALE_AFTER seconds. Empty when it cannot be
        read — which denies everyone, by design."""
        if not self.enforcing:
            return {}
        stamp = self._stat()
        cstamp, centries, _, read_at = self._cache
        if stamp == cstamp and (time.monotonic() - read_at) < STALE_AFTER:
            return centries
        parsed, err = self._parse()          # no lock held: must never block
        self._cache = (stamp, parsed, err, time.monotonic())
        if err != self._logged:
            self._logged = err
            if err:
                log(f"roster: {err} — DENYING every user until "
                    f"{self.path} is readable again")
        return parsed

    def _stat(self):
        try:
            st = os.stat(self.path)
            return (st.st_mtime_ns, st.st_size, st.st_ino, st.st_dev)
        except OSError as e:
            return ("unstattable", e.errno)

    def _read(self) -> tuple[bytes | None, str | None]:
        """Bytes of the roster, or a reason not to trust it. O_NONBLOCK plus
        an S_ISREG check because this runs on every request: opening a FIFO
        (or a device) here would block a worker thread indefinitely."""
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as e:
            return None, f"cannot open {self.path}: {e.strerror or e}"
        try:
            st = os.fstat(fd)
            if not statmod.S_ISREG(st.st_mode):
                return None, f"{self.path} is not a regular file"
            if st.st_size > MAX_ROSTER_BYTES:
                return None, (f"{self.path} is larger than "
                              f"{MAX_ROSTER_BYTES} bytes")
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ROSTER_BYTES:   # grew between fstat and read
                    return None, (f"{self.path} is larger than "
                                  f"{MAX_ROSTER_BYTES} bytes")
                chunks.append(chunk)
        except OSError as e:
            return None, f"cannot read {self.path}: {e.strerror or e}"
        finally:
            os.close(fd)
        return b"".join(chunks), None

    def _parse(self) -> tuple[dict[str, Entry], str | None]:
        raw, err = self._read()
        if err:
            return {}, err
        try:
            text = raw.decode()
        except UnicodeDecodeError:
            return {}, f"{self.path} is not valid UTF-8"
        out: dict[str, Entry] = {}
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 2)
            user = parts[0].strip()
            display = parts[1].strip() if len(parts) > 1 else ""
            flags = parts[2].strip() if len(parts) > 2 else ""
            if not USER_RE.match(user):
                log(f"roster: {self.path}:{n}: bad username {user!r}, ignored")
                continue
            disabled, unknown = False, None
            for f in (p.strip().lower() for p in flags.split(",")):
                if not f:
                    continue
                if f == "disabled":
                    disabled = True
                else:
                    unknown = f
            if unknown:
                # A typo in a security file has to fail CLOSED: 'disbaled'
                # must never leave the account quietly enabled.
                log(f"roster: {self.path}:{n}: unknown flag {unknown!r} — "
                    f"{user!r} DENIED")
                continue
            if user in out:          # first wins, as /etc/passwd itself does
                log(f"roster: {self.path}:{n}: duplicate {user!r}, ignored")
                continue
            out[user] = Entry(user, display or None, disabled)
        return out, None

    # ---- queries -----------------------------------------------------------
    def allows(self, user: str) -> bool:
        if not self.enforcing:
            return True
        e = self.entries().get(user)
        return e is not None and not e.disabled

    def display(self, user: str) -> str | None:
        """The roster's display name, when it sets one — it is the operator's
        central place to rename someone, so it wins over the account's own."""
        e = self.entries().get(user)
        return e.display if e else None

    # ---- writing (CLI convenience) -----------------------------------------
    def approve(self, user: str, display: str | None = None) -> None:
        """Append an entry. APPENDS rather than rewrites, so a concurrent
        hand-edit of the file can never be clobbered by the CLI."""
        if not self.path:
            raise ApiError(400, "no roster path configured")
        if not self.enforcing:
            # Creating the file here would arm the allowlist at the next
            # restart and lock out every account that isn't in it.
            raise ApiError(400, f"no roster at {self.path}; create it first "
                                "(an empty allowlist denies every account)")
        if not USER_RE.match(user):
            raise ApiError(400, "bad username")
        existing = self.entries().get(user)
        if existing is not None:
            # Appending would be a silent no-op: the parser takes the FIRST
            # entry for a name, so this would report success and change
            # nothing (worse still for a `disabled` entry, which stays denied).
            raise ApiError(409, f"{user!r} is already in {self.path}"
                                + (" (disabled — edit the file to re-enable)"
                                   if existing.disabled else ""))
        if display:
            # ':' is the field separator, and str.splitlines() — which the
            # parser uses — honours EIGHT terminators beyond \n (\r, \v, \f,
            # \x1c-\x1e, \x85,  ,  ). Rewriting only some of them
            # let a crafted display name inject a whole extra approved line,
            # so reject anything non-printable outright instead.
            if ":" in display or not display.isprintable():
                raise ApiError(400, "display name must be printable and "
                                    "must not contain ':'")
        line = user + (":" + display if display else "")
        try:
            size = self.path.stat().st_size
            need_nl = False
            if size:
                with open(self.path, "rb") as f:
                    f.seek(-1, os.SEEK_END)
                    need_nl = f.read(1) != b"\n"
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(("\n" if need_nl else "") + line + "\n")
        except OSError as e:
            raise ApiError(503, f"cannot write {self.path}: {e.strerror or e}")


def _present(path: Path) -> bool:
    """Is there something at this path? Only a definite ENOENT counts as
    "no roster". Path.exists() also swallows ELOOP/ENOTDIR/EACCES, which
    would turn a dangling symlink or an unreadable parent into a SILENTLY
    DISABLED allowlist — the one failure direction this control cannot have.
    lstat, not stat, so a broken symlink is still "something is here"."""
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return True

"""Optional passwd-style roster: the operator's list of who may connect.

One entry per line, ':'-separated; blank lines and '#' comments ignored:

    # who is allowed to use the chat server
    alice:Alice Anderson
    bob:Bob Brown
    carol:Carol Clark:disabled

Fields are `user[:display[:flags]]`. `display` overrides the name stored in
the account. `flags` is a comma-separated list; the only flag is `disabled`,
which keeps the record (and the account's data) but blocks the account —
the file's own equivalent of a `!` in shadow(5).

Deliberately NOT a shadow file: passwords stay in each account's auth.json.
This roster is meant to be read, reviewed, diffed, and generated from
whatever the org already treats as the source of truth for "who works here",
so it must never hold a secret.

Two properties are worth stating plainly, because they are the whole point:

* Enforcement is decided ONCE, when the server starts (a file that exists
  arms the allowlist for the life of the process). Deciding it per read
  would mean `rm passwd` silently switches the control off.
* The CONTENTS are re-read whenever the file changes, so adding or removing
  a line takes effect on the very next request with no restart — including
  for sessions that are already logged in. Every failure after arming —
  unreadable, unparseable, oversized, deleted — denies EVERY user instead of
  falling back to open: a roster that cannot be read is not evidence that
  everyone is allowed.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import NamedTuple

from .config import USER_RE
from .errors import ApiError
from .util import log

# ~30k entries at a typical line length. A mistyped --passwd (a log file, a
# device node) must not be slurped into memory on every change.
MAX_ROSTER_BYTES = 1 << 20


class Entry(NamedTuple):
    user: str
    display: str | None
    disabled: bool


class Roster:
    def __init__(self, path: Path | None):
        self.path = Path(path) if path else None
        self.enforcing = bool(self.path and self.path.exists())
        self._lock = threading.Lock()
        self._stamp: object = object()      # sentinel: never equals a real stat
        self._entries: dict[str, Entry] = {}
        self.error: str | None = None
        if self.enforcing:
            n = len(self.entries())
            log(f"roster: enforcing {self.path} "
                f"({n} entr{'y' if n == 1 else 'ies'})")
        elif self.path:
            log(f"roster: no allowlist at {self.path} — every provisioned "
                "account may connect")

    # ---- reading -----------------------------------------------------------
    def entries(self) -> dict[str, Entry]:
        """The parsed roster, re-read only when the file actually changes
        (one stat per call, not one parse). Empty when it cannot be read —
        which denies everyone, by design."""
        if not self.enforcing:
            return {}
        with self._lock:
            stamp = self._stat()
            if stamp != self._stamp:
                self._stamp = stamp
                self._entries, self.error = self._parse()
                if self.error:
                    log(f"roster: {self.error} — DENYING every user until "
                        f"{self.path} is readable again")
            return self._entries

    def _stat(self):
        try:
            st = os.stat(self.path)
            return (st.st_mtime_ns, st.st_size, st.st_ino, st.st_dev)
        except OSError as e:
            return ("unstattable", e.errno)

    def _parse(self) -> tuple[dict[str, Entry], str | None]:
        try:
            raw = self.path.read_bytes()
        except OSError as e:
            return {}, f"cannot read {self.path}: {e.strerror or e}"
        if len(raw) > MAX_ROSTER_BYTES:
            return {}, f"{self.path} is larger than {MAX_ROSTER_BYTES} bytes"
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
        line = user
        if display:
            # ':' and newlines are the format's separators; keep a display
            # name from silently turning into a flags field
            line += ":" + display.replace(":", " ").replace("\n", " ").strip()
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

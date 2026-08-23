"""The user file: ONE passwd-style file is the entire user database.

One entry per line, ':'-separated; blank lines and '#' comments ignored:

    # user[:display[:flags[:password]]]
    alice:Alice Anderson::pbkdf2-sha256$600000$<salt-hex>$<hash-hex>
    bob:Bob Brown:must-change:pbkdf2-sha256$600000$...$...
    carol:Carol Clark:disabled:pbkdf2-sha256$600000$...$...

The PASSWORD is the LAST field, exactly like pre-shadow /etc/passwd — and
because it is last, the line is split at most three times and the hash spec
may safely never collide with the separators (it uses '$' internally).
`display` overrides nothing any more: it IS the display name. `flags` is a
comma-separated list; `disabled` blocks the account while keeping the record,
`must-change` forces a password change at next login (cleared automatically
when the user changes it). An entry with no password field parses fine but
can never log in — useful for staging a name before issuing a credential.
A '#' starts a comment only at the START of a line: `alice  # note` is a
malformed username and (fail-closed) alice is then denied.

There are no account files besides this: an account's DIRECTORY (queue,
sessions, staged uploads) is provisioned automatically on first contact —
the first successful login, or the first message routed to the user —
so an operator adds a line and is done.

Consequences worth stating plainly:

* The file now holds password HASHES (PBKDF2-HMAC-SHA256, per-entry salt),
  so unlike the earlier allowlist-only roster it is no longer secret-free:
  keep it readable by the service and the operators only (0600/0640).
* The server itself REWRITES the file when a user changes their password
  (atomic re-write of just that line, under <path>.lock). A file the
  service cannot write is a valid hardening choice: logins keep working
  and self-service password changes answer 503.
* The file is authoritative and hot-reloaded: add a line and the user can
  log in on the next request; remove it and they are cut off within about
  a second, INCLUDING sessions already logged in. No file means no users —
  and every unreadable state (FIFO, directory, symlink loop, non-UTF-8,
  oversized) denies EVERYONE rather than guessing: a user database that
  cannot be read is not evidence that anyone is allowed.
* The stat stamp used to notice edits can in principle be defeated by a
  mtime-preserving copy (`rsync -a`, `cp -p`) or a coarse-mtime filesystem,
  and a missed REVOCATION is the dangerous direction — so the file is
  re-read at least every STALE_AFTER seconds regardless.

Nothing here may block: `allows()` sits on the path of every authenticated
request, so the file is opened non-blocking and rejected unless it is a
regular file (a FIFO at this path would otherwise park every worker thread
forever), and no lock is held across the read.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import secrets
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
# Upper bound on how long a stat-stamp collision can hide a change.
STALE_AFTER = 5.0

KNOWN_FLAGS = {"disabled", "must-change"}


# ---- password hashes (self-describing, so iterations can be raised later
#      without breaking existing lines) ------------------------------------
def make_hash(password: str, iters: int) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    return f"pbkdf2-sha256${iters}${salt.hex()}${h.hex()}"


def check_hash(password: str, spec: str) -> bool:
    """Constant-time verify; False for anything malformed (fail closed). A
    malformed spec still burns a comparable amount of work so a broken line
    is not distinguishable from a wrong password by timing."""
    try:
        scheme, iters_s, salt_hex, hash_hex = spec.split("$")
        if scheme != "pbkdf2-sha256":
            raise ValueError
        iters = int(iters_s)
        if not 1 <= iters <= 10_000_000:
            raise ValueError
        salt, want = bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        burn(600_000)
        return False
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    return hmac.compare_digest(got, want)


def burn(iters: int) -> None:
    """Spend the time a real verify would, so unknown users, password-less
    entries, and malformed specs are indistinguishable from a wrong password."""
    hashlib.pbkdf2_hmac("sha256", b"x", b"x" * 16, iters)


class Entry(NamedTuple):
    user: str
    display: str | None
    disabled: bool
    must_change: bool
    password: str | None      # the hash spec, never a cleartext


class Roster:
    def __init__(self, path: Path | None):
        self.path = Path(path) if path else None
        # (stamp, entries, error, read_at) swapped as ONE reference, so a
        # reader never sees a stamp that disagrees with its entries. No lock:
        # a change may be parsed twice concurrently, which is cheap — while a
        # lock held across the read is how one bad file wedges every thread.
        self._cache: tuple = (object(), {}, None, 0.0)
        self._logged: str | None = None
        n = len(self.entries())
        if n:
            log(f"roster: {self.path}: {n} user{'s' if n != 1 else ''}")
        elif self.error is None:
            log(f"roster: no user file at {self.path} — NO ONE can log in "
                "until it exists (see README: 'Users')")

    @property
    def error(self) -> str | None:
        return self._cache[2]

    # ---- reading -----------------------------------------------------------
    def entries(self) -> dict[str, Entry]:
        """The parsed user file, re-read when it changes (one stat per call)
        and at least every STALE_AFTER seconds. Empty when absent or when it
        cannot be read — either way no one is allowed, by design."""
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
        """Bytes of the user file, or a reason not to trust it. A genuinely
        ABSENT file is (b"", None): zero users, not an error to spam about.
        O_NONBLOCK plus an S_ISREG check because this runs on every request:
        opening a FIFO (or a device) here would block a worker forever."""
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK)
        except FileNotFoundError:
            return b"", None
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
            # password is the LAST field: split at most 3 times so the spec
            # (which never contains ':' anyway) could never be split further
            parts = line.split(":", 3)
            user = parts[0].strip()
            display = parts[1].strip() if len(parts) > 1 else ""
            flags = parts[2].strip() if len(parts) > 2 else ""
            password = parts[3].strip() if len(parts) > 3 else ""
            if not USER_RE.match(user):
                log(f"roster: {self.path}:{n}: bad username {user!r}, ignored")
                continue
            disabled = must_change = False
            unknown = None
            for f in (p.strip().lower() for p in flags.split(",")):
                if not f:
                    continue
                if f == "disabled":
                    disabled = True
                elif f == "must-change":
                    must_change = True
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
            out[user] = Entry(user, display or None, disabled, must_change,
                              password or None)
        return out, None

    # ---- queries -----------------------------------------------------------
    def entry(self, user: str) -> Entry | None:
        return self.entries().get(user)

    def allows(self, user: str) -> bool:
        e = self.entries().get(user)
        return e is not None and not e.disabled

    def display(self, user: str) -> str | None:
        e = self.entries().get(user)
        return e.display if e else None

    # ---- writing (the CLI, and the server on password change) --------------
    def _lock(self):
        """A sidecar lock, because the file itself is atomically REPLACED on
        rewrite — an flock on the old inode would guard nothing. Serializes
        the CLI and the server; a hand edit in vim is outside it (last writer
        wins), which the docs say out loud."""
        lockp = self.path.with_name(self.path.name + ".lock")
        fd = os.open(lockp, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    @staticmethod
    def _fmt(user: str, display: str | None, flags: list[str],
             password: str | None) -> str:
        # canonical 4-field form whenever a password is present, so the last
        # field is unambiguously the hash even with empty display/flags
        if password:
            return f"{user}:{display or ''}:{','.join(flags)}:{password}"
        if flags:
            return f"{user}:{display or ''}:{','.join(flags)}"
        return f"{user}:{display}" if display else user

    @staticmethod
    def _check_display(display: str | None) -> None:
        if not display:
            return
        # ':' is the field separator, and str.splitlines() — which the parser
        # uses — honours EIGHT terminators beyond \n. Reject rather than
        # rewrite: a crafted display name must never inject a second line.
        if ":" in display or not display.isprintable():
            raise ApiError(400, "display name must be printable and "
                                "must not contain ':'")

    def add_entry(self, user: str, display: str | None, password: str,
                  must_change: bool = False) -> None:
        """Append one user. Appending (not rewriting) means a concurrent hand
        edit elsewhere in the file cannot be clobbered; the lock serializes
        concurrent CLI runs so two appends cannot interleave."""
        if not self.path:
            raise ApiError(400, "no user file path configured")
        if not USER_RE.match(user):
            raise ApiError(400, "bad username (allowed: [a-z0-9_.-]{1,32})")
        self._check_display(display)
        fd = self._lock()
        try:
            if self.invalidate().get(user) is not None:
                # appending would be a silent no-op: the parser takes the
                # FIRST entry for a name
                raise ApiError(409, f"{user!r} already exists in {self.path}")
            flags = ["must-change"] if must_change else []
            line = self._fmt(user, display, flags, password)
            need_nl = False
            try:
                size = self.path.stat().st_size
                if size:
                    with open(self.path, "rb") as f:
                        f.seek(-1, os.SEEK_END)
                        need_nl = f.read(1) != b"\n"
            except FileNotFoundError:
                pass                     # first user creates the file
            with open(self.path, "a", encoding="utf-8") as f:
                if f.tell() == 0:
                    os.fchmod(f.fileno(), 0o600)   # it holds hashes now
                f.write(("\n" if need_nl else "") + line + "\n")
        except OSError as e:
            raise ApiError(503, f"cannot write {self.path}: {e.strerror or e}")
        finally:
            os.close(fd)

    def set_password(self, user: str, password_spec: str,
                     must_change: bool = False) -> None:
        """Rewrite exactly ONE user's password (and must-change flag), leaving
        every other byte of the file — comments, spacing, other entries —
        untouched. Atomic replace, so readers see the old file or the new one,
        never a torn line."""
        if not self.path:
            raise ApiError(400, "no user file path configured")
        fd = self._lock()
        try:
            raw, err = self._read()
            if err:
                raise ApiError(503, err)
            try:
                text = raw.decode()
            except UnicodeDecodeError:
                raise ApiError(503, f"{self.path} is not valid UTF-8")
            lines = text.split("\n")
            hit = None
            for i, line in enumerate(lines):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.split(":", 3)[0].strip() == user:
                    hit = i
                    break                # first wins, matching the parser
            if hit is None:
                raise ApiError(404, f"no such user in {self.path}")
            parts = lines[hit].strip().split(":", 3)
            display = parts[1].strip() if len(parts) > 1 else ""
            old_flags = parts[2].strip() if len(parts) > 2 else ""
            flags = [f.strip() for f in old_flags.split(",")
                     if f.strip() and f.strip().lower() != "must-change"]
            if must_change:
                flags.append("must-change")
            lines[hit] = self._fmt(user, display or None, flags, password_spec)
            tmp = self.path.with_name(self.path.name + ".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                os.fchmod(f.fileno(), 0o600)
                f.write("\n".join(lines))
            os.replace(tmp, self.path)
        except OSError as e:
            raise ApiError(503, f"password change unavailable: cannot write "
                                f"{self.path} ({e.strerror or e})")
        finally:
            os.close(fd)

    def invalidate(self) -> dict[str, Entry]:
        """Drop the cache and re-read now — for writers that must decide on
        CURRENT contents, not on a stamp-cached view."""
        self._cache = (object(), {}, None, 0.0)
        return self.entries()

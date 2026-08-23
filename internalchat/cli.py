"""Command-line entry: `serve`, `adduser`, `passwd`, `roster`, `hashpw`,
`export-passwd`."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .util import log
from .errors import ApiError
from .store import Store
from .router import Janitor
from .server import build_server

DESCRIPTION = "internal-chat server (folder-queue, stdlib only, no database)"

def _store(args) -> Store:
    """One Store constructor for every subcommand, so the user-file path is
    resolved identically. An EXPLICIT --roster that isn't there is a hard
    error: silently treating a mistyped path as "empty user file" would lock
    everyone out while looking like a clean start."""
    if getattr(args, "roster", None) and not Path(args.roster).is_file():
        raise ApiError(400, f"--roster {args.roster}: no such file (refusing "
                            "to run against a user file that does not exist)")
    return Store(args.data, roster=getattr(args, "roster", None))


def cmd_serve(args) -> None:
    store = _store(args)
    static_dir = Path(args.static).resolve() if args.static else None
    if not args.cert:
        log("WARNING: no --cert given, serving PLAIN HTTP — dev use only")
    httpd, router, api = build_server(store, args.host, args.port,
                                      static_dir, args.cert)
    Janitor(store, retain_days=args.retain_days, limiters=api.limiters).start()
    scheme = "https" if args.cert else "http"
    log(f"serving on {scheme}://{args.host}:{httpd.server_address[1]} "
        f"(data: {store.root})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        router.stopping.set()
        httpd.shutdown()


def _password(args, prompt: str) -> str:
    """One rule for every command, and the SAME rule POST /api/password
    enforces — the CLI used to accept a 1-character or even empty password,
    which is a weaker account than the API would ever let a user create."""
    pw = args.password if args.password is not None else getpass.getpass(prompt)
    if not 8 <= len(pw) <= 128:
        raise ApiError(400, "password must be 8..128 characters")
    return pw


def cmd_adduser(args) -> None:
    """Append one line to the user file. That is the WHOLE of provisioning:
    the account's directory appears by itself on first contact (first login,
    or the first message routed to the user)."""
    store = _store(args)
    password = _password(args, f"initial password for {args.user}: ")
    store.add_user(args.user, password, display=args.display,
                   must_change=not args.no_change)
    print(f"user {args.user!r} added to {store.roster.path} "
          f"(must change password on first login: {not args.no_change})")


def cmd_passwd(args) -> None:
    store = _store(args)
    if not store.user_exists(args.user):
        raise ApiError(404, f"no such user in {store.roster.path}")
    password = _password(args, f"new password for {args.user}: ")
    store.set_password(args.user, password, must_change=not args.no_change)
    sessions = store.user_dir(args.user) / "sessions"
    if sessions.is_dir():          # never provisioned = nothing to invalidate
        for s in sessions.iterdir():
            s.unlink(missing_ok=True)  # admin reset logs them out everywhere
    print(f"password reset for {args.user!r}; all sessions invalidated")


def cmd_roster(args) -> None:
    """The user file against the on-disk account state. The one drift that
    still exists is entries that have never made first contact (no directory
    yet) — and legacy directories whose line was removed (revoked)."""
    store = _store(args)
    r = store.roster
    entries = r.entries()
    if r.error:
        print(f"user file UNREADABLE ({r.error}): every user is denied")
    elif not entries:
        print(f"no users in {r.path} — no one can log in")
    provisioned = set()
    users_root = store.root / "users"
    if users_root.is_dir():
        provisioned = {p.name for p in users_root.iterdir() if p.is_dir()}
    for name in sorted(set(entries) | provisioned):
        e = entries.get(name)
        if e is None:
            state = "REVOKED (data on disk, no entry)"
        elif e.disabled:
            state = "disabled"
        elif not e.password:
            state = "no password set"
        elif e.must_change:
            state = "must change password"
        elif name not in provisioned:
            state = "listed, no contact yet"
        else:
            state = "ok"
        print(f"{name:<20} {state:<28} {(e.display if e else '') or ''}")


def cmd_hashpw(args) -> None:
    """Print a password-hash spec to paste into the user file by hand — for
    operators who manage the file in git/config-management and never run
    adduser on the box."""
    from .roster import make_hash
    from .config import PBKDF2_ITERS
    password = _password(args, "password to hash: ")
    print(make_hash(password, PBKDF2_ITERS))


def cmd_export_passwd(args) -> None:
    """Migration from the legacy per-account auth.json layout: emit one user
    line per existing account, preserving display, must-change, and the
    EXISTING hash (already pbkdf2-sha256, so nobody's password changes).
    Redirect into the user file:  chatserver.py export-passwd --data D >> D/passwd"""
    store = Store.__new__(Store)          # raw: no roster needed to read legacy
    store.root = Path(args.data).resolve()
    users_root = store.root / "users"
    if not users_root.is_dir():
        raise ApiError(404, f"no users/ under {store.root}")
    count = 0
    for udir in sorted(users_root.iterdir()):
        authf = udir / "auth.json"
        if not authf.is_file():
            continue
        try:
            a = json.loads(authf.read_text())
            spec = f"pbkdf2-sha256${a['iters']}${a['salt']}${a['hash']}"
            display = str(a.get("display", "") or "")
            if ":" in display or not display.isprintable():
                display = ""
            flags = "must-change" if a.get("must_change") else ""
            print(f"{udir.name}:{display}:{flags}:{spec}")
            count += 1
        except (ValueError, KeyError) as e:
            print(f"# SKIPPED {udir.name}: unreadable auth.json ({e})",
                  file=sys.stderr)
    print(f"# exported {count} users", file=sys.stderr)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=DESCRIPTION)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve", help="run the chat server")
    sp.add_argument("--data", default="./data")
    sp.add_argument("--host", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=8443)
    sp.add_argument("--cert", help="PEM with certificate + key (enables TLS)")
    sp.add_argument("--static", help="directory with the web client to serve")
    sp.add_argument("--retain-days", type=int, default=0,
                    help="archive day folders older than N days (0 = keep)")
    sp.add_argument("--roster", help="the user file "
                                     "(default: <data>/passwd)")
    sp.set_defaults(func=cmd_serve)

    au = sub.add_parser("adduser", help="add a user (one line in the user file)")
    au.add_argument("user")
    au.add_argument("--data", default="./data")
    au.add_argument("--roster")
    au.add_argument("--display")
    au.add_argument("--password", help="set non-interactively (visible in ps!)")
    au.add_argument("--no-change", action="store_true",
                    help="don't force a password change on first login")
    au.set_defaults(func=cmd_adduser)

    ro = sub.add_parser("roster", help="show the user file vs on-disk state")
    ro.add_argument("--data", default="./data")
    ro.add_argument("--roster")
    ro.set_defaults(func=cmd_roster)

    pw = sub.add_parser("passwd", help="admin password reset (kills all sessions)")
    pw.add_argument("user")
    pw.add_argument("--data", default="./data")
    pw.add_argument("--roster")
    pw.add_argument("--password", help="set non-interactively (visible in ps!)")
    pw.add_argument("--no-change", action="store_true",
                    help="don't force a password change on next login")
    pw.set_defaults(func=cmd_passwd)

    hp = sub.add_parser("hashpw",
                        help="print a hash spec to paste into the user file")
    hp.add_argument("--password", help="hash non-interactively (visible in ps!)")
    hp.set_defaults(func=cmd_hashpw)

    ex = sub.add_parser("export-passwd",
                        help="emit user-file lines from legacy auth.json accounts")
    ex.add_argument("--data", default="./data")
    ex.set_defaults(func=cmd_export_passwd)

    args = ap.parse_args(argv)
    try:
        args.func(args)
    except ApiError as e:
        print(f"error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (EOFError, KeyboardInterrupt):
        print("error: no password supplied", file=sys.stderr)
        sys.exit(1)

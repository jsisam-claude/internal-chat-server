"""Command-line entry: `serve`, `adduser`, `roster`, `passwd`."""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .util import log
from .errors import ApiError
from .store import Store
from .router import Janitor
from .server import build_server

DESCRIPTION = "internal-chat server (folder-queue, stdlib only, no database)"

def _store(args) -> Store:
    """One Store constructor for every subcommand, so the roster path is
    resolved identically. An EXPLICIT --roster that isn't there is a hard
    error: silently treating a mistyped path as "no allowlist" is exactly
    how this control would get switched off without anyone noticing."""
    if getattr(args, "roster", None) and not Path(args.roster).is_file():
        raise ApiError(400, f"--roster {args.roster}: no such file (refusing "
                            "to run with the allowlist silently disabled)")
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
    """One rule for both commands, and the SAME rule POST /api/password
    enforces — the CLI used to accept a 1-character or even empty password,
    which is a weaker account than the API would ever let a user create."""
    pw = args.password if args.password is not None else getpass.getpass(prompt)
    if not 8 <= len(pw) <= 128:
        raise ApiError(400, "password must be 8..128 characters")
    return pw


def cmd_adduser(args) -> None:
    store = _store(args)
    if args.approve:
        store.roster.approve(args.user, args.display)
        print(f"approved {args.user!r} in {store.roster.path}")
    password = _password(args, f"initial password for {args.user}: ")
    # the roster's display name is the operator's central one; honour it
    # unless this command was given an explicit --display
    display = args.display or store.roster.display(args.user)
    store.add_user(args.user, password, display=display,
                   must_change=not args.no_change)
    print(f"user {args.user!r} created (must change password on first login: "
          f"{not args.no_change})")


def cmd_roster(args) -> None:
    """Show the allowlist next to the accounts, because the two drift: an
    approved name with no account can't log in yet, and an account with no
    entry is revoked but still holds its data."""
    store = _store(args)
    r = store.roster
    if not r.enforcing:
        print(f"no roster at {r.path} — every provisioned account may connect")
    if r.error:
        print(f"roster UNREADABLE ({r.error}): every user is denied")
    entries = r.entries()
    accounts = sorted(p.name for p in (store.root / "users").iterdir()
                      if (p / "auth.json").is_file())
    for name in sorted(set(entries) | set(accounts)):
        e = entries.get(name)
        if e is None:
            state = "REVOKED (account only)" if r.enforcing else "account"
        elif e.disabled:
            state = "disabled"
        elif name not in accounts:
            state = "approved, no account yet"
        else:
            state = "ok"
        print(f"{name:<20} {state:<24} {(e.display if e else '') or ''}")


def cmd_passwd(args) -> None:
    store = _store(args)
    if not store.user_exists(args.user):
        raise ApiError(404, "no such user")
    password = _password(args, f"new password for {args.user}: ")
    store.set_password(args.user, password, must_change=not args.no_change)
    for s in (store.user_dir(args.user) / "sessions").iterdir():
        s.unlink(missing_ok=True)  # admin reset logs the user out everywhere
    print(f"password reset for {args.user!r}; all sessions invalidated")


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
    sp.add_argument("--roster", help="allowlist of who may connect "
                                     "(default: <data>/passwd, if present)")
    sp.set_defaults(func=cmd_serve)

    au = sub.add_parser("adduser", help="provision a user")
    au.add_argument("user")
    au.add_argument("--data", default="./data")
    au.add_argument("--roster")
    au.add_argument("--display")
    au.add_argument("--approve", action="store_true",
                    help="add the user to the roster first (it must exist)")
    au.add_argument("--password", help="set non-interactively (visible in ps!)")
    au.add_argument("--no-change", action="store_true",
                    help="don't force a password change on first login")
    au.set_defaults(func=cmd_adduser)

    ro = sub.add_parser("roster", help="show the allowlist and the accounts")
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

    args = ap.parse_args(argv)
    try:
        args.func(args)
    except ApiError as e:
        print(f"error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (EOFError, KeyboardInterrupt):
        print("error: no password supplied", file=sys.stderr)
        sys.exit(1)


"""Command-line entry: `serve`, `adduser`, and `passwd` subcommands."""
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

def cmd_serve(args) -> None:
    store = Store(args.data)
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


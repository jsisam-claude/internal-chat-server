"""internal-chat server — a lightweight, dependency-free chat backend.

The filesystem is the database and the queue: messages are directories, flags
are marker files, per-user queues are folders of symlinks, and every state
change is an atomic file operation. See DESIGN.md / API.md for the full model.

Module map
----------
config     limits, regexes, CSP, static-type table
errors     ApiError (the one raised type)
util       stateless helpers (ids, filenames, directory walks, logging)
store      Store — the on-disk data model
notifier   per-user wakeups for long-polling
ratelimit  bounded sliding-window rate limiter
router     Router (moves/fans out messages) + Janitor (retention)
api        Api — all request-handling business logic, HTTP-independent
server     the HTTP handler + build_server() wiring
cli        `serve` / `adduser` / `passwd` command line
"""
from .config import (  # noqa: F401  (re-exported for tests / embedders)
    SEND_LIMIT, SEND_WINDOW, UPLOAD_LIMIT, UPLOAD_WINDOW, LOGIN_IP_LIMIT,
    USER_STORAGE_QUOTA, MAX_FILE, MAX_TEXT, MAX_ATTACHMENTS)
from .errors import ApiError  # noqa: F401
from .util import (  # noqa: F401
    log, now_ms, mid_date, sanitize_filename, msg_dirs_newest_first)
from .store import Store  # noqa: F401
from .notifier import Notifier  # noqa: F401
from .ratelimit import RateLimiter  # noqa: F401
from .router import Router, Janitor  # noqa: F401
from .api import Api  # noqa: F401
from .server import Handler, build_server  # noqa: F401
from .cli import main  # noqa: F401

__all__ = [
    "Store", "Notifier", "RateLimiter", "Router", "Janitor", "Api",
    "Handler", "build_server", "main", "ApiError",
    "log", "now_ms", "mid_date", "sanitize_filename", "msg_dirs_newest_first",
    "SEND_LIMIT", "UPLOAD_LIMIT", "LOGIN_IP_LIMIT", "USER_STORAGE_QUOTA",
    "MAX_FILE", "MAX_TEXT", "MAX_ATTACHMENTS",
]

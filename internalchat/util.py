"""Small stateless helpers shared across the package."""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from .config import DATE_RE, MID_RE

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
        try:
            entries = sorted(day.iterdir(), reverse=True)
        except FileNotFoundError:
            continue  # janitor archived this day folder mid-walk
        for mdir in entries:
            if MID_RE.match(mdir.name):
                yield mdir


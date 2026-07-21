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


def image_mime(head: bytes) -> str | None:
    """Detect a SAFE-to-render-inline image type from magic bytes only —
    never from the filename, which the uploader controls. Deliberate
    allowlist: png/jpeg/gif/webp. SVG is intentionally absent (it is
    scriptable XML and must never be served inline), as are formats with
    exotic parser surface (BMP/TIFF/ICO). Comparing a few constant bytes is
    NOT image parsing — the server still never decodes uploads."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    return None


def audio_mime(head: bytes) -> str | None:
    """Detect a SAFE-to-play-inline audio container from magic bytes only —
    same rules as image_mime: constant-byte comparison, never parsing, never
    the filename. Allowlist: webm/ogg (what MediaRecorder produces), mp4/m4a
    (Safari's MediaRecorder), mp3. Anything else stays a download."""
    if head.startswith(b"\x1a\x45\xdf\xa3"):          # EBML (webm)
        return "audio/webm"
    if head.startswith(b"OggS"):
        return "audio/ogg"
    if len(head) >= 8 and head[4:8] == b"ftyp":       # ISO-BMFF (mp4/m4a)
        return "audio/mp4"
    if head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF
                                   and (head[1] & 0xE0) == 0xE0):
        return "audio/mpeg"
    return None


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


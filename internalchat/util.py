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


# ISO-BMFF major brands that are audio-ONLY (iTunes audio). Every other brand
# in the family (isom/iso2/mp41/mp42/avc1/dash/M4V …) may carry a video track.
AUDIO_BRANDS = (b"M4A ", b"M4B ", b"M4P ")


def av_mime(head: bytes, audio_hint: bool = False) -> tuple[str, str] | None:
    """Detect a SAFE-to-play-inline audio/video CONTAINER from magic bytes.
    Returns ("audio"|"video", mime), or None if it isn't playable media.

    Same rules as image_mime: constant-offset byte comparison, never parsing,
    never the filename. The wrinkle is that mp4 and webm are *containers* that
    can each hold audio-only OR video, so a type alone doesn't say how to
    present the file:

    * ISO-BMFF is resolved by its `ftyp` MAJOR BRAND — a fixed-offset field, so
      reading it is still just comparing constant bytes.
    * WebM/Matroska is genuinely undecidable here: audio-vs-video lives in the
      Tracks element, reachable only by walking EBML, which is parsing. It
      therefore defaults to VIDEO, because the failure modes are asymmetric —
      a <video> element plays an audio-only file fine (it just shows no
      picture), while an <audio> element cannot show a video at all and looks
      broken to the user.
    * `audio_hint` lets a client that RECORDED a voice note say so. It is
      PRESENTATION-ONLY: magic bytes remain the sole authority on whether a
      file may render inline and which container is served, so the hint can
      never make a non-media file inline-able, never changes the container, and
      never yields a scriptable type. It only narrows an already-verified
      ambiguous container from video to audio. Worst case, a user mislabels
      their own message; there is no cross-user impact.
    """
    if head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF
                                   and (head[1] & 0xE0) == 0xE0):
        return ("audio", "audio/mpeg")            # mp3: never carries video
    if head.startswith(b"OggS"):
        # Ogg can technically carry Theora video, but that is effectively
        # extinct; audio (vorbis/opus) is what clients produce.
        return ("audio", "audio/ogg")
    if head.startswith(b"\x1a\x45\xdf\xa3"):      # EBML: webm / matroska
        return ("audio", "audio/webm") if audio_hint else ("video", "video/webm")
    if len(head) >= 12 and head[4:8] == b"ftyp":  # ISO-BMFF: mp4 / m4a / mov
        if head[8:12] in AUDIO_BRANDS or audio_hint:
            return ("audio", "audio/mp4")
        return ("video", "video/mp4")
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


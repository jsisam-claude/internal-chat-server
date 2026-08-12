"""HTTP layer: the request handler that maps routes to Api calls, static
file serving, and build_server() which wires Store + Notifier + Router + Api
behind a threading HTTPS server."""
from __future__ import annotations

import json
import os
import ssl
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from .config import CSP, STATIC_TYPES, MAX_JSON, MAX_WAIT, MAX_CONNECTIONS
from .errors import ApiError
from .util import log
from .store import Store
from .notifier import Notifier
from .router import Router
from .api import Api

def _reject_surrogates(obj) -> None:
    """Walk a parsed JSON value and raise 400 if any string holds a lone
    surrogate (\\ud800-\\udfff). Such strings decode fine but crash on UTF-8
    encode; bounded by MAX_JSON so the walk is cheap. Iterative on purpose:
    a recursive walk's stack budget would ride on json.loads having stricter
    recursion accounting, which is a CPython detail, not a guarantee."""
    stack = [obj]
    while stack:
        o = stack.pop()
        if isinstance(o, str):
            if any("\ud800" <= c <= "\udfff" for c in o):
                raise ApiError(400, "bad json")
        elif isinstance(o, dict):
            stack.extend(o.keys())
            stack.extend(o.values())
        elif isinstance(o, list):
            stack.extend(o)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 75  # must exceed MAX_WAIT so long-polls aren't cut off
    server_version = "internal-chat"
    api: Api  # bound by build_server()
    static_dir: Path | None = None
    _head = False  # per-request "suppress the body" flag; reset in _dispatch

    # ---- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *args):  # quiet 2xx; log the rest
        pass

    def log_request(self, code="-", size="-"):
        if isinstance(code, int) and code >= 400:
            log(f"{self.client_address[0]} {self.command} "
                f"{self.path.split('?')[0]} -> {code}")

    def _hsts(self) -> None:
        # HSTS only over TLS (browsers must ignore it on plain HTTP, and the
        # spec forbids sending it there).
        if isinstance(self.connection, ssl.SSLSocket):
            self.send_header("Strict-Transport-Security",
                             "max-age=31536000; includeSubDomains")

    def _send_json(self, obj, status: int = 200) -> None:
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self._hsts()
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not self._head:   # HEAD: true Content-Length, zero body bytes
            self.wfile.write(data)

    def _json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not 0 < length <= MAX_JSON:
            raise ApiError(400, "missing or oversized body")
        try:
            # RecursionError: a deeply-nested "[[[[..." blows the parser's C
            # recursion limit; without catching it a malformed body 500s.
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise ApiError(400, "bad json")
        if not isinstance(body, dict):
            raise ApiError(400, "bad json")
        # JSON permits "\ud800" (a lone surrogate) but UTF-8 cannot encode it,
        # so any downstream `.encode()` (password hashing, message.txt, emoji,
        # group names) would raise UnicodeEncodeError → 500. Reject at the door.
        _reject_surrogates(body)
        return body

    def _user(self) -> str:
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            raise ApiError(401, "auth required")
        self._token = h[7:].strip()
        user = self.api.store.session_user(self._token)
        if not user:
            raise ApiError(401, "invalid or expired session")
        self.api.touch_seen(user)   # presence: any authenticated call counts
        return user

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        # HEAD rides the GET routing table (RFC 9110 §9.3.2: identical
        # headers, no body): same auth, same visibility gates, same read-only
        # api calls — only the body bytes are suppressed, at the three send_*
        # sinks — so the two methods can never diverge. The flag is
        # per-REQUEST state on a per-CONNECTION handler instance, so it must
        # be reset here on every request: the class default alone would let
        # one HEAD bleed body-suppression into the next keep-alive request.
        self._head = method == "HEAD"
        if self._head:
            method = "GET"
        try:
            url = urlsplit(self.path)
            parts = [p for p in url.path.split("/") if p]
            if any(p in (".", "..") for p in parts):
                raise ApiError(400, "bad path")
            self._route(method, parts, parse_qs(url.query))
        except ApiError as e:
            self.close_connection = True
            try:
                self._send_json({"error": e.message}, e.status)
            except OSError:
                pass
        except (ConnectionError, BrokenPipeError, TimeoutError):
            self.close_connection = True
        except Exception:
            log("handler: " + traceback.format_exc())
            self.close_connection = True
            try:
                self._send_json({"error": "internal error"}, 500)
            except OSError:
                pass

    # ---- routing -----------------------------------------------------------
    def _route(self, method: str, p: list[str], q: dict) -> None:
        api = self.api
        if not p or p[0] != "api":
            if method == "GET":
                return self._static(p)
            raise ApiError(404, "not found")
        p = p[1:]

        if method == "POST":
            if p == ["login"]:
                return self._send_json(api.login(self.client_address[0],
                                                 self._json_body()))
            if p == ["logout"]:
                self._user()
                api.store.drop_session(self._token)
                return self._send_json({"ok": True})
            if p == ["password"]:
                user = self._user()
                return self._send_json(api.change_password(user, self._json_body(),
                                                           self._token))
            if p == ["messages"]:
                return self._send_json(api.send(self._user(), self._json_body()))
            if len(p) == 4 and p[:3] == ["message", "dequeue", "read"]:
                return self._send_json(api.confirm(self._user(), p[3].split(",")))
            if p == ["message", "viewed"]:
                return self._send_json(api.viewed(self._user(), self._json_body()))
            if p == ["message", "react"]:
                return self._send_json(api.react(self._user(), self._json_body()))
            if p == ["message", "edit"]:
                return self._send_json(api.edit_message(self._user(),
                                                        self._json_body()))
            if p == ["message", "delete"]:
                return self._send_json(api.delete_message(self._user(),
                                                          self._json_body()))
            if p == ["message", "star"]:
                return self._send_json(api.star(self._user(), self._json_body()))
            if p == ["typing"]:
                return self._send_json(api.typing(self._user(), self._json_body()))
            if p == ["files"]:
                user = self._user()
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                # X-Media-Kind is a PRESENTATION hint only (see av_mime): it
                # can narrow an ambiguous A/V container to audio, and can never
                # grant inline rendering or change the served container.
                return self._send_json(api.upload(
                    user, self.rfile, length,
                    self.headers.get("X-File-Name", "file"),
                    self.headers.get("X-Media-Kind", "") == "audio"))
            if p == ["groups"]:
                return self._send_json(api.create_group(self._user(),
                                                        self._json_body()))
            if len(p) == 3 and p[0] == "groups" and p[2] == "members":
                return self._send_json(api.modify_members(self._user(), p[1],
                                                          self._json_body()))
            raise ApiError(404, "not found")

        # GET
        if p == ["messages"]:
            try:
                wait = float(q.get("wait", ["0"])[0])
            except ValueError:
                wait = 0.0
            if wait != wait:   # NaN: min(nan, MAX_WAIT) stays nan and the poll
                wait = 0.0     # deadline never elapses, wedging a worker thread
            return self._send_json(api.list_queue(self._user(), wait))
        if len(p) == 3 and p[:2] == ["message", "dequeue"]:
            return self._send_json(api.peek(self._user(), p[2]))
        if len(p) == 4 and p[:2] == ["message", "state"]:
            return self._send_json(api.state(self._user(), p[2], p[3]))
        if p == ["groups"]:
            return self._send_json(api.list_groups(self._user()))
        if len(p) == 2 and p[0] == "groups":
            return self._send_json(api.group_info(self._user(), p[1]))
        if len(p) == 3 and p[0] == "groups" and p[2] == "messages":
            try:
                limit = int(q.get("limit", ["50"])[0])
            except ValueError:
                limit = 50
            before = q.get("before", [None])[0]
            return self._send_json(api.history(self._user(), p[1], before, limit))
        if p == ["users"]:
            self._user()
            return self._send_json(api.list_users())
        if p == ["starred"]:
            return self._send_json(api.starred(self._user()))
        if p == ["search"]:
            try:
                limit = int(q.get("limit", ["20"])[0])
            except ValueError:
                limit = 20
            return self._send_json(api.search(
                self._user(), q.get("q", [""])[0],
                q.get("gid", [None])[0], limit))
        if len(p) == 4 and p[0] == "attachments":
            blob, meta = api.attachment(self._user(), p[1], p[2], p[3])
            # inline rendering is allowed ONLY for media the server verified
            # by magic bytes at upload — the request cannot force it
            media = (meta.get("image") or meta.get("audio")
                     or meta.get("video"))
            inline = q.get("inline", ["0"])[0] == "1" and bool(media)
            return self._send_blob(blob, meta["name"], meta["size"],
                                   ctype=media if inline
                                   else "application/octet-stream",
                                   inline=inline,
                                   sha256=meta.get("sha256"))
        if p == ["client", "version"]:
            if self.static_dir and (self.static_dir / "version.json").is_file():
                return self._send_static(self.static_dir / "version.json")
            raise ApiError(404, "no client published")
        raise ApiError(404, "not found")

    # ---- byte responses ------------------------------------------------------
    @staticmethod
    def _parse_range(header: str | None, fsize: int):
        """Parse a single-range 'bytes=' header against a file of `fsize`
        bytes. Returns an inclusive (start, end) window, None to serve the
        full body, or "unsat" (→ 416). Anything malformed — and multipart
        ranges, which we choose not to serve — is None, not an error: RFC
        9110 §14.2 lets a server ignore any Range header and a full 200 is
        always a correct answer, so this parser never needs to be clever.
        Digits are pinned to ASCII because int("¹") raises after isdigit()
        passes — the exact trap the attachment index hit (api.attachment)."""
        if not header or not header.startswith("bytes="):
            return None
        spec = header[6:].strip()
        if "," in spec:
            return None            # multipart: ignorable per RFC, so ignore
        start_s, sep, end_s = spec.partition("-")
        if not sep:
            return None
        if not start_s:            # suffix form "bytes=-N": the last N bytes
            if not (end_s.isascii() and end_s.isdigit()):
                return None
            n = int(end_s)
            # "-0" asks for zero bytes and an empty file has no last byte:
            # both are satisfiable-by-nothing → 416, not a zero-length 206
            if n == 0 or fsize == 0:
                return "unsat"
            return (max(fsize - n, 0), fsize - 1)
        if not (start_s.isascii() and start_s.isdigit()):
            return None
        start = int(start_s)
        if end_s:
            if not (end_s.isascii() and end_s.isdigit()):
                return None
            end = int(end_s)
            if end < start:
                return None        # last < first: invalid spec → serve full
            end = min(end, fsize - 1)
        else:
            end = fsize - 1        # open-ended "bytes=a-": to EOF
        if start >= fsize:
            return "unsat"         # nothing at/after EOF to serve
        return (start, end)

    def _inm_match(self, etag: str) -> bool:
        """True if the request's If-None-Match matches `etag`. GET/HEAD
        revalidation uses WEAK comparison (RFC 9110 §13.1.2), so the W/
        marker and quotes are stripped, any candidate in the list may match,
        and '*' matches any representation that exists — which this one does,
        or we would have 404ed before getting here."""
        inm = self.headers.get("If-None-Match")
        if not inm:
            return False
        bare = etag.strip('"')
        for cand in inm.split(","):
            cand = cand.strip()
            if cand == "*":
                return True
            if cand.startswith("W/"):
                cand = cand[2:].strip()
            if cand.strip('"') == bare:
                return True
        return False

    def _send_blob(self, path: Path, name: str, size: int,
                   ctype: str = "application/octet-stream",
                   inline: bool = False, sha256: str | None = None) -> None:
        """Attachments: opaque bytes. Default is a forced download. `inline`
        is used only for media the server verified by magic bytes at upload;
        even then, a CSP sandbox rides along so the bytes can never act as a
        document with script, and nosniff pins the declared type.

        Framing rule: Content-Length ALWAYS comes from fstat on the very fd
        being streamed, never from meta['size']. A stale meta size (crash-
        partial write, hand-edited tree) would otherwise promise more bytes
        than get sent, and on a keep-alive connection the client then reads
        the NEXT response's bytes as this body's tail — one bad meta poisons
        every later exchange on the socket. Open-then-fstat also closes the
        TOCTOU window a stat-then-open pair leaves.

        Blobs are immutable once routed (a delete tombstones the message and
        api.attachment 404s), so the upload-time sha256 is a permanent strong
        validator: it drives ETag + immutable Cache-Control, If-None-Match →
        304, and If-Range-gated single-range 206s (media seeking). Every
        status emitted here carries the full security header set — read
        'Security posture — do NOT weaken' in API.md before adding one."""
        try:
            f = open(path, "rb")
        except OSError:
            # the blob vanished between api.attachment's checks and here (a
            # delete race): gone is gone, and no headers are out yet, so this
            # still surfaces as a clean 404 instead of a mid-stream abort
            raise ApiError(404, "no such attachment")
        with f:
            fsize = os.fstat(f.fileno()).st_size
            if fsize != size:
                # serve the truth (the file), not the claim (the meta): a 404
                # here would take a working attachment down over bookkeeping
                log(f"blob {path}: meta size {size} != file size {fsize}; "
                    "serving file size")
            etag = f'"{sha256}"' if sha256 else None

            def security_headers():
                # the invariant set that rides on EVERY status this path can
                # emit (200/206/304/416) — see the posture section in API.md
                self.send_header("X-Content-Type-Options", "nosniff")
                if inline:
                    self.send_header("Content-Security-Policy",
                                     "default-src 'none'; sandbox")
                self.send_header("Cross-Origin-Resource-Policy", "same-origin")
                self._hsts()

            # conditional GET first: RFC 9110 §13.2.2 evaluates If-None-Match
            # before Range, so a revalidation never turns into a partial
            if etag and self._inm_match(etag):
                self.send_response(304)
                security_headers()
                self.send_header("ETag", etag)
                self.send_header("Cache-Control",
                                 "private, max-age=31536000, immutable")
                # no Content-Length: a 304 is bodiless BY STATUS (RFC 9110
                # §15.4.5), so omitting it keeps keep-alive framing exact,
                # while echoing the full-body length would only mislead
                self.end_headers()
                return
            # If-Range: a client resuming a download proves it still holds
            # OUR bytes; anything else (mismatch, weak W/ validator, a date —
            # we never emit Last-Modified, or no sha256 to compare against)
            # serves the WHOLE file so two representations can't be spliced.
            rng = None
            if_range = self.headers.get("If-Range")
            if if_range is None or (etag is not None
                                    and if_range.strip() == etag):
                rng = self._parse_range(self.headers.get("Range"), fsize)
            if rng == "unsat":
                self.send_response(416)
                security_headers()
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Range", f"bytes */{fsize}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status, start = (206, rng[0]) if rng else (200, 0)
            end = rng[1] if rng else fsize - 1
            span = end - start + 1
            ascii_name = (name.encode("ascii", "replace").decode()
                          .replace('"', "_"))
            disp = "inline" if inline else "attachment"
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            security_headers()
            self.send_header("Content-Disposition",
                             f'{disp}; filename="{ascii_name}"; '
                             f"filename*=UTF-8''{quote(name)}")
            self.send_header("Accept-Ranges", "bytes")
            if etag:
                self.send_header("ETag", etag)
                self.send_header("Cache-Control",
                                 "private, max-age=31536000, immutable")
            if status == 206:
                self.send_header("Content-Range",
                                 f"bytes {start}-{end}/{fsize}")
            self.send_header("Content-Length", str(span))
            self.end_headers()
            if self._head:
                return             # HEAD: true headers, zero body bytes
            f.seek(start)
            remaining = span
            while remaining:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    # the file shrank mid-stream (nothing should ever do this
                    # to a routed blob). Content-Length can no longer be
                    # honored, so kill the connection rather than let the
                    # client read the next response as this body's tail.
                    self.close_connection = True
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def _static(self, parts: list[str]) -> None:
        if self.static_dir is None:
            raise ApiError(404, "no web client installed")
        if any(part.startswith(".") for part in parts):
            raise ApiError(404, "not found")  # never serve dotfiles (.git etc.)
        base = self.static_dir.resolve()
        target = base.joinpath(*parts) if parts else base / "index.html"
        target = target.resolve()
        if not (target.is_file() and target.is_relative_to(base)):
            raise ApiError(404, "not found")
        self._send_static(target)

    def _send_static(self, path: Path) -> None:
        ctype = STATIC_TYPES.get(path.suffix.lower())
        data = path.read_bytes()
        self.send_response(200)
        if ctype is None:
            ctype = "application/octet-stream"
            self.send_header("Content-Disposition", "attachment")
        self.send_header("Content-Type", ctype)
        self.send_header("X-Content-Type-Options", "nosniff")
        self._hsts()
        if path.suffix.lower() == ".html":
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not self._head:   # HEAD: true Content-Length, zero body bytes
            self.wfile.write(data)


class BoundedHTTPServer(ThreadingHTTPServer):
    """Caps CONCURRENT CONNECTIONS at the accept side, before a worker thread is
    spawned — so a flood (including slowloris clients that dribble headers and
    would otherwise each hold a thread + FD) can't exhaust threads/FDs. Excess
    connections are closed immediately; the semaphore is released when the
    connection's thread finishes. This is the real thread/FD bound; put a
    reverse proxy in front for production-grade connection limiting."""
    max_connections = MAX_CONNECTIONS

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._conn_slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request, client_address):
        if not self._conn_slots.acquire(blocking=False):
            self.shutdown_request(request)   # at capacity: drop the connection
            return
        super().process_request(request, client_address)  # spawns the thread

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_slots.release()


def build_server(store: Store, host: str, port: int,
                 static_dir: Path | None = None, certfile: str | None = None):
    notifier = Notifier()
    router = Router(store, notifier)
    api = Api(store, notifier, router)
    handler = type("BoundHandler", (Handler,),
                   {"api": api, "static_dir": static_dir})
    httpd = BoundedHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    router.start()
    return httpd, router, api


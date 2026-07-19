"""HTTP layer: the request handler that maps routes to Api calls, static
file serving, and build_server() which wires Store + Notifier + Router + Api
behind a threading HTTPS server."""
from __future__ import annotations

import json
import shutil
import ssl
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .config import CSP, STATIC_TYPES, MAX_JSON, MAX_WAIT
from .errors import ApiError
from .util import log
from .store import Store
from .notifier import Notifier
from .router import Router
from .api import Api

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 75  # must exceed MAX_WAIT so long-polls aren't cut off
    server_version = "internal-chat"
    api: Api  # bound by build_server()
    static_dir: Path | None = None

    # ---- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *args):  # quiet 2xx; log the rest
        pass

    def log_request(self, code="-", size="-"):
        if isinstance(code, int) and code >= 400:
            log(f"{self.client_address[0]} {self.command} "
                f"{self.path.split('?')[0]} -> {code}")

    def _send_json(self, obj, status: int = 200) -> None:
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not 0 < length <= MAX_JSON:
            raise ApiError(400, "missing or oversized body")
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "bad json")
        if not isinstance(body, dict):
            raise ApiError(400, "bad json")
        return body

    def _user(self) -> str:
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            raise ApiError(401, "auth required")
        self._token = h[7:].strip()
        user = self.api.store.session_user(self._token)
        if not user:
            raise ApiError(401, "invalid or expired session")
        return user

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
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
            if p == ["files"]:
                user = self._user()
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                return self._send_json(api.upload(
                    user, self.rfile, length,
                    self.headers.get("X-File-Name", "file")))
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
        if len(p) == 4 and p[0] == "attachments":
            blob, meta = api.attachment(self._user(), p[1], p[2], p[3])
            return self._send_blob(blob, meta["name"], meta["size"])
        if p == ["client", "version"]:
            if self.static_dir and (self.static_dir / "version.json").is_file():
                return self._send_static(self.static_dir / "version.json")
            raise ApiError(404, "no client published")
        raise ApiError(404, "not found")

    # ---- byte responses ------------------------------------------------------
    def _send_blob(self, path: Path, name: str, size: int) -> None:
        """Attachments: always opaque bytes, always a download — never
        rendered from this origin, regardless of content."""
        ascii_name = name.encode("ascii", "replace").decode().replace('"', "_")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{ascii_name}"; '
                         f"filename*=UTF-8''{quote(name)}")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(path, "rb") as f:
            shutil.copyfileobj(f, self.wfile, 65536)

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
        if path.suffix.lower() == ".html":
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def build_server(store: Store, host: str, port: int,
                 static_dir: Path | None = None, certfile: str | None = None):
    notifier = Notifier()
    router = Router(store, notifier)
    api = Api(store, notifier, router)
    handler = type("BoundHandler", (Handler,),
                   {"api": api, "static_dir": static_dir})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    router.start()
    return httpd, router, api


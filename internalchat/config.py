"""Compiled regexes, size/rate limits, and static-serving tables.
Everything here is a plain constant — no logic, no imports beyond `re`."""
import re

USER_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")
GID_RE = re.compile(r"^[gd]-[a-z0-9_.-]{1,72}$")
MID_RE = re.compile(r"^\d{13}-[0-9a-f]{12}$")
# queue entry: "<msg-id>" (a message), "<msg-id>~d~<user>" / "<msg-id>~r~<user>"
# (delivered/read flag events for a message the queue's owner sent),
# "<msg-id>~x~server" (routing failed; the owner's message bounced),
# "<msg-id>~a~<user>" (reaction changed), or "<msg-id>~u~<user>" (message
# edited/deleted) — the a/u events carry no payload; clients refetch state
ENTRY_RE = re.compile(r"^(\d{13}-[0-9a-f]{12})(?:~([drxau])~([a-z0-9_.-]{1,32}))?$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
FID_RE = re.compile(r"^[0-9a-f]{32}$")

MAX_JSON = 64 * 1024
MAX_TEXT = 8192
MAX_FILE = 50 * 1024 * 1024
MAX_ATTACHMENTS = 8
MAX_STAGED = 16
MAX_WAIT = 30
MAX_GROUP_MEMBERS = 64
SESSION_IDLE_DAYS = 30
PBKDF2_ITERS = 600_000
# Abuse limits (an authenticated internal user may be malicious):
SEND_LIMIT = 60          # messages per SEND_WINDOW per user
SEND_WINDOW = 60
UPLOAD_LIMIT = 30        # uploads per UPLOAD_WINDOW per user
UPLOAD_WINDOW = 60
LOGIN_WINDOW = 300       # shared window for both login limiters (5 min)
LOGIN_USER_LIMIT = 10    # login attempts per LOGIN_WINDOW per (ip, username)
LOGIN_IP_LIMIT = 60      # login attempts per LOGIN_WINDOW per source IP
GROUP_OP_LIMIT = 20      # group create + membership changes per minute per user
GROUP_OP_WINDOW = 60
SEARCH_LIMIT = 30        # searches per minute per user (each scans the tree)
SEARCH_WINDOW = 60
SEARCH_SCAN_CAP = 4000   # max message dirs one search may examine
MAX_SEARCH_Q = 256
MAX_REACTION = 16        # max codepoints in a reaction (a grapheme, not text)
MAX_STARS = 1000         # starred-message markers per user
TYPING_TTL = 6.0         # seconds a typing signal stays live (client re-pings)
TYPING_CAP = 200         # max concurrent typing entries held in memory
PRESENCE_ONLINE_SECS = 60      # "online" = authenticated activity this recent
LASTSEEN_PERSIST_SECS = 300    # write users/<u>/lastseen at most this often
USER_STORAGE_QUOTA = 2 * 1024 * 1024 * 1024   # 2 GB of attachments per user
MAX_CONNECTIONS = 512    # global cap on concurrent request threads (bounds the
                         # thread/FD cost of a long-poll flood)
MAX_POLLS_PER_USER = 8   # concurrent parked long-polls one user may hold

# img-src/media-src blob: lets the web client render photos and play voice
# notes it fetched with its auth header (fetch -> Blob -> object URL); blob:
# URLs are same-origin-created media only, so this widens nothing an
# attacker controls.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "connect-src 'self'; img-src 'self' blob:; "
       "media-src 'self' blob:; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")

STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".apk": "application/vnd.android.package-archive",
}


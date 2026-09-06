# internal-chat-server

Minimal internal chat server: **stdlib only, no database, no dependencies**.
Messages are directories, flags are marker files, queues are folders of
symlinks — every state change is a file appearing or moving. The full design
(protocol, folder layout, security model) lives in the `internal-chat` repo's
`DESIGN.md`; clients are `internal-chat-android` and `internal-chat-web`.

## Layout

`chatserver.py` is the runnable entry point; the implementation is a small
package so each concern is in its own file:

```
chatserver.py          run this (or `python3 -m internalchat`)
internalchat/
├── config.py          limits, regexes, CSP, static-type table
├── errors.py          ApiError — the one raised type
├── util.py            stateless helpers (ids, filenames, dir walks, logging)
├── store.py           Store — the on-disk data model (folders/markers/symlinks)
├── notifier.py        per-user wakeups for long-polling
├── ratelimit.py       bounded sliding-window rate limiter
├── router.py          Router (routes + fans out messages) + Janitor (retention)
├── api.py             Api — all request-handling logic, HTTP-independent
├── server.py          the HTTP handler + build_server() wiring
├── roster.py          THE user file: identity, flags, password (last field)
└── cli.py             serve / adduser / passwd / roster / hashpw / export-passwd
```

Data flows one way: `server.py` parses a request → calls an `api.py` method →
which reads/writes through `store.py`; the `router.py` thread moves messages
between queues in the background. `chatserver.py` re-exports the package's
public names, so `import chatserver` keeps working.

## Quick start

```bash
# provision users (they must change the password on first login)
# each adduser appends ONE line to <data>/passwd — that's all provisioning
# is; the account's folders appear by themselves on first login/first message
python3 chatserver.py adduser alice --data /var/lib/internal-chat
python3 chatserver.py adduser bob   --data /var/lib/internal-chat

# lost password: admin reset (forces a change, kills all sessions)
python3 chatserver.py passwd alice  --data /var/lib/internal-chat

# the file IS the user database (password hash last field); manage it by
# hand if you prefer: chatserver.py hashpw prints a spec to paste
python3 chatserver.py roster --data /var/lib/internal-chat   # list users/state

# TLS cert (internal CA or self-signed; clients pin it)
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout server.pem -out server.pem -subj "/CN=chat.internal"

# run (also serves the web client if --static points at internal-chat-web)
python3 chatserver.py serve --data /var/lib/internal-chat \
    --cert server.pem --port 8443 --static ./static --retain-days 0
```

Without `--cert` the server speaks plain HTTP and prints a loud warning —
dev use only.

## Users

**One passwd-style file is the entire user database** — `<data>/passwd`, or
wherever `--roster` points. One line per user, the password hash as the last
field; the format, flags and login semantics are in `API.md` ("The user
file"). What an operator needs on one screen:

- `chatserver.py adduser <u>` appends a line — and creates the file, mode
  0600, if it is not there yet. That is the whole of provisioning; the
  account's folders appear on first contact.
- The file is **authoritative and hot-reloaded**: add a line and they can log
  in on the next request; remove one and they are cut off within ~1 s,
  including sessions already logged in. **No file means no users**, and every
  unreadable state (FIFO, directory, symlink loop, non-UTF-8, oversized,
  unknown flag on a line) denies *everyone* rather than guessing.
- Edit it **atomically** (write a temp file, `rename` over it). A
  truncate-in-place rewrite can be read half-written, and a line cut inside
  its flags field parses as an *enabled* entry — so an in-place edit can
  briefly grant the very account it is revoking.
- It is capped at **1 MiB** (~7,400 hashed lines). Past the cap the file is
  unreadable and nobody can log in, so `adduser`/`passwd` refuse to write the
  line that would cross it instead of bricking the deployment.
- Hardening option: put it somewhere the service can only read
  (`--roster /etc/internal-chat/passwd` with a root-owned *directory*) —
  logins keep working and self-service password changes answer 503. A
  read-only *file* in a writable directory hardens nothing: the atomic
  replace still succeeds.
- `chatserver.py roster` prints the file against the on-disk accounts. It is
  the first thing to run when nobody can log in.

## Tests

```bash
python3 -m unittest discover -s tests
```

The suite starts the real server on a loopback port and drives the full flow:
login → send → queue → dequeue (peek/confirm) → delivered + read flags →
groups → attachment upload/download, plus authorization, validation,
rate-limit, and upload-inertness checks.

`tests/load_test.py` is a separate concurrency load test (not picked up by
`discover`) — run it explicitly to verify the connection cap, parked-poll
cap, and no-cross-user-stall behavior under real load:

```bash
python3 tests/load_test.py
```

## The one-glance tour

```
data/
├── incoming/                       # accepted, awaiting routing (the queue)
├── users/<u>/queue/                # symlinks: new messages + flag events
│                                   #   (~d~ delivered, ~r~ read, ~x~ bounced,
│                                   #    ~a~ reaction, ~u~ edited/deleted)
├── users/<u>/{staged,nonces,sessions,starred}   # auto-provisioned on first contact
├── users/<u>/{storage_used,lastseen}  # quota cache; coarse last-activity stamp
├── groups/<gid>/members/<u>        # roster = marker files
├── groups/<gid>/<date>/<msg-id>/   # message.txt, from, attachments/,
│                                   # deliveredto/<u>, readby/<u>,
│                                   # reactions/<u> (=emoji), reply_to,
│                                   # edited, deleted  (all markers)
└── {tmp,archive,rejected}/
```

Typing indicators live in server memory only — they expire in seconds and are
never written to disk. Presence is memory-authoritative the same way, with one
exception worth knowing about for backups, retention and data-subject
requests: a coarse `users/<u>/lastseen` (epoch ms) is written at most every 5
minutes, so a restart still knows roughly when someone was last active. Search
(`GET /api/search?q=`) is a bounded, newest-first walk of the same folders.

A message's tick state is literally `ls`:

```
$ ls groups/d-alice-bob/2026-07-14/1784…-e6bb…/deliveredto readby
deliveredto: bob        # ✓✓ arrived
readby:      bob        # ✓✓ read (mtime = when)
```

## Deployment notes (see DESIGN.md §5/§9 for the full model)

- Run as a dedicated non-root user; mount the data dir `noexec,nosuid,nodev`.
- Suggested systemd hardening: `ProtectSystem=strict`, `NoNewPrivileges=yes`,
  `ReadWritePaths=<data dir>`, `PrivateTmp=yes`.
- Back up by snapshotting/rsyncing `data/` — it's only files.
- The login rate limits key on the **TCP peer**. If you terminate TLS at a
  reverse proxy or reach the server across a NAT gateway, every user shares
  one key and `LOGIN_IP_LIMIT` (60 / 5 min, `config.py`) becomes a
  company-wide cap on new sign-ins — raise it for that topology.

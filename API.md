# internal-chat — Client/Server API

Everything is JSON over HTTPS except file bytes. All endpoints except
`POST /api/login` and `GET /api/client/version` (§7) require
`Authorization: Bearer <token>`. Errors are `{"error": "<message>"}`. Status
codes: 400 (bad input, incl. duplicate file id), 401 (no/expired session),
403 (not a member / wrong password / not your message), 404 (not found /
pre-join), 409 (already claimed — a second thumb for one staged file), 413
(file too big or per-user storage quota exceeded, 2 GB), 429 (rate-limited:
login, password change, send/react/edit/delete, upload, group ops, search,
starred, typing), 503 (server at its connection cap, a transient send-claim
collision, or the user file cannot be written — retry), 507 (a write would
push the user file past its size cap, see §1), 500 (server bug). `confirm`
and `viewed` process at most 500 ids per call, so clients must chunk larger
batches (the server silently ignores the overflow otherwise); one poll
returns at most 500 queue entries, so a backlog drains over several polls.

The one rule that shapes everything: **a client learns things only through
its queue** (`GET /api/messages`). New messages, delivered ticks, read ticks,
message changes (reaction/edit/delete), send failures, and group lifecycle
all arrive there; every other GET is for (re)building state from the truth
(group folders), never for noticing change.

## 1. Session

| Endpoint | Body → Response |
|---|---|
| `POST /api/login` | `{"user","password"}` → `{"token","user","display","must_change"}` |
| `POST /api/logout` | → `{"ok":true}` (invalidates this token) |
| `POST /api/password` | `{"old","new"}` → `{"ok":true}` — kills every *other* session |

Login is rate-limited per IP+user (10 / 5 min → 429) **and** per source IP
(60 / 5 min). `POST /api/password` shares the per-user budget (10 / 5 min):
checking `old` is a full password verify, so it is guessable at speed by
anyone holding a token but not the password. If `must_change` is true, the
client must show the password-change screen before anything else.

> The "source IP" is the **TCP peer**. Terminate TLS at a reverse proxy, or
> reach the server across a NAT gateway, and every client collapses onto one
> limiter key — the 60/5min cap then applies to the whole company at once
> (a rollout or a Monday-morning login wave hits it). Raise `LOGIN_IP_LIMIT`
> in `config.py` for any shared-egress deployment. The server deliberately
> does **not** read `X-Forwarded-For`: an unauthenticated header would let
> every client pick its own limiter key and switch the defence off.

### The user file — identity, flags, password

**One passwd-style file is the entire user database**: `<data>/passwd`
(override with `--roster PATH`). One line per user, properties in order,
the password hash as the LAST field — pre-shadow `/etc/passwd`, honestly:

```
# user[:display[:flags[:password]]]
alice:Alice Anderson::pbkdf2-sha256$600000$<salt-hex>$<hash-hex>
bob:Bob Brown:must-change:pbkdf2-sha256$600000$...$...
carol:Carol Clark:disabled:pbkdf2-sha256$600000$...$...
```

Blank lines and `#` comments are ignored (a `#` only starts a comment at the
START of a line). `flags` is comma-separated: `disabled` blocks the account
while keeping the record; `must-change` forces a password change at next
login and is cleared automatically when the user changes it. A line with no
password parses but can never log in (stage a name before issuing a
credential). Hash specs are self-describing (`pbkdf2-sha256$iters$salt$hash`),
so iteration counts can be raised without breaking existing lines. Generate
one with `chatserver.py hashpw`, or add whole lines with
`chatserver.py adduser`.

**There is no other provisioning step.** An account's directory tree
(queue, sessions, staged uploads) is created automatically on *first
contact*: the first successful login, or the first message routed to the
user. Everyone listed appears in `GET /api/users` immediately — DM-able
from day zero, their queue materialising with the first message.

* The file is **authoritative and hot-reloaded**: add a line and the user
  can log in on the next request; remove it and they are cut off within
  ~1s, **including sessions already logged in** (a parked long-poll is cut
  too). Session markers are kept on denial, so restoring the line restores
  access without a fresh login. No file means **no users**.
* Every unreadable state — FIFO, directory, symlink loop, non-UTF-8,
  oversized, unknown flag on a line — **denies** rather than guesses. A
  user database that cannot be read is not evidence that anyone is allowed.
* A denied login answers with the same `401 bad credentials` as a wrong
  password, with **flat timing** across every failure shape (unknown name,
  password-less entry, malformed hash, wrong password, disabled — the
  disabled check runs *after* the hash). The work spent on a shape with no
  hash to check is calibrated to the iteration count *this file* uses, so
  raising `PBKDF2_ITERS` before everyone has changed their password does not
  make an unknown username measurably slower than a known one.
* The server **rewrites the file** when a user changes their password
  (`POST /api/password`): exactly one line changes, atomically, under
  `<path>.lock`; comments, other lines, and each line's own terminator
  survive byte-for-byte. A file the service cannot write is a valid
  hardening stance — logins keep working and self-service changes answer
  `503`. What enforces that stance is an unwritable **directory** (both the
  lock and the atomic replace create files in it); a read-only `passwd`
  inside a writable directory is simply replaced. Since the file holds
  hashes, keep it `0600` (the CLI creates it that way).
* Edit it **atomically** (write a temp file and `rename`). A
  truncate-in-place rewrite can be read half-written, and the outcome is not
  always the safe one: a read landing mid-line usually denies, but a line cut
  inside its `flags` field (`carol:Carol:`) parses as a valid, *not-disabled*
  entry — so an in-place edit can briefly **grant** the very account it is
  revoking.
* The file is capped at **1 MiB** (`MAX_ROSTER_BYTES` in `roster.py`) — about
  7,400 users at a typical hashed line. Past the cap it is unreadable, which
  denies **everyone**, so `adduser` and the admin `passwd` refuse with `507`
  rather than write the line that would cross it. Raise the constant (and
  restart) if you genuinely need more.

**What removal does and does not do.** It stops the account *connecting*
and hides it from the directory, so it cannot be DM'd by name or added to
groups. It deliberately does **not** rewrite history: existing groups still
list the member, and messages to those groups still queue for them — which
is what lets a restored line resume with nothing missed. If removal is
permanent, delete the account's directory too.

**Migrating** from the legacy per-account `auth.json` layout:
`chatserver.py export-passwd --data D >> D/passwd` — existing hashes are
preserved, so nobody's password changes.

## 2. The queue — receive loop

### `GET /api/messages?wait=25`

Long-polls up to `wait` seconds (max 30) if the queue is empty; returns
immediately otherwise. The response may also carry `"typing"` —
`{"<gid>": ["bob", …]}`, everyone currently typing in a group you are in,
excluding yourself. It is ephemeral in-memory state, not a queue entry:
nothing to confirm, and an ABSENT or empty `typing` clears every indicator. A
parked poll also returns early when the typing set changes, so indicators are
live without a second connection.

```json
{"queue": [
  {"entry":"1784…9f2a",          "kind":"msg",       "id":"1784…9f2a", "gid":"d-alice-bob", "at":1784070365969},
  {"entry":"1784…11aa~d~bob",    "kind":"delivered", "id":"1784…11aa", "gid":"d-alice-bob", "user":"bob", "at":…},
  {"entry":"1784…11aa~r~bob",    "kind":"read",      "id":"1784…11aa", "gid":"d-alice-bob", "user":"bob", "at":…},
  {"entry":"1784…77cc~x~server", "kind":"failed",    "id":"1784…77cc", "gid":null, "user":"server", "at":…},
  {"entry":"1784…3b7e~u~bob",    "kind":"updated",   "id":"1784…3b7e", "gid":"g-9c9fe43a", "user":"bob", "at":…}
]}
```

- `kind:"msg"` — a new message for me; fetch it with dequeue, then confirm.
- `kind:"delivered"/"read"` — `user` received/viewed message `id` that *I*
  sent; update ticks, then confirm (nothing to fetch — the entry is the data).
- `kind:"failed"` — message `id` I sent could not be routed; mark the bubble
  failed (retry = fresh send with a fresh nonce), then confirm.
- `kind:"updated"` — message `id` CHANGED: `user` reacted to it, edited it,
  or deleted it for everyone. The entry carries no payload — refetch with
  `GET /api/message/state/<gid>/<mid>`, re-render (text, reactions,
  `edited`, `deleted`, attachments), then confirm. `at` is when the latest
  change happened.

**Confirm every entry you are handed** — including kinds you do not
recognise, and entries whose fetch fails permanently (a 4xx: the message is
gone, or was never visible to you). An unconfirmed entry stays in the queue,
and `GET /api/messages` returns *immediately* while the queue is non-empty:
one entry a client never confirms turns its long-poll into a hot loop at full
request rate, and past 500 stuck entries newer messages stop appearing at all.

Confirming an `updated` entry that changed **again** since the poll handed it
to you is deliberately a no-op: the server keeps it queued so the newer change
still reaches you, and `{"confirmed": n}` comes back smaller than the number
of entries you sent. That is not an error — re-poll, refetch the state, and
confirm again. (Repeat changes by one actor share a single queue entry, so
retiring it early is how an edit or a "delete for everyone" would be lost.)

### `GET /api/message/dequeue/<msg-id>` — peek

Fetches a queued message. Repeatable, changes nothing — safe to call again
after a crash. 404 if the id isn't in *your* queue.

```json
{"id":"1784…9f2a", "gid":"d-alice-bob", "from":"alice", "at":1784070365969,
 "text":"see attached",
 "attachments":[{"n":1,"name":"clip.mp4","size":48211,"sha256":"…",
                 "video":"video/mp4",     // at most ONE of image/audio/video
                 "thumb":true,            // a preview exists: fetch ?thumb=1
                 "w":1280,"h":720}],      // the ORIGINAL's pixel size
 "recipients":["bob"],                    // members at SEND time (see below)
 "deliveredto":{}, "readby":{},
 "reactions":{"bob":"👍"},                 // omitted when there are none
 "edited":1784070999123,                  // only if edited (server stamp)
 "deleted":true,                          // tombstone: text "", no attachments
 "reply":{"id":"1784…11aa","from":"bob","text":"first 160 chars…"},
 "system":{"event":"join","user":"carol","by":"alice"}}   // only on announcements
```

Every field after `readby` is present only when it applies. A `reply` stub is
resolved at READ time, so it tracks its target: `{"id","deleted":true}` when
the quoted message was deleted, `{"id","gone":true}` when it was archived or
is invisible to you. This is the same body `GET /api/message/state` and
`history` return.

**`recipients`** is the set of members who had joined by the time this message
was sent (excluding the sender). Aggregate ticks over THIS set, not the live
roster — a member added later is not a recipient of older messages, so
`recipients` keeps their ✓✓/read state from regressing. `history` returns it
too. **`image`/`audio`/`video`** on an attachment is the server-verified mime
(see §3).

### `POST /api/message/dequeue/read/<entry>[,<entry>…]` — confirm

Removes the queue symlinks. For `msg` entries this also stamps the **arrival
flag** (`deliveredto/<me>`) and queues a `~d~` event to the sender. Confirm
only after the message is safely persisted locally — the fetch→persist→confirm
order is what makes delivery crash-proof. → `{"confirmed": n}`

### `POST /api/message/viewed` — the read flag

`{"gid":"d-alice-bob", "ids":["1784…9f2a", …]}` → `{"marked": n}`

Send **only** while the messages are actually on screen. Never called for
system announcements. Stamps `readby/<me>` and queues `~r~` events.

## 3. Sending

### `POST /api/messages`

```json
{"to":"bob",            // 1:1 — creates/uses the d-<a>-<b> group implicitly
 "gid":"g-9c9fe43a",    // …or an explicit group (exactly one of to/gid)
 "text":"hello",
 "nonce":"c0ffee-4b1d…",     // client-random, 8..64 chars — retry dedup key
 "files":["3f9c…"],          // optional staged file_ids, max 8
 "reply_to":"1784…11aa"}     // optional: quote a message you can see
→ {"id":"1784…9f2a", "gid":"d-alice-bob"}
```

200 = durable (✓). Same nonce retried → same `id` back, no duplicate.
Ticks then arrive via the queue: `~d~` from each recipient (✓✓ when all),
`~r~` (blue when all), or `~x~server` (failed).

### `POST /api/files` — stage an upload

Raw request body (no multipart). Headers: `Content-Length` (≤ 50 MB),
`X-File-Name: report.pdf` (metadata only — never becomes a path), and
optionally `X-Media-Kind: audio`.

→ `{"file_id":"3f9c…","name":"note.m4a","sha256":"…","audio":"audio/mp4"}`
— then reference in `files` on send. Staged uploads expire after 24 h; at most
16 pending. The response carries **at most one of `image` / `audio` /
`video`**, set only where the server recognised the bytes themselves — their
**magic bytes**, never the filename — as a safe-to-render container:

| field | verified types |
|---|---|
| `image` | `image/png`, `image/jpeg`, `image/gif`, `image/webp` |
| `audio` | `audio/mpeg`, `audio/ogg`, `audio/webm`, `audio/mp4` |
| `video` | `video/webm`, `video/mp4`, `video/quicktime`, `video/3gpp`, `video/3gpp2` |

One of those three is what unlocks inline rendering, and each is echoed on the
attachment in every message render. Anything else (PDF, SVG, HEIC/AVIF stills,
archives, unknown bytes) carries none of them and is a forced download.

`X-Media-Kind: audio` is a **presentation-only** hint from a client that
recorded the bytes. WebM and ISO-BMFF are containers that can hold either
audio or video, and telling them apart means parsing a track header, which the
server will not do — so they default to `video`, and this header narrows an
already-verified one to `audio` (a voice note). It can never make a non-media
file inline-eligible, change the container served, or produce a scriptable
type; worst case a user mislabels their own message.

### `GET /api/attachments/<gid>/<mid>/<n>[?inline=1]` — download / view

Membership-checked. By default `application/octet-stream` +
`Content-Disposition: attachment` + `nosniff` — a forced download.

`?inline=1` serves the bytes under their verified type with
`Content-Disposition: inline` **only if** the server flagged the attachment as
verified `image`, `audio` or `video` at upload (the table above); for anything
else the flag is ignored and the response stays a forced octet-stream
download. Every attachment response carries
`Cross-Origin-Resource-Policy: same-origin`; inline responses additionally
carry `Content-Security-Policy: default-src 'none'; sandbox`, so the bytes
can never act as a document or run script even if a client dereferenced them
directly. SVG is never inline-eligible (scriptable XML).

`?thumb=1` serves the sender-generated preview of an attachment (its stored,
magic-verified `image/*` type), `404` when the sender didn't provide one.
Same auth gates, same header set, its own `sha256` as the ETag.

### `POST /api/files/<file_id>/thumb` — attach a preview to a staged upload

Raw request body: a **≤ 64 KiB** image that must itself pass the same
magic-byte allowlist as any inline image (png/jpeg/gif/webp — SVG is
structurally impossible). Optional `X-Media-Dims: <w>x<h>` records the
*original's* pixel dimensions (bounded ints, ignored when malformed) so
clients can reserve layout before the bytes arrive. One thumb per staged
file (`409` on a second), `404` for an unknown/expired/consumed id.

The server never decodes anything: generation happens on the **sending
client** (canvas downscale on web, bounded bitmap on Android; video posters
from a locally-decoded frame). A thumb is presentation-only and carries the
same trust class as the client-supplied filename — size-capped, sniffed to
the safe raster allowlist, served under the sandbox CSP. Its bytes count
against the sender's quota, expire with the staged upload, and are credited
back when the message is deleted. On send it becomes `attachments/<n>.thumb`
and `render_msg` marks the attachment `"thumb":true` (plus `"w"`/`"h"` when
dims were recorded). A message sent while its thumb upload was still in
flight simply goes out thumbless — the race is benign by design.

Blob responses advertise `Accept-Ranges: bytes` and honor a single
`Range: bytes=a-b` / `bytes=a-` / `bytes=-N` with a byte-exact `206` +
`Content-Range` (multipart or malformed ranges are ignored and answered with
the full `200`, as RFC 9110 permits; an unsatisfiable range is `416` with
`Content-Range: bytes */<size>`). A routed blob never changes (deleting the
message 404s the path via its tombstone), so responses also carry
`ETag: "<sha256>"` and `Cache-Control: private, max-age=31536000, immutable`;
`If-None-Match` revalidates to a bodiless `304` and `If-Range` gates resumed
downloads (mismatch → full `200`). `HEAD` works on every GET endpoint and
returns the same headers — including the true `Content-Length` — with no
body.

## 4. Message actions

Everything here is authorized by the same visibility predicate as a read: a
member of the group, a message that exists, and not from before you joined —
otherwise `403`/`404`. All of them are rate-limited (`429`).

| Endpoint | Body → Response |
|---|---|
| `POST /api/message/react` | `{"gid","mid","emoji":"👍"}` → `{"ok":true,"reactions":{…}}`. An empty/omitted `emoji` REMOVES yours. One reaction per user per message; ≤ 16 codepoints, printable. `400` on a system or deleted message. |
| `POST /api/message/edit` | `{"gid","mid","text"}` → `{"ok":true,"edited":<ms>}`. Sender only (`403`), never a system or deleted message. |
| `POST /api/message/delete` | `{"gid","mid"}` → `{"ok":true}` — delete **for everyone**. Sender only. Idempotent. Blanks the text, drops reactions and attachment bytes (crediting the quota back) and leaves a tombstone, so replies and history still render a coherent stub. |
| `POST /api/message/star` | `{"gid","mid","on":true}` → `{"ok":true,"starred":true}` — private, no fan-out, max 1000 per user (`429`). |
| `GET /api/starred` | `{"messages":[…]}` newest first, up to 200 full renders. Self-healing: markers whose message is gone (or whose group you left) are pruned as they are met. |
| `GET /api/search?q=&gid=&limit=20` | `{"results":[{"id","gid","from","at","snippet"}],"truncated":bool}` — case-insensitive substring over message text and attachment names, newest first, across every group you are in (or one `gid`). `q` is 1..256 chars; `limit` ≤ 50. |
| `POST /api/typing` | `{"gid"}` → `{"ok":true}` — fire-and-forget; re-ping every ~3 s while the user types. Delivered as the `typing` field of other members' polls (§2), never as a queue entry. A `429` just skips one refresh. |

React, edit and delete each fan a `kind:"updated"` entry out to every member
who can see the message — **including the actor's other devices** — so that is
how a second device learns about them.

**`truncated`** on a search means the scan hit its work cap (4000 message
directories) before history was exhausted: there may be older matches. Say so
in the UI — reporting "no results" for a truncated scan is wrong.

## 5. Conversations & directory

| Endpoint | Response |
|---|---|
| `GET /api/groups` | `{"groups":[{"gid","name","members",` `"last":{"id","at","from","text","attachments","deleted"}}]}` — sidebar, sorted by activity |
| `GET /api/groups/<gid>` | `{"gid","name","members","joined_at"}` — resolve a gid learned from an announcement |
| `GET /api/groups/<gid>/messages?before=<mid>&limit=50` | `{"messages":[…]}` newest-first (`limit` ≤ 200), full renders; pre-join history excluded |
| `GET /api/message/state/<gid>/<mid>` | the **full message render** — the same body dequeue returns (§2), not just the flag maps: text, attachments, reactions, `edited`/`deleted`, `deliveredto`/`readby`. This is what a `kind:"updated"` entry tells you to refetch, and what the "message info" screen reads. |
| `GET /api/users` | `{"users":[{"user","display","online","last_seen"}]}` — new-chat picker. `online` is true when the account made an authenticated request in the last 60 s; `last_seen` is epoch ms and is absent for an account that has never been seen. |

## 6. Groups

| Endpoint | Body → Response |
|---|---|
| `POST /api/groups` | `{"name","members":["bob","carol"]}` → `{"gid","members"}` |
| `POST /api/groups/<gid>/members` | `{"add":[…],"remove":["me"]}` → `{"members"}` |

Both are **announced in-band**: a system message (`"system":{"event":
"created"/"join"/"leave"}`) routes to every member's queue — that is how the
other clients learn the group exists or changed. Members can add anyone and
remove only themselves. Leaving ends access and sweeps the leaver's queue.

## 7. Distribution

| Endpoint | Purpose |
|---|---|
| `GET /` (+ static files) | the web client, served same-origin |
| `GET /api/client/version` | `{version_code, sha256, url}` for APK self-update |
| `GET /download/app.apk` | the sideload APK (via the static dir) |

`GET /api/client/version` is the **one endpoint that needs no Bearer token**,
deliberately: it echoes `version.json` out of the static directory, which the
static route already serves unauthenticated at `/version.json`, describing an
APK that `/download/app.apk` hands to anyone. Requiring a session would hide
nothing and would break an updater that must check before it has one.

## 8. The client loop, end to end

```
login ─► GET /api/groups ─► GET …/messages per open chat   (rebuild truth)
   └► loop forever:
        GET /api/messages?wait=25
        for entry in queue:
          msg       → dequeue → persist locally → confirm
                      (if system.event names an unknown gid → GET /api/groups/<gid>)
          delivered → tick ✓✓ when all members present → confirm
          read      → tick blue when all members present → confirm
          failed    → mark bubble failed → confirm
          updated   → GET /api/message/state/<gid>/<mid> → re-render → confirm
          (anything else) → confirm anyway; never leave an entry queued
        (conversation on screen? → POST /api/message/viewed for visible ids)

send:  [POST /api/files]* → POST /api/messages   (outbox until 200, then ✓)
```

Reconnect/reinstall needs no special path: history + flag maps rebuild the
entire UI state; the queue only makes it live.

## Security posture — do NOT weaken

Invariants that hold everywhere above, written down so a future change can't
erode them one convenience at a time (util.py's magic-byte allowlists
cross-reference this section):

- **The server never decodes uploads.** No server-side thumbnailing,
  transcoding, EXIF parsing, or PDF rasterizing — classification is a
  constant-offset magic-byte comparison (util.py) and nothing more. Every
  media parser added server-side is remote attack surface reachable by any
  authenticated user's uploaded bytes.
- **The inline surface is exactly the three allowlists in §3** — four raster
  image types, four audio containers, five video containers — each recognised
  by constant-offset magic bytes. `X-Media-Kind` only chooses how an
  already-verified ambiguous container is presented; it can never add to this
  set. Every inline response still carries `nosniff` and the sandbox CSP.
- **SVG is never inline.** It is scriptable XML; whatever its filename or
  the `inline` flag says, it is served only as a forced
  `application/octet-stream` download. HEIC/AVIF are recognised as still
  images inside the ISO-BMFF family precisely so they are *not* mistaken for
  playable video — they are downloads too.
- **PDF is never inline, even sandboxed.** PDF viewers are their own
  script-capable document surface, and a sandbox CSP does not reliably reach
  plugin/viewer contexts — PDFs stay forced downloads.
- **Any new response status on the attachment path must carry the full
  header set**: `X-Content-Type-Options: nosniff`, the sandbox CSP whenever
  inline was granted, `Cross-Origin-Resource-Policy: same-origin`, and HSTS
  over TLS. `200`, `206`, `304`, and `416` all do today; a status added
  without them becomes the one response an attacker aims for.

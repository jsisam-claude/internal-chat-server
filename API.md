# internal-chat — Client/Server API

Everything is JSON over HTTPS except file bytes. All endpoints except
`POST /api/login` require `Authorization: Bearer <token>`. Errors are
`{"error": "<message>"}` with 400/401/403/404/413/429 status codes.

The one rule that shapes everything: **a client learns things only through
its queue** (`GET /api/messages`). New messages, delivered ticks, read ticks,
send failures, and group lifecycle all arrive there; every other GET is for
(re)building state from the truth (group folders), never for noticing change.

## 1. Session

| Endpoint | Body → Response |
|---|---|
| `POST /api/login` | `{"user","password"}` → `{"token","user","display","must_change"}` |
| `POST /api/logout` | → `{"ok":true}` (invalidates this token) |
| `POST /api/password` | `{"old","new"}` → `{"ok":true}` — kills every *other* session |

Login is rate-limited per IP+user (10 / 5 min → 429). If `must_change` is
true, the client must show the password-change screen before anything else.

## 2. The queue — receive loop

### `GET /api/messages?wait=25`

Long-polls up to `wait` seconds (max 30) if the queue is empty; returns
immediately otherwise.

```json
{"queue": [
  {"entry":"1784…9f2a",          "kind":"msg",       "id":"1784…9f2a", "gid":"d-alice-bob", "at":1784070365969},
  {"entry":"1784…11aa~d~bob",    "kind":"delivered", "id":"1784…11aa", "gid":"d-alice-bob", "user":"bob", "at":…},
  {"entry":"1784…11aa~r~bob",    "kind":"read",      "id":"1784…11aa", "gid":"d-alice-bob", "user":"bob", "at":…},
  {"entry":"1784…77cc~x~server", "kind":"failed",    "id":"1784…77cc", "gid":null, "user":"server", "at":…}
]}
```

- `kind:"msg"` — a new message for me; fetch it with dequeue, then confirm.
- `kind:"delivered"/"read"` — `user` received/viewed message `id` that *I*
  sent; update ticks, then confirm (nothing to fetch — the entry is the data).
- `kind:"failed"` — message `id` I sent could not be routed; mark the bubble
  failed (retry = fresh send with a fresh nonce), then confirm.

### `GET /api/message/dequeue/<msg-id>` — peek

Fetches a queued message. Repeatable, changes nothing — safe to call again
after a crash. 404 if the id isn't in *your* queue.

```json
{"id":"1784…9f2a", "gid":"d-alice-bob", "from":"alice", "at":1784070365969,
 "text":"see attached",
 "attachments":[{"n":1,"name":"report.pdf","size":48211,"sha256":"…"}],
 "deliveredto":{}, "readby":{},
 "system":{"event":"join","user":"carol","by":"alice"}}   // only on announcements
```

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
 "files":["3f9c…"]}          // optional staged file_ids, max 8
→ {"id":"1784…9f2a", "gid":"d-alice-bob"}
```

200 = durable (✓). Same nonce retried → same `id` back, no duplicate.
Ticks then arrive via the queue: `~d~` from each recipient (✓✓ when all),
`~r~` (blue when all), or `~x~server` (failed).

### `POST /api/files` — stage an upload

Raw request body (no multipart). Headers: `Content-Length` (≤ 50 MB),
`X-File-Name: report.pdf` (metadata only — never becomes a path).

→ `{"file_id":"3f9c…","name":"report.pdf","sha256":"…"}` — then reference in
`files` on send. Staged uploads expire after 24 h; at most 16 pending.

### `GET /api/attachments/<gid>/<mid>/<n>` — download

Membership-checked. Always `application/octet-stream` +
`Content-Disposition: attachment` + `nosniff` — attachments are downloads,
never renderable content.

## 4. Conversations & directory

| Endpoint | Response |
|---|---|
| `GET /api/groups` | `{"groups":[{"gid","name","members",` `"last":{"id","at","from","text","attachments"}}]}` — sidebar, sorted by activity |
| `GET /api/groups/<gid>` | `{"gid","name","members","joined_at"}` — resolve a gid learned from an announcement |
| `GET /api/groups/<gid>/messages?before=<mid>&limit=50` | `{"messages":[…]}` newest-first, full flag maps; pre-join history excluded |
| `GET /api/message/state/<gid>/<mid>` | `{"deliveredto":{"bob":ts,…},"readby":{…}}` — "message info" screen |
| `GET /api/users` | `{"users":[{"user","display"}]}` — new-chat picker |

## 5. Groups

| Endpoint | Body → Response |
|---|---|
| `POST /api/groups` | `{"name","members":["bob","carol"]}` → `{"gid","members"}` |
| `POST /api/groups/<gid>/members` | `{"add":[…],"remove":["me"]}` → `{"members"}` |

Both are **announced in-band**: a system message (`"system":{"event":
"created"/"join"/"leave"}`) routes to every member's queue — that is how the
other clients learn the group exists or changed. Members can add anyone and
remove only themselves. Leaving ends access and sweeps the leaver's queue.

## 6. Distribution

| Endpoint | Purpose |
|---|---|
| `GET /` (+ static files) | the web client, served same-origin |
| `GET /api/client/version` | `{version_code, sha256, url}` for APK self-update |
| `GET /download/app.apk` | the sideload APK (via the static dir) |

## 7. The client loop, end to end

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
        (conversation on screen? → POST /api/message/viewed for visible ids)

send:  [POST /api/files]* → POST /api/messages   (outbox until 200, then ✓)
```

Reconnect/reinstall needs no special path: history + flag maps rebuild the
entire UI state; the queue only makes it live.

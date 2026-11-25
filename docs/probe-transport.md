# Network Probe transport (Core 1.18.47)

Core 1.18.46 added one websocket for the Network Probe and one contract for the module that owns it. Core 1.18.47 adds the tunnel to it. The capability is `core.probe_transport`: 1.0.0 is the control channel (framework 1.18.46 or later) and 1.1.0 adds the tunnel (framework 1.18.47 or later). 1.1.0 is additive: nothing in 1.0.0 changed.

Core owns the connection and its security. The module `networkprobe` owns who a probe is, what the messages mean and the probe record. Core never reads `func`.

C1 of the probe channel plan is the control channel (1.0.0). C2 is the tunnel (1.1.0): the Engineer Console ticket, two data routes, the relay and their limits (see "The tunnel (contract 1.1.0)" below). No contract file for 1.18.47 exists in `docs/contracts` yet: the export runs on the dev server after this release is signed. The probe route shares no code, cache key, group, pool, audit action or credential with the endpoint agent route (AD-54). An agent token never reaches the probe authenticator, and a probe key never reaches Tactical.

## What you get

* A probe connects once and stays connected. Core checks who it is through `networkprobe`, keeps one live connection per probe and answers `ping`.
* `networkprobe` can ask a connected probe a question and wait for the answer, send it one event or reply, see who is online and close a probe's channel.
* An event from a probe reaches `networkprobe` through a Celery task. There is no `ack`: delivery is best effort. Bulk data and the outbox stay on HTTPS, and the probe's HTTPS polling never stops.

## The socket

`wss://<host>/ws/tfd/network-probe/`

The probe is a native client, so there is no Origin rule and no key in the URL. It sends one header:

| Header | Value |
|---|---|
| `Authorization` | `Probe <probe_id>.<key>` |

The probe id is 8 to 64 characters from `A-Z a-z 0-9 -`. The key is 16 to 128 characters from `A-Z a-z 0-9 _ -`. It is the same secret the probe already uses over HTTPS.

TLS is nginx's job. Core refuses a connection only where the proxy says it was plain text (`X-Forwarded-Proto` of `http` or `ws`, close 4403). Until `networkprobe` has registered, every connection closes 4503, and counts for nothing.

### Who may connect

1. There is exactly one `Authorization` header, and it starts with `Probe`. A `Token` header (an agent token) is refused with close 4401 and the reason `wrong_scheme`. A missing, duplicated, over-long or non-ASCII header is refused with `malformed_header`.
2. The owner's authenticator accepts the probe id and key.

Core accepts the socket first and then closes a refusal with its code, so the probe can read 4401 or 4429. The reason goes into the audit row, never the key and never its first characters.

### Failed attempts

The numbers are the ones AD-54 signed for the agent route. Nothing is widened.

* `FAILURES_PER_ADDRESS_PER_MINUTE` is 10 failed attempts a minute from one address (an IPv6 address counts by its /64). The 11th gets 4429 with no audit row.
* `FAILURES_PER_PROBE_PER_MINUTE` is 10 failed checks a minute naming one probe id. It is read only after a failed check, so someone who presents a real probe's id can never lock that probe out.
* A server-side fault (owner fault, pool full, timeout of 10 seconds) is not an identity answer. It closes 1013 and counts nothing.

## The owner: `register_owner`

`networkprobe` calls this from `AppConfig.ready()`. Core checks the caller from the call stack. The `module_id` argument must equal the verified id.

```python
register_owner(module_id, authenticator_path, event_task_path)
```

* `authenticator_path` is the dotted path of a plain function in the owner's own folder: `authenticate(probe_id, key)`. It runs on one of Core's own worker threads, never on the event loop.
  * It returns `{"probe_id": <the id presented>, "client_id": int or None, "site_id": int or None}` for an accepted probe.
  * It returns the string `probe_unknown`, `probe_disabled` or `probe_key_invalid` for a refusal.
  * Any other return, a fault or a timeout is a server fault: Core closes 1013 and counts nothing.
* `event_task_path` is the dotted path of a Celery task in the owner's own folder. Core calls it by its Celery name with `(probe_id, frame)` for every probe event.
* The same call again is accepted. Different paths are refused. A second module id is refused.

Core holds the key in memory only, for the 5-minute re-check.

## The other operations

All are sync. Call them from a Celery task or a request thread, not from async code. Every one verifies the caller. Any other module, Core itself and an unverifiable caller get `{"outcome": "denied"}`.

| Operation | Returns |
|---|---|
| `request(module_id, probe_id, frame, timeout=10)` | `{outcome: ok, timeout, offline, denied or invalid, reply}`. `frame.type` must be `request`. The timeout is clamped to 1 to 30 seconds and the call returns within timeout plus 1. `offline` is decided at once from presence. |
| `send(module_id, probe_id, frame)` | `{outcome: ok, offline, denied or invalid}`. `frame.type` must be `event` or `reply`. Fire and forget. The owner answers `probe.hello` with a reply that carries the hello's `id`. |
| `presence(module_id, probe_ids)` | `{outcome, presence: {probe_id: {connected, since, client_id, site_id}}}`. At most 2000 ids. Reads the cache only. |
| `disconnect(module_id, probe_id, reason)` | `{outcome: ok, offline, denied or invalid}`. `reason` is `disabled`, `revoked`, `key_rotated` or `module_disabled`. Closes that probe's socket with 4401. |

## Frames

A JSON text frame: `{"v": 1, "type", "id", "func", "payload"}`.

* `type` is `request`, `reply`, `event`, `ping` or `pong`. There is no `ack`.
* `id` and `func` are strings of at most 128 characters. `payload` is an object, required for `request`, `reply` and `event`.
* A frame is at most `MAX_FRAME_BYTES` (16 KiB). A probe may send at most `MAX_FRAMES_PER_SECOND` (20) a second.
* A binary frame or an invalid frame is dropped and counted. After `MAX_BAD_FRAMES` (20) the socket closes 4400.
* A `request` from the probe is dropped. A `reply` is routed only to the request that was delivered to this socket.

Core pings every `PING_SECONDS` (30). `MAX_UNANSWERED_PINGS` is 2: two unanswered pings close the socket 4408. Presence lives `PRESENCE_SECONDS` (90) and each ping renews it.

Core checks the identity again every `RECHECK_SECONDS` (300, plus up to `RECHECK_JITTER_SECONDS` of 30). A refusal closes 4401. A server fault keeps the socket until `RECHECK_GRACE_SECONDS` (300) past that deadline, then closes 1013.

## Close codes

| Code | Meaning |
|---|---|
| 4401 | Identity refused, the owner no longer accepts the probe at a re-check, or the owner called `disconnect`. Never a server fault. |
| 4403 | The proxy reports a plain-text connection. |
| 4400 | 20 invalid frames. |
| 4409 | Another connection for the same probe took over. |
| 4408 | Two pings went unanswered. |
| 4429 | Too many failed attempts from one address or naming one probe id in a minute, or more than 20 frames in a second. |
| 4503 | No owner has registered, or the consumer could not be loaded. Tactical itself still runs. |
| 1009 | A frame over 16 KiB. |
| 1013 | Retry later: a server fault, a busy server, or a re-check with no answer for 10 minutes. |

## The probe's reconnect rules

* Wait a random time that starts at 1 second and doubles up to 5 minutes.
* After 4409, wait 60 seconds.
* After 4401, stop the channel and keep the 5-minute HTTPS check.
* While the channel is up, the job poll may slow from 10 to 60 seconds. HTTPS stays for all bulk data and the outbox.

## Audit

Non-strict Core rows: module `core`, provenance `probe-transport`, object type `probe`, actor service `probe-transport`.

* `custom:probe-connect`
* `custom:probe-disconnect` (with the close code)
* `custom:probe-refused` (refusals only: the reason code, the address and the probe id when it is valid)

The client and site the owner reported are in the metadata. There are no per-event rows: the owner writes its own. A row never holds a key, a header or a payload.

## What Core does not do

Core does not interpret messages, keep a probe record, store events, check a person's scope or port rules, read tunnel stream ids, windows or payloads, or run module code. Agent and probe credentials never cross.

## Fleet size and pools

The pools are sized for up to 500 connected probes. A reconnect storm after a server restart is spread by the probe's jittered back-off (1 second doubling to 5 minutes), and the pools are sized for that. The tunnel routes use the same pools, with a limit of 50 concurrent tunnel sessions.

| Pool | Threads and backlog (`POOL_SPECS`) |
|---|---|
| `auth` | `(6, 256)` |
| `recheck` | `(2, 4096)` |
| `cache` | `(6, 2000)` |
| `audit` | `(3, 800)` |
| `handover` | `(2, 64)` |

`UNAUTHENTICATED_IN_FLIGHT` is 64: at most 64 connects, on the control route and on both tunnel routes together, may be between their first byte and their identity answer. A connect over it is answered 1013 at once and counted nowhere, so a flood spread over many addresses cannot make real probes queue behind it. A frame that is not valid JSON (including 15000 nested `[`, which raises `RecursionError`) counts as one bad frame.

## The tunnel (contract 1.1.0)

`core.probe_transport` 1.1.0 needs framework 1.18.47 or later. It lets an engineer reach a device behind a Network Probe through a desktop tool, the Engineer Console, with Core relaying the traffic. Core checks the engineer's account and permission and relays frames. It never reads, logs, audits or stores what the frames carry. `networkprobe` decides which device and port an engineer may reach; Core does not.

Four operations, for `networkprobe` only (Core verifies the caller; `module_id` must equal it). All are sync.

| Operation | Returns |
|---|---|
| `issue_tunnel_ticket(request, module_id, spec)` | `{outcome: ok, ticket, launch_url, expires_in: 60, session_id}` or `{outcome: denied, invalid, rate_limited, limit_reached, probe_offline, session_exists or unavailable, code, message}`. `request` is the engineer's signed-in Tec-Tac request. |
| `end_tunnel(module_id, session_id, ended_by)` | `{outcome: ok, invalid, denied or unavailable, already_ended}`. `ended_by` is `engineer`, `admin` or `core`. |
| `end_tunnels_for_probe(module_id, probe_id, reason)` | `{outcome, ended: [session ids]}`. `reason` is `ended_by_core`, `probe_offline`, `server_restart` or a 1.0.0 disconnect reason. |
| `tunnel_status(module_id, session_ids=None, probe_id=None)` | `{outcome, sessions: {id: {state, probe_id, started, last_data, console_connected, probe_connected, bytes_up, bytes_down, reason, ended_by}}}`. Up to 200 ids, cache only. `state` is `pending`, `open`, `ended` or `unknown`. |

### The ticket

`spec` is `{session_id, probe_id, permission, target_label, idle_s, cap_s}`:

* `session_id` is a uuid4 string. One ticket per session and no resume: a second ticket for the same id is refused (`session_exists`), even after the session ended.
* `permission` is a `networkprobe.` permission code the engineer must hold. Core checks it again at connect and every 5 minutes.
* `target_label` is audit text only (at most 128 characters).
* `idle_s` is 60 to 900 (default 900). `cap_s` is 60 to 14400 (default 14400).

Core checks, in this order: a signed-in request with a live Knox digest, the spec, the permission, the probe's presence (an offline probe is refused, so no slot is spent), the ticket rate, then the slots. The ticket is `secrets.token_urlsafe(32)`, 43 characters. Only its SHA-256 is stored, under its own cache prefix, for `TICKET_TTL_SECONDS` (60) and it works once. Every refusal writes one deny row (`custom:probe-tunnel-refused`) and never holds the ticket.

The launch link is `tectac-console://open?host=<server host>&ticket=<ticket>`. The host comes from the request, lower case, without port 443.

The owner's order: check the engineer's scope and the port rules, call `issue_tunnel_ticket`, then ask the probe for `tunnel.open` with `request()` or `send()`, and hand the engineer the link. Core never sends `tunnel.open` and never reads `func`. Call `end_tunnels_for_probe` when a probe is disabled or revoked. `disconnect()` does not end tunnels by itself.

### Limits

All counted in the shared Django cache (Redis). With no shared cache Core refuses to issue a ticket (`unavailable`).

| Limit | Value |
|---|---|
| `MAX_SESSIONS` | 50 live sessions |
| `MAX_SESSIONS_PER_PROBE` | 5 |
| `MAX_SESSIONS_PER_ENGINEER` | 3 |
| `TICKETS_PER_MINUTE` | 10 per engineer |
| `TICKET_TTL_SECONDS` | 60 |
| `IDLE_SECONDS_MAX` | 900 (15 minutes with no DATA frame) |
| `CAP_SECONDS_MAX` | 14400 (4 hours, hard cap) |
| `PAIR_WAIT_SECONDS` | 15 (the probe side must attach this soon after the Console) |
| `BUFFER_CAP_BYTES` | 1 MiB (Console frames held before the probe side attaches) |
| `RECHECK_SECONDS` | 300 (account, permission, module and probe re-check) |
| `FRAMES_PER_SECOND_MAX` | 2000 messages a second on one tunnel socket, then `protocol_error` (1.18.49) |
| `BACKSTOP_IDLE_GRACE_SECONDS` | 30 (the probe socket's own idle timer: the idle limit plus this, 1.18.49) |

A slot is held from the ticket (pending) until the session ends. An entry carries an expiry (75 seconds while pending, the hard cap plus 60 seconds once open), so a leaked slot heals.

### The two data routes

Both are binary only: a text frame is a protocol error (close 1002). No Origin rule (native clients). A plain-text connection is refused 4403. Core accepts first and then closes with the code and the reason name as the websocket close text.

| Route | Headers |
|---|---|
| `wss://<host>/ws/tfd/probe-tunnel/` (Console) | `Authorization: Ticket <43 characters>` |
| `wss://<host>/ws/tfd/network-probe/tunnel/` (probe) | `Authorization: Probe <probe_id>.<key>` and `X-Tunnel-Session: <uuid>` |

The Console side redeems its ticket once. Core re-checks the account at connect: the user is active and not blocked, the Knox token is live, the Tec-Tac session is not revoked, idle or past its lifetime (the engineer's idle and absolute sign-in limits apply to a live tunnel; the engineer's own DATA frames count as activity, output from the target does not, rule 1.8), the permission is held and the module is enabled. The probe side goes through the same identity check and failure counters as the control route, and its session must be a pending session of that probe. A `Ticket` or `Token` header on the probe route, and a `Probe` or `Token` header on the Console route, is refused 4401 (`wrong_scheme`) and never reaches an authenticator. One Console side and one probe side per session.

### Frames

One binary websocket message is one frame: `[type u8][stream u32 BE][payload]`. `OPEN` is 1, `DATA` 2, `ACK` 3 and `CLOSE` 4 (its payload is one reason byte). Stream id 0 is never used. A DATA payload is at most `MAX_DATA` (32 KiB). Each stream has a `STREAM_WINDOW` of 128 KiB, a session has at most `MAX_STREAMS` (8) streams and `SESSION_IN_FLIGHT` is 1 MiB per direction. Those are the two ends' rules (the end-to-end window already bounds the sender).

Core reads byte 0 and the length only. The type must be 1 to 4 and the length 5 up to 5 + 32768. Anything else, and any text frame, ends the session with close 1002. Core never parses stream ids, windows or payloads and never logs them.

Only DATA frames reset the tunnel's idle timer. The Console's consumer counts DATA payload bytes (the frame length minus 5): `bytes_up` is Console to probe and `bytes_down` is probe to Console. For the engineer's sign-in, only the engineer's own DATA frames (Console to probe) count as activity; output from the target does not refresh the sign-in idle timer (rule 1.8, AD-35). A session that only streams output therefore ends at the sign-in idle limit.

Pairing (1.18.48, symmetric from 1.18.49): a side is paired once it knows its peer's channel name. After a socket has accepted and joined the session's group it writes its ready marker (`probe_ready` or `console_ready`) with its own channel name, sends `tunnel.paired` (with its side and channel name) to the group, and then looks at the other side's marker. Either the marker or the message is seen, in both connect orders. The watcher keeps polling the peer's marker while unpaired, so a lost `tunnel.paired` cannot leave a side waiting. A channel name that does not match `^[A-Za-z0-9._!-]{1,200}$` is refused. Frames a side sends before then wait in Core's buffer (at most 1 MiB, then `probe_offline` for the Console side and `console_not_connected` for the probe side) and go out in order the moment the peer's channel is known, so the first frames after `OPEN` are never lost. The Console side also ends `probe_offline` after 15 seconds unpaired; the probe side ends `console_not_connected` when the Console is attached but its channel stays unknown for 15 seconds (or when no Console attaches within the 60 second ticket window). The 15 second check does not end a drain that is still running: the drain is bounded (1 MiB, 5 seconds a send) and ends the session itself if it fails. No wire change: Core still reads only the type byte and the length.

### The relay (1.18.49)

Frames travel with `channel_layer.send` to the peer's own channel name, not through the group. A group send to a channel that already holds its capacity (100 messages in Tactical's settings) is skipped without an error in channels_redis, so a frame would vanish. `send` raises `ChannelFull`, and a full channel, a send that takes over 5 seconds or any layer error ends the session `relay_overloaded`. The group carries only `tunnel.paired` and `tunnel.end`. A peer whose channel is full may miss `tunnel.end`; its watcher finds the end marker at its next tick (5 seconds), and the frames already in its channel are still delivered in order first.

Each direction numbers its frames in the layer message (`seq`, 0, 1, 2 ...; it is not on the wire, so the frames to the probe and the Console are byte for byte what the other side sent). A receiver that sees any other number ends the session `relay_overloaded`. That covers what `ChannelFull` cannot: a message the layer expired after 60 seconds in the queue of a stalled consumer, a Redis flush, a repeat or a reorder. A lost last frame is noticed at the next frame or at the idle limit.

Known residual: a frame sent to a peer that has already disconnected waits in Redis until the layer expires it (60 seconds). Payload bytes pass through Redis only while they are relayed (channels_redis keeps a message at most 60 seconds) and are never stored.

### Limits on a tunnel socket (1.18.49)

* Each socket counts its messages in a one-second window, in memory only (no cache or database call), before it looks at the frame. The `FRAMES_PER_SECOND_MAX` (2000) + 1 th message in a window ends the session `protocol_error` (close 1002, `ended_by` `core`). A 100 Mbit link carries about 400 full DATA frames a second plus ACKs.
* Message size: Core checks the length (5 up to 5 + 32 KiB) first thing in `receive()`, but only after the server has buffered the message. Tactical 1.6.1 runs uvicorn (a service still named `daphne.service`, started without `--ws-max-size`), so the hosting stack accepts up to its default of 16 MiB per message. A 1.5.2 server runs Daphne, where no limit was verified. This is a known gap in the hosting stack, not in Core; a unit-wide `--ws-max-size` is an installer change and is not part of this release.
* The 4403 refusal of a plain-text connection reads `X-Forwarded-Proto`. Tactical's nginx `location ~ ^/ws/` block sets `Host`, `X-Real-IP`, `X-Forwarded-For` and `X-Forwarded-Host` but not `X-Forwarded-Proto`, so on a stock server the refusal never fires. Nothing is exposed by that today: nginx serves `/ws/` on 443 only, and the probe and the Console both refuse `ws://` in their own code.
* Backstop timers on the probe socket: once paired, the probe socket ends the session `idle_timeout` when no DATA frame has moved in either direction for the idle limit plus `BACKSTOP_IDLE_GRACE_SECONDS`, and `hard_cap` when the session record's creation time plus the cap plus `SLOT_GRACE_SECONDS` (60) has passed. Both are later than the Console's own timers, so the Console fires first in normal running. They exist for a Console worker that died without writing an end. A session ended by a backstop is written by the probe socket: the end row and `tunnel.closed` carry the Console's last flushed counters, and a live Console's own final row is dropped as a duplicate.

### Close codes

| Code | Meaning on the tunnel routes |
|---|---|
| 4401 | Ticket unknown, used or expired; the account, permission or module check failed; the probe's identity was refused. |
| 4403 | Plain-text connection. |
| 4404 | No pending session of that name (unknown, ended, or another probe's). |
| 4409 | That side of the session is already attached. |
| 1002 | Protocol error: a text frame, a type byte outside 1 to 4, a bad length, or more than 2000 messages in a second. |
| 1009 | Not used by the tunnel routes (an oversize frame is 1002). |
| 1013 | Retry later: a busy or faulty server, or a relay that cannot keep up (`relay_overloaded`). |
| 1001 | The server is going away (`server_restart`). |
| 4503 | No owner has registered, no channel layer, or the tunnel consumer could not be loaded. Tactical itself still runs. |

### Close reasons

The close text and the `reason` of the end row and the `tunnel.closed` event come from one fixed list: `ended_by_engineer`, `ended_by_admin`, `ended_by_core`, `idle_timeout`, `hard_cap`, `target_out_of_scope`, `target_blocked_address`, `target_own_address`, `connect_failed`, `probe_offline`, `console_disconnected`, `console_not_connected`, `relay_overloaded`, `server_restart`. Core adds `protocol_error` for a frame that breaks the rules. Core only originates the reasons of its own control. The probe's `target_*` and `connect_failed` reasons pass through the owner.

* Console drops: `console_disconnected` (no resume). The probe's data socket drops: `probe_offline`. No probe side within 15 seconds of the Console: `probe_offline`. No Console within the 60 second ticket window: `console_not_connected`.
* A `send` that raises `ChannelFull`, takes over 5 seconds or fails, and a frame with the wrong sequence number, end the session `relay_overloaded`.
* The watcher (5 second tick) ends the session `idle_timeout` or `hard_cap`, and every 5 minutes (with up to 30 seconds of jitter) re-checks the account, the permission, the module and the probe's presence or data socket. A lost right, a disabled account, a revoked session or a disabled module ends it `ended_by_core`.
* When Core refuses a probe at its own 5-minute re-check, it ends that probe's tunnels itself, `ended_by_core`.

### End, events and audit

An end is written once: the first caller wins. Both data sockets close at once, the probe gets a `tunnel.close` event frame `{session_id, reason, ended_by}` on its control channel (so it drops its target connection even when the data socket is slow; an offline probe still has its data side closed), and one `tunnel.closed` event reaches the owner's event task as `(probe_id, frame)`:

```
func: tunnel.closed
payload: {session_id, reason, ended_by, bytes_up, bytes_down, source: "core"}
```

The Console consumer sends it at its close with the final counters. When the Console never attached, whoever ended the session sends it with zero counters. When the probe socket's backstop ended the session, the probe socket sends it with the last flushed counters. The probe's own `tunnel.closed` event arrives through the normal event path; `source` tells them apart.

Audit rows (non-strict, module `core`, provenance `probe-transport`, object type `probe`, no per-frame rows): `custom:probe-tunnel-ticket` (engineer, session id and permission; no target), `custom:probe-tunnel-connect` (with the side), `custom:probe-tunnel-end` (session id, probe id, engineer, reason, `ended_by`, duration, `bytes_up`, `bytes_down`) and `custom:probe-tunnel-refused` (reason code). Never a ticket, key, header, payload or target address.

The end row of a session with an attached Console is written by that Console's consumer at its close, with its final counters. A server process that dies without closing its sockets leaves no end row for that session; its slot heals at its expiry.

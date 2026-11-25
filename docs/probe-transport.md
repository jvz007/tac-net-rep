# Network Probe transport (Core 1.18.46)

Core 1.18.46 adds one websocket for the Network Probe and one contract for the module that owns it. The capability is `core.probe_transport` 1.0.0. It needs framework 1.18.46 or later.

Core owns the connection and its security. The module `networkprobe` owns who a probe is, what the messages mean and the probe record. Core never reads `func`.

This is C1 of the probe channel plan. The tunnel relay and the Engineer Console ticket (C2) are a later release and are not in this one. The probe route shares no code, cache key, group, pool, audit action or credential with the endpoint agent route (AD-54). An agent token never reaches the probe authenticator, and a probe key never reaches Tactical.

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

Core does not interpret messages, keep a probe record, store events, check a person's scope, relay tunnels or run module code. The tunnel relay and the Console ticket are a later release (C2). Agent and probe credentials never cross.

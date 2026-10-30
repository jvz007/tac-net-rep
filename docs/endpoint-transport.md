# Endpoint agent transport (Core 1.17.90, 1.17.92, 1.17.93)

Core 1.17.90 adds one websocket for the endpoint agent and one contract for the module that owns it. The capability is `core.endpoint_transport` 1.0.0. It needs framework 1.17.90 or later. Core 1.17.92 checks the identity before any per-agent decision, limits failed attempts to 10 a minute per address and 10 failed checks a minute per agent id, and adds close code 1013. Core 1.17.93 raises the process open-file limit, makes the 10 minute re-check close 1013 after 16 minutes without an answer, closes 1013 when the cache pool is full, and writes an audit row for the per-agent 4429 (see Failed attempts, Pools and bursts, Open files and Close codes). No operation, signature or return shape changed, so the capability stays at 1.0.0.

Core owns the connection and its security. The module `endpoint-comms` owns what the messages mean, the agent record, the events and the page. Core never reads `func`.

## What you get

* An agent connects once and stays connected. Core checks who it is, keeps one live connection per agent and answers `ping`.
* `endpoint-comms` can ask a connected agent a question and wait for the answer, send one event to many agents, and see who is online.
* An event from an agent reaches `endpoint-comms` through a Celery task. The agent gets an `ack` only after that hand-over worked.

## The socket

`wss://<host>/ws/tfd/endpoint-agent/`

The agent is a native client, so there is no Origin rule and no token in the URL. It sends two headers:

| Header | Value |
|---|---|
| `Authorization` | `Token <Tactical agent token>` |
| `X-Agent-Id` | the Tactical agent id |

TLS is nginx's job. Core refuses a connection only where the proxy says it was plain text (`X-Forwarded-Proto` of `http` or `ws`, close 4403). Where there is no such header, Core cannot tell.

### Who may connect

All of these must hold. Core reads Tactical's own tables only.

1. The token is a Tactical agent token (the token Tactical made when the agent was installed).
2. The token's user is linked to an agent. A dashboard user's token has no agent and is refused. A Knox session token is not in this table.
3. That agent's `agent_id` equals `X-Agent-Id` exactly.
4. The user is active.

The compare is constant time. Core checks again every 10 minutes. There is no enrolment and no revoke call: when Tactical deletes the agent or issues a new token, the next re-check closes the socket with 4401.

Core accepts the socket first and then closes a refusal with its code, so the agent can read 4401 or 4429. The reason goes into the audit row and the log, never the token and never its first characters.

### Failed attempts

Core checks the identity first. A valid token is never refused because someone else failed. Only after a failed check does Core look at how often an agent id failed.

| Limit | Value | Over it |
|---|---|---|
| Failed attempts from one address | 10 a minute (signed, AD-54). An IPv6 address counts by its /64. An IPv4 address counts exactly | 4429, no audit row |
| Failed checks naming one agent id | 10 a minute. Counted only for an id that is a valid agent id, read only after a failed check | 4429, with an audit row (reason `rate_limited_agent`, since 1.17.93) |
| Refusal audit rows | Every refusal is written, except the per-address 4429 close. No global budget | None |

* The address limit is the signed 10 failures a minute. A good connect never counts, so a site with a thousand agents behind one address is not refused for valid tokens, until ten attempts from that address fail within a minute. A higher NAT limit and a row budget are proposals in `reviews/questions/core.md`, off until Johan signs an amendment.
* The agent id limit is read after the check, never before it. Someone who presents a real agent's id can therefore not lock that agent out. The 11th failed check naming one id gets 4429 and one audit row. A valid token for that id still connects.
* Only failures count. The plaintext refusal counts as a failure. A server-side fault (1013) counts for nothing.

The address is nginx's `X-Real-IP` (nginx sets it from `$remote_addr`, so a client cannot choose it), then the address ASGI reports. The leftmost `X-Forwarded-For` is client controlled, because uvicorn trusts every proxy on a unix socket, so Core never uses it. If the cache is down (a real backend error), the counters read as not limited and Core logs it: a token has 160 bits, so a missing counter does not make guessing possible. A cache pool that is full is different (Core 1.17.93): the limiter could not be read or written, so Core closes 1013 with the reason `busy`, counts nothing, and never closes 4401 for a failure it could not count. A valid agent can get 1013 during a cache overload and retries with back-off.

### A fault is not a refusal (1013)

When Core cannot check the token because of its own fault (a database error, a timeout of 10 seconds, or the auth pool being full), it closes the socket with 1013 (retry later). It never closes 4401 for this and it counts nothing against the address or the agent. It writes at most one `custom:endpoint-refused` row with the reason `unavailable` or `busy` every 10 seconds. The agent should treat 1013 like a network error: wait, with jitter, then connect again.

The 10 minute re-check follows the same rule for as long as the fault is short. A fault at the re-check does not close 4401. Core tries again 30 seconds later. Since 1.17.93 a fault no longer keeps the socket open for good: when the last good identity check is older than 960 seconds (10 minutes, up to 60 seconds of jitter and 5 minutes of grace), Core closes 1013 with one audit row (reason `identity_stale`) and the agent reconnects through a fresh check. A database outage over 16 minutes therefore closes the sockets 1013, and the agents back off and reconnect when the database is back. Only a real identity answer closes 4401. The re-check runs on its own small pool, so a connect flood cannot starve it.

### Pools and bursts

The consumer never blocks the event loop and never uses the loop's default executor, which Tactical's own sockets share. Core owns five small pools, created on first use. Each counts what is in flight, and a full pool answers at once instead of queueing.

| Pool | Threads | Backlog cap | Used for | When full |
|---|---|---|---|---|
| auth | 6 | 256 | the identity check (each job closes its database connection) | the connect closes 1013 |
| recheck | 2 | 4096 | the 10 minute identity re-check (same job as auth) | the re-check is retried 30 seconds later |
| cache | 8 | 2000 | counters, presence | at connect the socket closes 1013 `busy`; elsewhere the call reads as a cache fault |
| audit | 2 | 1000 | audit rows (each job drops a stale database connection before and after the write, since 1.17.93) | the row is dropped, with a throttled log line |
| hand-over | 4 | 64 | the Celery hand-over of an event (no publish retry) | no ack; the agent resends |

The first ping goes out 60 to 70 seconds after connect and the re-check 600 to 660 seconds after, so a fleet that connected in one ramp does not hit the database together. The connect audit row is written in the background.

### Frames

Text frames only. A frame is a JSON object:

```json
{"v": 1, "type": "event", "id": "ev-1", "func": "reboot.choice", "payload": {}}
```

* `v` is 1. `type` is `request`, `reply`, `event`, `ack`, `ping` or `pong`.
* `id` and `func` are strings of at most 128 characters. `payload` is an object (required for `request`, `reply` and `event`).
* At most 64 KB a frame (close 1009) and 20 frames a second (close 4429). A frame that is not valid is dropped, and 20 of them close the socket with 4400.
* A `request` from the agent, an `ack` and a `reply` that matches no request delivered to this connection are dropped.

### One live connection, ping, presence

A new connection for an agent closes the older one with 4409, even across processes. Core pings every 60 seconds and closes with 4408 after two pings with no `pong`. The agent may ping too: Core answers `pong`.

Presence is the cache key `tec-tac:ea:presence:<agent_id>` holding `{connected, since}` for 150 seconds. It is set on connect and refreshed on every ping and pong. While the connection owns the key, the refresh only extends its life (it never rewrites the value, so a late refresh cannot overwrite a newer connection). When the key is gone (Redis restarted or evicted it), the refresh creates it again with that connection's own `since`, unless a newer connection took over. A different live owner is left alone. A disconnect removes the key only when that connection still owns it.

## Events

When an agent sends an `event`, Core, in a worker thread (never in the receive loop, bounded by 5 seconds):

1. calls the owner's registered Celery task by name with `(agent_id, frame)`;
2. writes one audit row (agent, func, frame id; never the payload);
3. sends `{"type": "ack", "id": <event id>}`.

With no owner registered, or when the hand-over fails or times out, Core sends no ack and logs a throttled line. The agent keeps the event and sends it again after it reconnects. Core does not ack and drop an event, because that could lose a person's choice.

## The contract, for `endpoint-comms` only

Every operation verifies the calling module from the call stack (`core.caller_identity`), not from the `module_id` argument. The caller must be the enabled, installed extension `endpoint-comms`. Core 1.17.94 also accepts the older id `nats-comms` until the dev server has moved to `endpoint-comms`. Only one of them owns the transport at a time. When both are installed and enabled, `endpoint-comms` owns it and `nats-comms` is refused at `register_owner` (`denied`). Before any owner is registered in a process, `nats-comms` is refused at every operation (not only at `register_owner`) while `endpoint-comms` is installed and enabled. Core 1.17.95 reads that fact from a short cache (3 seconds; a failed read is kept 1 second and counts as installed). Once an owner is registered in a process, only that module may call the operations. Any other caller, Core itself and a caller Core cannot verify get `{"outcome": "denied"}`. `module_id` stays in the signatures and must equal the verified id. Core checks nothing about people: `endpoint-comms` checks the person's scope before it calls.

```python
from tec_tac.capabilities import get_capability

transport = get_capability("core.endpoint_transport", version=">=1.0.0,<2.0.0")
```

| Operation | Returns |
|---|---|
| `register_owner(module_id, event_task_path)` | `{outcome: ok, denied or invalid}` |
| `request(module_id, agent_id, frame, timeout=10)` | `{outcome: ok, timeout, offline, denied or invalid, reply}` |
| `send_many(module_id, agent_ids, frame)` | `{outcome, queued, offline: [...]}` |
| `presence(module_id, agent_ids)` | `{outcome, presence: {agent_id: {connected, since}}}` |

* `register_owner`: call it from `AppConfig.ready()`. `event_task_path` is the dotted import path of a Celery task. The task's code must lie inside the owner's own folder. An identical re-registration is accepted (every process runs `ready()`). A different path is refused.
* `request`: `frame.type` must be `request`. `timeout` is clamped to 1 to 30 seconds and the call returns within `timeout` + 1 second. `offline` is decided at once from presence. The call is sync: use it from a Celery task or a request thread, not from async code. The reply goes only to the connection the request was delivered to, so agent A cannot answer agent B's request.
* `send_many`: `frame.type` must be `event`. At most 2000 agent ids (more is `invalid` and nothing is sent). Ids are de-duplicated. Offline agents are listed and not sent. Fire and forget.
* `presence`: at most 2000 ids. One cache read.

## Close codes

| Code | Meaning |
|---|---|
| 4401 | Identity refused, or the Tactical agent or token is gone at a re-check. Only ever an answer about identity |
| 1013 | Retry later (Core 1.17.92). A server-side fault or a busy server while checking the token. Since 1.17.93 also a full cache pool at connect and a re-check with no identity answer for 16 minutes. Not counted. Back off with jitter |
| 4403 | The proxy reports a plain-text connection |
| 4400 | Too many invalid frames |
| 4408 | Two pings went unanswered |
| 4409 | Another connection for the same agent took over |
| 4429 | More than 10 failed attempts from one address a minute (IPv6 by /64), more than 10 failed checks naming one agent id a minute, or more than 20 frames a second |
| 1009 | A frame over 64 KB |
| 4503 | The consumer could not be loaded. Tactical itself still runs |

## Load test

The 29 October 2026 test ran the load simulator against Core 1.17.90 and nats-comms 0.1.2 on the dev server, from one address.

| Stage 3 | Result |
|---|---|
| Agents, ping, ramp | 2 000 agents, 60 s ping, 20 ms ramp, one address |
| Opened (counting refusals) | 1968 of 2000 |
| Connect p95 | 10.6 s |
| Ping p95 | 6.6 s, 164 pings unanswered |
| Close 4401 | 42 |
| Close 4429 | 1129 |
| HTTP 502 | 32 (nginx's answer to a slow upstream) |
| uvicorn CPU peak | about 67% of one core |
| Memory | 222 to 240 MB |

Core 1.17.92 changed how Core behaves under that burst: the identity check comes first, a fault closes 1013 and is not counted, and the work runs on Core's own pools. The 29 October evidence for the failures that remained is in the next section. Core 1.17.93 was not load tested on this PC. The re-test runs on the dev server.

**Pass target:** 2 000 agents at the real 60 s ping, ramp 20 ms, from one address. All connect. No 4401 or 4429 for a valid token. Ping p95 under 2 s after the ramp. No 502s, or 502s only during the ramp with the agents' back-off recovering all.

## Open files and the 2 000 agent target

Every agent socket is one open file (a descriptor) in the uvicorn worker that holds it. The 29 October 2026 load test showed the limit was too low: the uvicorn process had a soft limit of 1024 and a hard limit of 524288. At about 968 sockets Core hit `[Errno 24]` (too many open files). Then psycopg could not resolve `localhost`, `authenticate_endpoint_agent` answered 1013 for 996 agents, and nginx returned 36 HTTP 502. nginx was not the cause: `worker_connections` was 4096 and the log held 0 "worker_connections are not enough" lines.

**What Core does (1.17.93).** Core raises the process soft limit to the smaller of the hard limit and 65536, once per process. It does this in each uvicorn worker, when Core starts (only where uvicorn, daphne or hypercorn is loaded, so Celery workers and `manage.py` commands are left alone) and again at the first endpoint socket. It never lowers a limit and never touches the hard limit. A failure is one warning line and start-up goes on. There is no systemd or nginx change (AD-54 E2).

**Rough budget.** One descriptor per agent socket, plus the database, Redis and broker connections, Core's pools' threads and the files the process has open. For 2 000 agents on one worker that is well under 4 096 descriptors, so the 65536 target leaves a wide margin.

**How to verify.** On the server:

```
cat /proc/$(pgrep -f uvicorn | head -1)/limits | grep -i 'open files'
```

The soft value should read 65536 (not 1024). The journal holds one info line per worker: "The open-file soft limit was raised from 1024 to 65536 (hard limit 524288)."

**If the hard limit is low.** A hard limit below about 4 096 cannot hold 2 000 agents with headroom. Raising a hard limit is a server change (systemd `LimitNOFILE`), so it goes to Johan (AD-54 E2) and Core does not do it.

## Audit

Non-strict Core rows (module `core`, provenance `endpoint-transport`, object type `agent`): `custom:endpoint-connect`, `custom:endpoint-disconnect`, `custom:endpoint-refused` (the agent id presented, a reason code and the address; written for every refusal except the per-address 4429 limit close), `custom:endpoint-event`. They are records of what happened on the channel, not a gate: a failed audit write is logged and the event still goes to the owner. A payload is never audited. A token is never audited.

## Test-only load seed

`python manage.py tectac_endpoint_agent_loadseed --count N --out <file>` makes N throwaway agent accounts (prefix `loadtest-ea-`) in a staging database. `--cleanup` removes exactly those. It does nothing unless the Django setting `TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST` is `True`. Tokens go only to the `--out` file (mode 0600). Never run it on production.

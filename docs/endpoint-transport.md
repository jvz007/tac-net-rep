# Endpoint agent transport (Core 1.17.90)

Core 1.17.90 adds one websocket for the endpoint agent and one contract for the module that owns it. The capability is `core.endpoint_transport` 1.0.0. It needs framework 1.17.90 or later.

Core owns the connection and its security. The module `nats-comms` owns what the messages mean, the agent record, the events and the page. Core never reads `func`.

## What you get

* An agent connects once and stays connected. Core checks who it is, keeps one live connection per agent and answers `ping`.
* `nats-comms` can ask a connected agent a question and wait for the answer, send one event to many agents, and see who is online.
* An event from an agent reaches `nats-comms` through a Celery task. The agent gets an `ack` only after that hand-over worked.

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

Ten failed attempts from one address in a minute are allowed. The eleventh is closed with 4429. Only failures count. A good connect never does, so a fleet of agents behind one NAT cannot lock itself out. The plaintext refusal counts as a failure, and an address over the limit gets no audit row.

The address is nginx's `X-Real-IP` (nginx sets it from `$remote_addr`, so a client cannot choose it), then the address ASGI reports. The leftmost `X-Forwarded-For` is client controlled, because uvicorn trusts every proxy on a unix socket, so Core never uses it. If the cache is down, the counter reads as not limited and Core logs it: a token has 160 bits, so a missing counter does not make guessing possible.

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

Presence is the cache key `tec-tac:ea:presence:<agent_id>` holding `{connected, since}` for 150 seconds. It is refreshed on connect and on every ping. A disconnect removes it only when that connection still owns it.

## Events

When an agent sends an `event`, Core, in a worker thread (never in the receive loop, bounded by 5 seconds):

1. calls the owner's registered Celery task by name with `(agent_id, frame)`;
2. writes one audit row (agent, func, frame id; never the payload);
3. sends `{"type": "ack", "id": <event id>}`.

With no owner registered, or when the hand-over fails or times out, Core sends no ack and logs a throttled line. The agent keeps the event and sends it again after it reconnects. Core does not ack and drop an event, because that could lose a person's choice.

## The contract, for `nats-comms` only

Every operation verifies the calling module from the call stack (`core.caller_identity`), not from the `module_id` argument. The caller must be the enabled, installed extension `nats-comms`. Any other caller, Core itself and a caller Core cannot verify get `{"outcome": "denied"}`. `module_id` stays in the signatures and must equal the verified id. Core checks nothing about people: `nats-comms` checks the person's scope before it calls.

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

* `register_owner`: call it from `AppConfig.ready()`. `event_task_path` is the dotted import path of a Celery task. The task's code must lie inside the `nats-comms` folder. An identical re-registration is accepted (every process runs `ready()`). A different path is refused.
* `request`: `frame.type` must be `request`. `timeout` is clamped to 1 to 30 seconds and the call returns within `timeout` + 1 second. `offline` is decided at once from presence. The call is sync: use it from a Celery task or a request thread, not from async code. The reply goes only to the connection the request was delivered to, so agent A cannot answer agent B's request.
* `send_many`: `frame.type` must be `event`. At most 2000 agent ids (more is `invalid` and nothing is sent). Ids are de-duplicated. Offline agents are listed and not sent. Fire and forget.
* `presence`: at most 2000 ids. One cache read.

## Close codes

| Code | Meaning |
|---|---|
| 4401 | Identity refused, or the Tactical agent or token is gone at a re-check |
| 4403 | The proxy reports a plain-text connection |
| 4400 | Too many invalid frames |
| 4408 | Two pings went unanswered |
| 4409 | Another connection for the same agent took over |
| 4429 | Too many failed attempts from one address, or too many frames |
| 1009 | A frame over 64 KB |
| 4503 | The consumer could not be loaded. Tactical itself still runs |

## Audit

Non-strict Core rows (module `core`, provenance `endpoint-transport`, object type `agent`): `custom:endpoint-connect`, `custom:endpoint-disconnect`, `custom:endpoint-refused` (the agent id presented, a reason code and the address), `custom:endpoint-event`. They are records of what happened on the channel, not a gate: a failed audit write is logged and the event still goes to the owner. A payload is never audited. A token is never audited.

## Test-only load seed

`python manage.py tectac_endpoint_agent_loadseed --count N --out <file>` makes N throwaway agent accounts (prefix `loadtest-ea-`) in a staging database. `--cleanup` removes exactly those. It does nothing unless the Django setting `TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST` is `True`. Tokens go only to the `--out` file (mode 0600). Never run it on production.

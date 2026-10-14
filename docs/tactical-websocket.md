# Tactical WebSocket ticket (Core 1.17.31, Origin rule 1.17.32, stale connections 1.17.33)

Core 1.17.31 lets a module open Tactical's terminal socket for the person who is signed in, without the module ever holding a
Tactical token. It is capability `core.tactical_websocket` 1.0.0. It is additive: nothing that already existed changed.

## Why a ticket

Tactical's own terminal socket (`/ws/agent/<id>/terminal/<session>/`) reads the person's Knox token from the URL. Core stores Knox
tokens only as hashes (AD-6, condition 2), so Core cannot open a socket to Tactical as the person, and it must not mint extra tokens
(that would blur session revocation). So the browser asks Core for a short-lived ticket over the authenticated API, and then opens
Core's own socket. Core checks the caller, then runs Tactical's own terminal consumer in-process as that person.

## Who may use it

Only the owner of the socket kind, which Core reads from its route owner table (`tec_tac/tactical_operations.py`, the same table
that decides who may declare a Tactical operation):

| Kind | Owner | Tactical route it follows | Flag | Scope |
| --- | --- | --- | --- | --- |
| `agent-terminal` | `remote-background` in 1.17.31 | `agents/{agent_id}/terminal-defaults/` | `can_use_terminal` | the agent must be inside the caller's client and site limits |

The socket has the same owner as `terminal-defaults`, and the two cannot drift: both come from the one table. An honoured AD-20
replacement of that module follows the same rule. A premium or server module that is not a replacement is refused, and so is a
disabled, legacy or unknown module, and Core itself. Only the kind `agent-terminal` exists in 1.17.31. The server web terminal
(`ws/trmmcli/`, a shell on the server itself) is not a kind; it waits for Johan's decision.

## 1. Ask for a ticket

`POST /api/tfd/tactical-websocket/<module_id>/<kind>/tickets/` with the JSON object `{"agent_id": "<canonical agent id>"}`. Nothing else
may be in the body (any other key, or a missing `agent_id`, is 400 `invalid_ticket_request`).

| Status | Code | Meaning |
| --- | --- | --- |
| 201 | | `{ticket, path, session_id, expires_in, kind}`. `expires_in` is 30. `path` is `/ws/tfd/agent-terminal/<ticket>/`. `session_id` is a new uuid for this terminal session. |
| 400 | `invalid_agent_id` | the agent id is not well formed |
| 401 | `authenticated_request_required` | no signed-in Tec-Tac session |
| 401 | `tactical_session_required` | the session is not linked to a Tactical token; sign in again |
| 403 | `websocket_owner_required` | the module does not own the kind |
| 403 | `tactical_permission_denied` | the caller lacks `can_use_terminal` (the detail names it) |
| 404 | `websocket_kind_not_found` | no socket of that kind |
| 404 | `object_not_found` | the agent is outside the caller's limits or does not exist (the same text for both) |
| 503 | `websocket_unavailable` | the ticket store did not hold the ticket; nothing was issued (fail closed) |

Every 403 and every scope refusal writes one Core deny row (see "Audit"). A successful request writes no audit row.

Limits: 30 requests a minute and 500 a day for each signed-in user and address (`TacticalWebSocketTicketMinThrottle`, `...DayThrottle`).

## 2. Open the socket

`wss://<host>/ws/tfd/agent-terminal/<ticket>/`, with no token in the URL other than the ticket and no `Authorization` header.

The ticket is 32 random bytes, URL-safe (43 characters). It is single use and lives 30 seconds. It is kept only as a hash in Django's
cache (Tactical's Redis, `default`, shared by the rmm and daphne processes). The key is `tec-tac:wsticket:v1:` followed by the SHA-256 of
the ticket, so the raw ticket is never stored. A ticket is taken once: a second socket with the same ticket is refused.

Core checks, in this order:

1. The ticket exists, is not used or expired, and its shape is right. Otherwise close **4401**.
2. The sign-in behind the ticket still holds: the user exists, is active and not blocked from the dashboard; the Tec-Tac session row is
   not revoked, belongs to that user and is inside its absolute lifetime; the Knox token behind it is present and not expired. Otherwise
   close **4401**.
3. The `Origin` header, if sent, names the same host as the request, or one of the frontend origins in Tactical's
   `CORS_ORIGIN_WHITELIST` (Core 1.17.32). No `Origin` is allowed, because the ticket already blocks use from another site. A `null`,
   empty or malformed `Origin` is refused. Otherwise close **4003**. See "Split-host layout and nginx" below.
4. The user still holds `can_use_terminal` and the agent is still in scope. Otherwise close **4003**.
5. Tactical's own terminal consumer runs its own checks (the permission, the agent and the shell) unchanged. If Tactical refuses, Core
   accepts nothing and starts no watcher.

Agent and session come from the ticket only, never from the URL. If Tactical's terminal consumer cannot be loaded (Tactical moved
it), the socket closes **4503** and Tactical itself keeps running.

Messages are Tactical's own, unchanged (AD-25): the client sends `start` (`shell`, `run_as_user`), `input`, `resize` and `kill`, and
receives `trmmcli.output`, `terminal_error` and `terminal_info`. A `terminal_error` with code `audit_unavailable` means Core could not
write the audit row, so the shell did not start.

A watcher checks the sign-in every 30 seconds and closes the socket with **4401** when it ends (the session is revoked or past its
absolute lifetime, the Knox token is gone, or the user is disabled). Idle time is not checked, because typing in a terminal does not touch
the REST API. Tactical's own disconnect then sends its kill, and the watcher is cancelled.

## Split-host layout and nginx (Core 1.17.32)

A standard Tactical install puts the API on one host (`rmmdomain`) and the web UI on another (`frontenddomain`). Tec-Tac's UI is served
from `/tec-tac/` on the frontend host and opens `wss://` on the API host, so the browser sends `Origin` = the frontend host while nginx
sends `Host` = the API host. Core 1.17.31 accepted only the same host, so every terminal closed 4003 on that layout. Core 1.17.32 also
accepts the frontend origin named in Tactical's `CORS_ORIGIN_WHITELIST`. The conditions:

- nginx sends `/ws/` to daphne with the `Upgrade` and `Connection` headers, and does not rewrite `Origin`. The `location ~ ^/ws/`
  block in the API server block is expected to do this (`proxy_pass http://unix:/rmm/daphne.sock`, `proxy_set_header Host $host`).
- `Host` is the API host (`ALLOWED_HOSTS`).
- The frontend origin, with its scheme and host, is in `CORS_ORIGIN_WHITELIST`. Core reads only that setting and `CORS_ALLOWED_ORIGINS`,
  from server settings, never from a request.
- Tec-Tac does not accept a frontend origin that is not in that list.

Only exact http(s) origins count: a path, a query, `*`, `null`, a regular expression or an allow-all setting is ignored. The default port
is the same as no port (`https://rmm.example:443` equals `https://rmm.example`). The scheme must match too. A setting that cannot be
read gives same-host only. The ticket, the session re-check, the scope check, the audit row and the watcher are unchanged.

This is the code side only. The real proxy and layout still have to be confirmed on the dev server (Johan): see the dev-server steps in
`reviews/questions/core.md` (note of 14 October 2026).

## Stale database connections (Core 1.17.33)

Django can hold a database connection that the server has already dropped (a Postgres or pgbouncer restart, an idle kill) while
`CONN_MAX_AGE` is above 0. Django has not flagged it yet, so the first use fails with `OperationalError` or `InterfaceError` ("the
connection is closed"). Before 1.17.33 that one failure refused a good ticket, or closed a terminal that had run for hours.

What Core does now, in `tactical_websocket.run_with_fresh_connection`:

- A **read** that fails with `OperationalError` or `InterfaceError` closes this thread's connections and runs again, once. The whole
  check runs again, not one query. It applies to the connect re-check (the user, the session row, the Knox token, the Tactical
  permission and the agent scope) and to every 30 second watcher tick. A second failure keeps the old result: close **4401**. Core logs
  one warning line on a reconnect (no user data, no ticket) and the "Could not re-check" line only when the second attempt fails.
- Any other error is not retried.
- Inside a database transaction nothing is closed or retried, because a close would drop the transaction.
- The **audit write is never retried**: a retry could write a row twice, and the strict rule stays "no row, no start". Core only checks
  first that this thread's connection still answers, and closes it if not (`ensure_usable_connections`, skipped inside a transaction).
  A write that still fails sends `audit_unavailable` and starts nothing.

Nothing a module sees changes: the close codes, the messages, the ticket, the audit row and the capability version (`core.tactical_websocket`
1.0.0) are the same.

The dev-server probe used to fail for a different reason, which was its own design: it ran inside `transaction.atomic()` and rolled back,
and channels' `database_sync_to_async` calls `close_old_connections()` around each call, which closes the shared connection inside a
transaction. The 1.17.33 probe commits `wsprobe-` rows and deletes the user, role, token and session rows in a `finally` block. It keeps its audit rows (CQ103).

## Audit

One row per session start, written by Core before Tactical starts the shell, and strict: if the row cannot be written, the shell does not
start.

| Field | Value |
| --- | --- |
| `action` | `custom:terminal-start` |
| `object_type` | `agent` |
| `object_id` | the agent id |
| `username` | the signed-in user |
| `module_id` (debug info) | the owner of the kind |
| `after_value` | `{shell, run_as_user, session_id}`. `shell` is the requested text with control characters removed, at most 260 characters, or `default` |
| `operation_context` | `server_provenance` = `tactical-websocket`, `websocket` = `agent-terminal` |
| `correlation_id` | the ticket's correlation id, which is the request's |

The row never carries typed input, output, the ticket or a token. Core logs no frame.

A refusal writes one deny row: action `deny`, the same object id, `operation_context.core_refusal` true, the same provenance, and metadata
`{reason, status, kind}`. A refusal for a missing owner is written against the terminal's owner. If no enabled core owner exists, the row
cannot be attributed and is not written (logged).

Only session start is audited. Ending a session (exit code, duration) is not audited in 1.17.31 (Johan's decision).

## Not in 1.17.31

- The server web terminal (`ws/trmmcli/`, globalsettings). It waits for Johan's decision.
- The command stream socket (`ws/agent/<id>/cmd/`). Remote Background already runs Send command through declared operations. A later kind could add it.
- A row when a session ends.
- Binding the ticket to the client's address. A 30 second single-use ticket is enough, and address binding breaks behind some proxies.
- The UI helper. It is a request in `reviews/requests/ui.md` (From Core 1.17.31).

## For the nginx side

The ticket is in the path, so nginx logs it. It is dead after use, unlike Tactical's own token in the URL. The existing `location ~ ^/ws/`
should already send `/ws/tfd/...` to daphne. This is to be confirmed on the dev server.

## Checks

- `tests/tactical-websocket-ticket-1.17.31.py`: mint, owner, flag and scope refusals with their deny rows, the store, one use, expiry, the
  sign-in re-check, the route-owner pin, `register_tactical_operation` for the terminal defaults route, the capability and the contract rows.
- `tests/tactical-websocket-consumer-1.17.31.py`: the relayed socket against a stub of Tactical's consumer.
- `tests/tactical-websocket-origin-1.17.32.py`: the Origin rule, split host through `connect()`, the default-port, scheme, path and regex
  forms, the empty and failing settings, and the refusals.
- `tests/tactical-websocket-route-1.17.31.py`: the route is appended once and skipped in DEMO; a missing consumer closes 4503.
- `tests/tactical-websocket-stale-connection-1.17.33.py`: one retry on `OperationalError` or `InterfaceError`, fail closed on the second,
  connect and watcher ticks with a stale connection, no retry for other errors or inside a transaction, and the audit write never retried.
- `tests/tactical-websocket-probe-1.17.33.py`: a PC-side check of the probe below with no Django: `pick_agent` against a fake Agent whose
  `status` is a property (never a database filter), and the shape of the rewrite.
- `tests/tactical-websocket-runtime-1.17.33.py`: a dev-server check through `manage.py shell`. It drives `tacticalrmm.asgi.application` with
  asgiref's `ApplicationCommunicator` (not channels' `WebsocketCommunicator`, which needs daphne, and Tactical's venv has no daphne). It
  sweeps old `wsprobe-` rows, commits a probe user, role, Knox token and session row, checks the accept, one start row, the 4401 reuse, the
  foreign Origin 4003, the split-host Origin, the malformed ticket 4401 and a socket after this thread's database connection was closed,
  then deletes its user, role, token and session rows (only rows named `wsprobe-`) and checks none are left. Its `custom:terminal-start` audit row is kept. Run it with
  `sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/tactical-websocket-runtime-1.17.33.py'`,
  and put `TECTAC_WS_PROBE_AGENT=<agent_id>` before `../env/bin/python` to choose the agent. It was written on the development PC and did not
  run there.
- `tests/runtime-script-imports-1.17.32.py`: a PC-side guard that every `manage.py shell` script imports only what Tactical's venv has.

Django, channels, Redis and Tactical are not installed on the development PC. The stub tests cover Core's own logic. The real
`TerminalStreamConsumer` subclass, the Redis single-use delete, the ASGI route, the watcher and the real proxy only run on the dev server.

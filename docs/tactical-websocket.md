# Tactical WebSocket ticket (Core 1.17.31, Origin rule 1.17.32, stale connections 1.17.33, server terminal and terminal activity 1.17.34)

Core 1.17.31 lets a module open Tactical's terminal socket for the person who is signed in, without the module ever holding a
Tactical token. It is capability `core.tactical_websocket`: 1.0.0 in 1.17.31, and 1.1.0 since Core 1.17.34 (AD-35), which adds the kind
`server-terminal` and makes terminal input count as session activity. Both changes are additive: nothing that already existed changed.

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
| `server-terminal` (1.17.34) | `globalsettings` only | none (Tactical has no REST route for it) | `can_use_webterm`, and an effective superuser | a shell on the server itself, so no agent and no scope |

The socket has the same owner as `terminal-defaults`, and the two cannot drift: both come from the one table. An honoured AD-20
replacement of that module follows the same rule. A premium or server module that is not a replacement is refused, and so is a
disabled, legacy or unknown module, and Core itself. The kind `server-terminal` (1.17.34) is different: its owner is fixed, the enabled
core module `globalsettings` and nobody else (no replacement, no other module), because Tactical has no REST route that an owner table
could follow. See "Server terminal" below.

## 1. Ask for a ticket

`POST /api/tfd/tactical-websocket/<module_id>/<kind>/tickets/`. For `agent-terminal` the body is the JSON object
`{"agent_id": "<canonical agent id>"}` and nothing else (any other key, or a missing `agent_id`, is 400 `invalid_ticket_request`). For
`server-terminal` (1.17.34) the body is exactly `{}`: any key, including `agent_id`, is 400 `invalid_ticket_request`.

| Status | Code | Meaning |
| --- | --- | --- |
| 201 | | `{ticket, path, session_id, expires_in, kind}`. `expires_in` is 30. `path` is `/ws/tfd/agent-terminal/<ticket>/`, or `/ws/tfd/server-terminal/<ticket>/` for the server terminal. Open the path from the answer. `session_id` is a new uuid for this terminal session. |
| 400 | `invalid_agent_id` | the agent id is not well formed |
| 401 | `authenticated_request_required` | no signed-in Tec-Tac session |
| 401 | `tactical_session_required` | the session is not linked to a Tactical token; sign in again |
| 403 | `websocket_owner_required` | the module does not own the kind |
| 403 | `tactical_permission_denied` | the caller lacks `can_use_terminal` (the detail names it) |
| 403 | `superuser_required` | `server-terminal` (1.17.34): the caller is not an effective superuser |
| 403 | `server_terminal_disabled` | `server-terminal` (1.17.34): Tactical's server web terminal is off, or the caller lacks `can_use_webterm` |
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

A watcher checks the sign-in every 30 seconds and closes the socket with **4401** when it ends (the session is revoked, past its
absolute lifetime or idle, the Knox token is gone, or the user is disabled), and with **4003** when the flag or the agent's scope no
longer holds. Tactical's own disconnect then sends its kill, and the watcher is cancelled. Until 1.17.33 the idle limit was not checked
here; since 1.17.34 it is, and terminal input keeps the sign-in alive. See "Terminal input is activity".

## Terminal input is activity (Core 1.17.34, AD-35)

A technician who types in a terminal for an hour is working, even though no REST request is made. Before 1.17.34 the watcher did not look
at idle time at all, so a terminal could outlive the sign-in's idle limit. Now:

- **What counts.** Only the person's input and resize frames. Agent terminal: `{"action": "input", "data": "<text>"}` and
  `{"action": "resize", "rows": n, "cols": n}`. Server terminal: `{"action": "trmmcli.input", "data": {"input": "<text>"}}` and
  `{"action": "trmmcli.resize", "data": {"rows": n, "cols": n}}`. Start, kill, disconnect, unknown actions, empty input, a size that is
  not a whole number above zero, and everything Tactical sends back (output) do not count. A terminal that only prints output (for
  example `tail -f`) does not stay alive. Johan may widen or narrow this reading; it stands until he says so.
- **How.** The socket keeps only the time of the last counted frame, in memory, with a monotonic clock. No frame, text or size is stored or
  logged. Once every 30 seconds the watcher hands that time to `session_security.record_terminal_activity`, which runs Core's own
  session rules on the person's `TecTacSessionTrust` row: the row is locked, the policy in force now is used, `last_activity_at`,
  `last_seen_at` and `idle_expires_at` only move forward, the time is clamped to now, a revoked row is never revived, and there is at most
  one save a tick. There is no database write per keystroke.
- **What ends it.** An idle socket (no input for the idle limit) closes **4401**, and the trust row and the Knox token end the same way
  a REST idle timeout ends them. The absolute maximum still closes **4401** however much the person types. A disabled user, a revoked
  session or a deleted Knox token close **4401**. A removed role, a lost `can_use_terminal` or an agent that left the role's scope close
  **4003**.
- **Retries.** A stale database connection during the refresh is retried once (the refresh is safe to run twice). A second failure closes
  4401.

## Server terminal (Core 1.17.34, AD-35)

Tactical's own server web terminal (`ws/trmmcli/`) is a shell on the server that runs Tec-Tac and Tactical, started as the Tactical service
user. It is the most powerful socket Core relays, so it has its own kind and its own rules.

**Ticket.** `POST /api/tfd/tactical-websocket/globalsettings/server-terminal/tickets/` with the body `{}`. Single use, 30 seconds, kept as
a hash only, in the same store as the agent ticket. Core refuses, in this order: another module than `globalsettings` (403
`websocket_owner_required`, with a deny row); a caller who is not an effective superuser (a Django superuser, a role superuser or the root
user) (403 `superuser_required`, deny row); Tactical's switch off, or no `can_use_webterm` (403 `server_terminal_disabled`, deny row).
The switch is Tactical's own test (`CoreSettings.web_terminal_enabled` in v1.5.2): off when Tactical is hosted, when
`TRMM_DISABLE_WEB_TERMINAL` or `DEMO` is set, or when the Global Settings toggle `enable_server_webterminal` is off. Any error reading it
counts as off.

**Socket.** `wss://<host>/ws/tfd/server-terminal/<ticket>/`. Core runs Tactical's own `core.consumers.TerminalConsumer` in process as the
ticket's user, after these checks, in this order: the ticket is consumed once (close **4401**); the Origin check, the same rule as the
agent socket (**4003**); the sign-in re-check (**4401**); the effective-superuser re-check (**4003**); Tactical's switch and
`can_use_webterm` (**4003**); then ONE strict audit row, `custom:server-terminal-start`, written BEFORE the shell starts. If that row cannot
be written the socket closes **4502** (`audit_unavailable`) and no shell starts. Tactical's consumer then runs its own checks and starts
the shell the moment the socket is accepted. There is no start frame.

Frames are Tactical's own (AD-25): the client sends `trmmcli.input` (`data.input`), `trmmcli.resize` (`data.rows`, `data.cols`) and
`trmmcli.disconnect`; the server answers `trmmcli.output`. Input and resize count as session activity; output does not.

**Watcher.** Every 30 seconds, in a daemon thread: the sign-in rule above (4401), plus the effective-superuser standing, Tactical's switch
and `can_use_webterm` (4003). On any loss Core closes the socket and kills the shell (`kill_pty`).

**Route.** `ws/tfd/server-terminal/<ticket>/` is added next to the agent route, and only where Tactical itself would install `ws/trmmcli/`:
not in `DEMO`, not `HOSTED` and not `TRMM_DISABLE_WEB_TERMINAL`. If `core.consumers` cannot be imported (it needs `fcntl` and `pty`, so
Linux only), the socket closes **4503** and Tactical still starts.

**Audit.** The row's `module_id` is `globalsettings`, `object_type` is `server`, `object_id` is empty, `after_value` is `{session_id}`,
`operation_context.websocket` is `server-terminal`, and the provenance is `tactical-websocket`. Never typed text, output, a ticket or a
token. Core logs no frame. A refusal writes one deny row on the same object.

**Who calls it.** Only `globalsettings`. It is a request in `reviews/requests/core-modules.md`; the UI helper for the kind is a request in
`reviews/requests/ui.md`. Until both ship nothing in the product opens this socket. The capability and the Python contract
(`tec_tac.tactical_websocket.issue_ticket`) accept the kind the same way they accept `agent-terminal`: `agent_id` is `None`.

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
start. The table below is the agent terminal. The server terminal's row (1.17.34) is described under "Server terminal".

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

## Not in 1.17.34

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
- `tests/tactical-websocket-activity-1.17.34.py`: terminal input is activity: idle, input every few minutes, output alone, what does not count,
  the absolute maximum, the closed sign-ins (4401), the lost standing (4003), no backwards activity, no write per frame, no logged text, the
  stale-connection retry.
- `tests/tactical-websocket-server-terminal-1.17.34.py`: the server terminal ticket and socket against a stub of Tactical's `TerminalConsumer`:
  owner, superuser and switch refusals with their deny rows, the `{}` body, single use, Origin, the audit row before the shell, 4502 with no
  shell, losing superuser standing kills the shell, no logged text, the agent kind unchanged, and the switch read.
- `tests/tactical-websocket-probe-1.17.34.py`: a PC-side check of the 1.17.34 probe (no ticket call in an async leg, the refusal step, the
  gated server socket step with no input, the activity steps, cleanup limited to `wsprobe-`).
- `tests/tactical-websocket-runtime-1.17.34.py`: the 1.17.34 dev-server probe. It replaces the 1.17.33 one (kept in the tree): ticket calls in
  the async legs go through `sync_to_async(thread_sensitive=True)` (they raised `SynchronousOnlyOperation` and logged "Tec-Tac audit write
  failed module=remote-background action=deny"), the out-of-scope agent has its own refusal step with the `object_not_found` code and one
  deny row, and it adds the activity and server terminal steps. The server terminal SOCKET step starts a real shell, so it runs only with
  `TECTAC_WS_PROBE_SERVER_TERMINAL=1`; it sends no input, only Tactical's `trmmcli.disconnect`. Run it as in the 1.17.33 line below with
  the name `tactical-websocket-runtime-1.17.34.py`. Like 1.17.33 it was written on the development PC and did not run there.
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

# Tec-Tac Framework 1.17.31

This release adds Core's side of the Tactical terminal socket (C4). A signed-in person can ask Core for a single-use ticket, then open a
socket that Core relays to Tactical's own terminal, run as that person. No module ever holds a Tactical token. Nothing that already existed
changed. The UI helper and Remote Background's terminal tab come in later releases, once the UI ships its half.

Capability: new `core.tactical_websocket` 1.0.0 (major 1, additive). No migration in this release.

Date: 14 October 2026.

## Module-facing changes

Read these before you adopt 1.17.31. Each needs `requires.framework >=1.17.31`. A module that does not use them behaves as before.

- **Capability `core.tactical_websocket` 1.0.0 (new).** One operation, `issue_ticket(request, module_id, kind, agent_id)`. It answers
  `{ticket, path, session_id, expires_in, kind}` or raises `TicketRefusal` (`status`, `code`, `message`, `audit`). Core verifies the caller from
  the call stack, so a module can ask only for its own kind. Feature-detect with `has_capability('core.tactical_websocket')`.
- **The ticket route.** `POST /api/tfd/tactical-websocket/<module_id>/<kind>/tickets/` with exactly the JSON object `{agent_id}`. Any other key
  is 400 `invalid_ticket_request`. It answers 201 `{ticket, path, session_id, expires_in, kind}` with `expires_in` 30. The refusals are 400
  `invalid_agent_id`; 401 `authenticated_request_required` and `tactical_session_required`; 403 `websocket_owner_required` and
  `tactical_permission_denied` (it names `can_use_terminal`); 404 `websocket_kind_not_found` and `object_not_found` (an agent outside the
  caller's limits, the same text as the executor); 503 `websocket_unavailable` (nothing issued; fail closed).
- **Kinds and owners.** Only `agent-terminal` exists. Its owner is read from Core's route owner rule `agents/{}/terminal-defaults/`
  (`remote-background` today; an honoured AD-20 replacement follows the same rule). Its flag is `can_use_terminal`, and the agent must be in
  the caller's client and site limits. A module that is not the owner, or is a premium or server module that is not a replacement, gets 403.
- **The ticket.** 32 random bytes, URL-safe (43 characters), single use, valid 30 seconds. Core keeps only its SHA-256, under the key
  `tec-tac:wsticket:v1:` in Django's cache (Tactical's Redis). A cache that does not hold it gives 503 and no ticket. Throttles: 30 a
  minute and 500 a day.
- **The socket.** `wss://<host>/ws/tfd/agent-terminal/<ticket>/`, with no token in the URL. Close codes: **4401** (ticket missing, used or
  expired, or the sign-in behind it ended), **4003** (Origin not the request host, or the flag or scope no longer holds) and **4503** (Tactical's
  terminal consumer cannot be loaded; Tactical still starts). Messages are Tactical's own, unchanged: `start` (`shell`, `run_as_user`), `input`,
  `resize` and `kill`, and `trmmcli.output`, `terminal_error` and `terminal_info`.
- **The audit row.** One row per session start, action `custom:terminal-start`, object type `agent`, object id the agent. `after_value` is
  `{shell, run_as_user, session_id}`; the shell is cleaned and capped at 260 characters, or `default`. Its `operation_context` has
  `server_provenance` `tactical-websocket` and `websocket` `agent-terminal`. The row is strict: if it cannot be written, the shell does not start
  (`terminal_error`, code `audit_unavailable`). The row never carries typed input, output, a ticket or a token.
- **Deny rows.** Each 403 and each out-of-scope refusal writes one Core deny row (`core_refusal` true, the same provenance, metadata `reason`,
  `status` and `kind`). A successful ticket writes no row.
- **Nothing existing changed.** `core.tactical_operations` and the route owner table are unchanged. `terminal-defaults` keeps its owner, and a
  test pins it. The contract gains rows only.

## Closes

In `reviews/requests/core.md`: `C4 (RB2, RB11, finding 4)`, `C4, route owner` and `C4 update`. The `Tactical WebSocket ticket` bullet of the
core-modules review keeps only globalsettings' server web terminal.

Waiting for: the UI helper (`reviews/requests/ui.md`, From Core 1.17.31) and remote-background's terminal tab (`reviews/requests/core-modules.md`,
From Core 1.17.31). Each ends when the consuming release is signed.

## What changed

- `framwork/tec_tac/tactical_websocket.py` (new): the kinds, the owner check (through `_check_route_owner`), the ticket issue and consume,
  the sign-in re-check, the provider and capability, the lazy route and its installer.
- `framwork/tec_tac/tactical_websocket_consumers.py` (new): `TecTacAgentTerminalConsumer`, Tactical's own `TerminalStreamConsumer` run as the
  ticket's user, with the connect checks, the start row, and the watcher (every 30 seconds).
- `framwork/tec_tac/tactical_websocket_views.py` (new): the POST view.
- `framwork/tec_tac/audit.py`: `SERVER_PROVENANCE_TACTICAL_WEBSOCKET` and the private `_record_tactical_websocket`.
- `framwork/tec_tac/throttles.py`: the two ticket throttles. `framwork/tec_tac/urls.py`: the route. `framwork/tec_tac/openapi.py`: the group.
- `framwork/tec_tac/apps.py`: the capability registration and the ws route, each in its own guarded `try` in `ready()`. The route is skipped in DEMO.
- `framwork/tec_tac/contracts.py`: the Python row `issue_ticket` and the HTTP row for the route.
- `install.sh`: a verify step for `core.tactical_websocket`.
- `docs/tactical-websocket.md` (new). `docs/tactical-operations.md`: the note on the terminal-defaults owner.
- `docs/releases/RELEASE_NOTES_1.17.30.md`: the 1.17.30 note moved to the archive, as the release-integrity check requires.

## Tests

New, run on this PC against stubs (Django, channels, Redis and Tactical are not installed here):

- `tests/tactical-websocket-ticket-1.17.31.py`: the mint and its shape, the stored key and value (no raw ticket), each owner, flag and scope
  refusal with its deny row, the refusals without a row, the store (a dummy, down or colliding cache gives 503), one use, expiry, malformed
  tickets, the sign-in re-check, the owner table pin, `register_tactical_operation` for the terminal defaults route, the capability and its
  provider, the audit provenance, the view, the throttle rates and the contract rows. It runs the real `audit.py`, `tactical_operations.py`
  and `module_category.py`.
- `tests/tactical-websocket-consumer-1.17.31.py`: the relayed socket against a stub of Tactical's consumer: a valid ticket, replay, expiry,
  revoked session, lost flag, out-of-scope agent, Origin, Tactical's own refusal, one audit row per start, a row that cannot be written, no
  input, output or ticket in rows or logs, the watcher, and the kill on disconnect.
- `tests/tactical-websocket-route-1.17.31.py`: the route is appended once and skipped in DEMO; a missing consumer closes 4503; the guarded
  calls in `apps.py`.
- `tests/tactical-websocket-runtime-1.17.31.py`: a dev-server script run through Tactical's `manage.py shell` with channels'
  `WebsocketCommunicator`. It rolls back what it writes. **Not run here.**

Updated: `tests/f11-openapi-final-1.15.178.py` and `tests/f11-tracker-closure-1.15.184.py` pass with the new view mapped to the Tactical
Operations group.

## Not in this release

- **The server web terminal** (`ws/trmmcli/`, a shell on the server itself). It is a safety topic and waits for Johan's decision (CQ100).
- **The command stream socket** (`ws/agent/<id>/cmd/`). Remote Background already runs Send command through declared operations.
- **A row when a session ends** (exit code, duration). Johan asked for one row per session start only.
- **Binding the ticket to the client's address.** Not built; it breaks behind some proxies.
- **CQ93 (known issue, unchanged).** Scheduled runs of server-wide report models are unscoped (AD-34 condition 5). The design revisit is
  in `reviews/requests/core.md` ("Known issue ... CQ93").
- **Nginx.** Core assumes the existing `location ~ ^/ws/` routes `/ws/tfd/agent-terminal/` to daphne. Confirm on the dev server.

## Where the plan changed in the code

- The owner check uses `tactical_operations._check_route_owner` as the plan named, so the category rule and the honoured AD-20 replacement
  are the same ones the executor applies. A premium module that is not an honoured replacement is refused.
- A ticket is refused 401 `tactical_session_required` when the session has no linked Knox token. The plan did not list this code, but without
  a digest the socket's re-check could never pass.
- A refusal for a non-owner is written against the owner of the terminal (`remote-background`), not the module that asked. If no enabled core
  owner exists, the refusal is still 403 and no row is written (logged).
- The provider `issue_ticket` checks the verified caller, so a module can only ask for its own kind.
- A server web terminal kind was left out, and a question (CQ100) was added for Johan. This is not in the plan's list, but the decision is his.

## Checks run on this PC

- `ruff check` with the pipeline's Core selection (E9, F63, F7, F82) over the Core tree: passed. Pyflakes on the new files: passed.
- `python -B` on the whole `tests/` folder before and after the change: 213 pass now against 210 before. The three new stub tests pass, and
  so do the two OpenAPI guards after the mapping fix. The runtime script fails here only on the missing `asgiref` package, as expected. The other
  failures (scripts that need Django, Postgres or a dev server) are the same as before this release.
- `tests/reporting-server-wide-scope-1.17.30.py` now reads its release note from `docs/releases/`, where the note was archived in this release.
- `bash tests/release-integrity.sh`: passes. It needs a `python3` command, which this PC does not have, so it was run through a shim that calls
  the project's Python.

Not run here: Django, channels, Redis, Tactical, nginx. The real consumer, the Redis single-use delete, the ASGI route and the watcher run only
on the dev server, through `tests/tactical-websocket-runtime-1.17.31.py`.

# Tec-Tac Framework 1.17.33

Date: 14 October 2026.

This patch release fixes the dev-server probe for the Tactical terminal socket, hardens the socket against a stale database connection, and adds the browser contract rows that UI 0.12.103 asked for. Nothing that a module calls changed.

Capability: `core.tactical_websocket` stays 1.0.0. No migration in this release.

Closes these requests in `reviews/requests/core.md`: "Bug in the 1.17.32 dev-server probe", "1.17.32 probe on the dev server: the relayed socket refused a valid ticket" and "From ui 0.12.103". The Origin and nginx entries from UI 0.12.102 stay open until Johan's probe run passes and a real terminal works in the browser.

## Module-facing changes

No module needs to change, and `requires.framework` does not move.

- **No contract change.** The ticket route, its body and answers, its refusals, the close codes 4401, 4003 and 4503, the messages and the audit row are unchanged. Checked: only `remote-background` is the owner of the terminal kind, and nothing in `modules/` calls `core.tactical_websocket`, `tactical_websocket`, `agent-terminal` or `session_refusal` directly.
- **One behaviour is more tolerant, on the server.** A read that fails on a stale database connection is retried once before the socket is refused or closed. A second failure still closes 4401, as before.
- **The contract export gains one row and two details.** Browser row `ui.authenticated.jobs` (UI 0.12.103), the signed-out line on `ui.authenticated.notifications`, and the signed-out line on `ui.authenticated.transport` (the row that lists `api`, `apiRaw`, `apiBlob` and `apiText`). They are documentation only: no capability or contract version moves, and no value a module consumes changes. The export itself is generated on the server after this release.

## 1. The probe had a bug of its own: `status` is not a column

Johan's run of the 1.17.32 probe stopped in `pick_agent` with a `FieldError`. In Tactical v1.5.2, `Agent.status` is a Python property (`agents/models.py`, computed from `last_seen`, `offline_time` and `overdue_time`). It is not a database field, so `Agent.objects.exclude(status=...)` cannot work.

`pick_agent` now works in Python:

1. `TECTAC_WS_PROBE_AGENT` still comes first, and the probe still stops if that agent does not exist.
2. Without it, the probe walks `Agent.objects.order_by("pk")` and takes the first agent whose `status` is not `online`. It stops reading at the first match.
3. If every agent is online, it takes the first agent and prints the same two WARN lines as before.
4. If the query or the status read fails, the probe prints one plain line (what failed, and `set TECTAC_WS_PROBE_AGENT=<agent_id>`) and stops. No traceback.

Nothing in the probe filters on `status` in the database.

## 2. "The connection is closed": the probe's design, plus a small real gap in Core

Johan's run then showed Core refusing a valid ticket. The log held `OperationalError: the connection is closed`, raised in `session_refusal`.

**Decision: mainly the probe's design.** The 1.17.32 probe did all its work inside `transaction.atomic()` and rolled back at the end. Channels' `database_sync_to_async` calls `close_old_connections()` before and after each call. Inside an atomic block, autocommit is off, which differs from the setting, so Django treats the connection as unusable and closes it in the middle of the transaction. The next read then fails, and Core fails closed with `check_failed`. Core's connect path was already right: the ticket, the re-check, the start row and the watcher all run through `database_sync_to_async`, as Tactical's own consumers do.

**Core still had a smaller gap.** After a Postgres or pgbouncer restart, or an idle kill, a connection that Django has not yet flagged (`CONN_MAX_AGE` above 0) fails on first use. One such failure refused a good ticket, or closed a terminal that had run for hours. Tactical sets no `CONN_MAX_AGE`, so the dev server mostly reconnects on every call. This is hardening, not the cause of Johan's failure.

What changed in Core (`tactical_websocket.py`, `tactical_websocket_consumers.py`):

- New `run_with_fresh_connection(fn)`. A read that fails with `OperationalError` or `InterfaceError` closes this thread's connections and runs again, once. The whole check runs again, not one query. A second failure is raised as before, so Core still fails closed. Any other error is not retried. Inside a transaction nothing is closed or retried.
- `session_refusal` uses it, so the user, session and Knox reads retry together. The consumer's `recheck()` uses it too, including the Tactical permission and the agent scope. That covers the connect and every 30 second watcher tick. A stale connection at connect, or at a tick, reconnects and carries on.
- Before the strict audit write, Core checks that this thread's connection still answers and closes it if not. It skips this inside a transaction. **The audit write itself is never retried.** A retry could write a row twice, and the rule stays "no row, no start": a failed write still sends `audit_unavailable` and starts nothing (CQ97).
- Logging: one warning line on a reconnect (no user data, no ticket). The "Could not re-check" line is logged only when the second attempt fails.
- No change to the close codes, the messages, the ticket, the capability version or the audit row. See "Stale database connections" in `docs/tactical-websocket.md`.

## 3. The probe is rewritten: committed rows, a cleanup, a stale-connection step

`tests/tactical-websocket-runtime-1.17.33.py` replaces `tests/tactical-websocket-runtime-1.17.32.py` (removed). It drops `transaction.atomic` and the rollback.

- **Sweep first.** It deletes leftovers of earlier runs: users and roles named `wsprobe-...`, their session rows and Knox tokens. It keeps `wsprobe-` audit rows.
- **Committed rows.** A probe user `wsprobe-<tag>`, a role with `can_use_terminal` and no client or site limit, a Knox token and a session row.
- **Same socket checks.** A valid ticket is accepted; one start row for two starts; a replay closes 4401; a foreign Origin closes 4003; the split-host Origin is accepted; a malformed ticket closes 4401. It still uses `asgiref` only (no `channels.testing`, no `daphne`).
- **New: the stale-connection check.** It mints a ticket, breaks this thread's database connection, then opens a socket with that ticket. It must be accepted. On the dev server the driver connection is closed under Django, which is the real stale case. If there is no driver connection to close, it calls `connection.close()`.
- **Cleanup in a `finally` block.** It deletes the session rows, tokens, user and role it created, and every ticket key it minted. It prints one line per kind, and ends with a "no wsprobe rows left" check. It deletes only rows whose user name or role name starts with `wsprobe-`, and refuses any other prefix. See CQ103 in `reviews/questions/core.md` (assumption: keep the probe's audit rows until Johan answers; option b). Each run leaves one `custom:terminal-start` row under a `wsprobe-` user name.

The PC-side guard `tests/runtime-script-imports-1.17.32.py` follows the new name and checks the new shape (no transaction, deletes in a `finally`).

### What could not run on this PC

Django, channels, Redis, nginx and Tactical are not installed here. The probe itself has not run, and the real stale-connection behaviour has not been seen. The PC tests cover Core's own logic against stubs (`tests/tactical-websocket-stale-connection-1.17.33.py`) and the probe's shape and `pick_agent` against a fake Agent (`tests/tactical-websocket-probe-1.17.33.py`). The probe needs Johan's run.

## 4. Commands for the dev server (Johan)

1. Update the dev server to Core 1.17.33 from `dev`. Migrations are unchanged.
2. As root, copy the probe and make it readable: `cp /opt/tec-tac-src/tests/tactical-websocket-runtime-1.17.33.py /tmp/ && chmod 644 /tmp/tactical-websocket-runtime-1.17.33.py`. `/opt/tec-tac-src` is the installer's default source folder. If the checkout is elsewhere, use that path.
3. Check the packages: `sudo -u tactical /rmm/api/env/bin/python -c "import asgiref.testing, channels, uvicorn; print('ok')"`.
4. Run the probe: `sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/tactical-websocket-runtime-1.17.33.py'`. To choose an agent: `sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && TECTAC_WS_PROBE_AGENT=<agent_id> ../env/bin/python manage.py shell < /tmp/tactical-websocket-runtime-1.17.33.py'`.
5. Expect PASS lines, one `deleted` line per kind, and a last line `tactical-websocket-runtime-1.17.33: ok`. A NATS error after the start is expected with no online agent.
6. Check nothing is left: `sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell -c "from django.contrib.auth import get_user_model as g; print(g().objects.filter(username__startswith=\"wsprobe-\").count())"'`. Expect 0.
7. If not yet done, repeat steps 4 to 6 of the 1.17.32 note (`nginx -T`, `systemctl status daphne`, `ALLOWED_HOSTS` and `CORS_ORIGIN_WHITELIST`). Then try a real terminal in the browser. The Origin and nginx entries in `reviews/requests/core.md` stay open until that passes.

## 5. Browser contract rows from UI 0.12.103

Wording is taken from `workspace/ui/docs` (`module-job-follow.md`, `module-notifications.md`, `module-runtime-api.md`).

- **New row `ui.authenticated.jobs`** (service `jobs`, operation `follow`, docs `tec-tac-ui/docs/module-job-follow.md`). `follow(descriptor)` returns `{id, cancel()}`. Descriptor keys: `id`, `title`, `path`, `check(payload)`, `successMessage`, `errorMessage`, `timeoutMessage`, `intervalMs` (default 5000, clamped 2000 to 60000) and `timeLimitMs` (required, clamped 10000 to 1800000). Stop rules, the limits (10 live follows per module, 50 in all), the refusals, the shell-bound module id, the `dedupeKey` `job-follow:<id>` and the guarded `api` rule are in the row.
- **`ui.authenticated.notifications`** gets a details list (it had none): nothing shows and nothing is sent while the person is signed out, a module treats status 401 as signed out and stays silent, and `show`, `info`, `success`, `warning` and `error` return null.
- **`ui.authenticated.transport`** gets the line "While signed out the shell refuses the call with status 401 and code signed_out, with no request." The request named `api`, `apiRaw`, `apiBlob` and `apiText` but not a row, and this row lists those four calls.

The pinned set in `tests/browser-contract-catalog-1.15.170.py` moves with the rows, as it did in 1.17.32.

## Tests

New:

- `tests/tactical-websocket-stale-connection-1.17.33.py`
- `tests/tactical-websocket-probe-1.17.33.py`
- `tests/browser-contract-rows-1.17.33.py`
- `tests/tactical-websocket-runtime-1.17.33.py` (dev server only)

Changed: `tests/runtime-script-imports-1.17.32.py` (new probe name and shape), `tests/browser-contract-catalog-1.15.170.py` (the pinned row set), and a comment in `tests/tactical-websocket-consumer-1.17.31.py` and `tests/tactical-websocket-ticket-1.17.31.py` that names the probe. The earlier release note moved to `docs/releases/`.

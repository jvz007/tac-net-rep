# Tec-Tac Framework 1.17.34

Date: 14 October 2026.

This patch release does three things. It stops old "Module job failed" notices and emails from coming back after you clear them. It makes typing in a Tactical terminal count as activity, so a technician at work is not signed out. It adds the server web terminal for superusers (Johan's AD-35), and fixes the last steps of the dev-server probe.

Capability: `core.tactical_websocket` goes **1.0.0 to 1.1.0** (additive). **Migration `0030_notice_ledger` runs**: one new table, written by hand because Django is not installed on the development PC.

Closes these requests in `reviews/requests/core.md`: the HIGH "Module job failed notices for OLD jobs come back every time a module is installed", "Module failure notices raised days late for later recipients" (same code), the "Binding (Johan, 14 October 2026, AD-35)" entry (items 1, 2 and 3), and the waiting bullet "Tactical WebSocket ticket (server side of the UI WebSocket helper), for the server web terminal only". The Origin and nginx entries stay open until Johan's probe run and a real browser terminal pass. The release-manager record step for these entries is done here: I removed them from `core.md` in this commit, so nothing is left for the record step except confirming it after signing.

## Module-facing changes

Checked: `grep` of `modules/` finds `core.tactical_websocket` only in `remote-background` (documentation, its UI module and tests, all for the kind `agent-terminal`). Nothing in `modules/` or `workspace/ui` reads the failure notices, the sweep or the notice dedupe. Notices that modules publish through `tec_tac.notices.publish` are not touched.

- **`core.tactical_websocket` 1.1.0 (additive).** New ticket kind `server-terminal`. Route: `POST /api/tfd/tactical-websocket/globalsettings/server-terminal/tickets/` with the body exactly `{}`. Only the module `globalsettings` may ask. Only an effective superuser may have it. The answer is `201 {ticket, path, session_id, expires_in, kind}` with `path` `/ws/tfd/server-terminal/<ticket>/`. New refusals: `403 superuser_required` and `403 server_terminal_disabled` (Tactical's switch is off, or `can_use_webterm` is missing). New close code **4502** (`audit_unavailable`: the start row could not be written, so no shell started). New audit action `custom:server-terminal-start` (object type `server`, module `globalsettings`). `issue_ticket(request, module_id, kind, agent_id=None)`: `agent_id` now defaults to `None` and is `None` for the server kind. The Python contract row, the HTTP row and the `ui.authenticated.websocket` row list all of this.
- **Unchanged for `agent-terminal`:** the body `{agent_id}`, the answers, the refusals, the close codes 4401, 4003 and 4503, the messages and the audit action `custom:terminal-start`.
- **One behaviour changes for every Tactical terminal socket (AD-35).** Input and resize frames now count as session activity, and the socket's watcher now enforces the sign-in's idle limit. A terminal with no input for the idle limit closes **4401** and the sign-in ends, like a REST idle timeout. A terminal in use stays open. Output alone does not count. Before this release the idle limit was not checked on a terminal. `remote-background` and the UI helper already treat 4401 as "sign-in ended", so nothing needs to change.
- **Contract export.** `ui.authenticated.websocket` gains three detail lines. The export is generated on the server after this release.
- **Notices.** `tec_tac.notices.publish_system_notice` is unchanged. `notices.py` gains `ledger_have`, `ledger_add`, `ledger_count_since` and `ledger_prune` (Core-internal, not a public contract).

## 1. Old "Module job failed" notices came back (HIGH)

**What Johan saw.** After an install on 14 October, two old failures (Patching jobs 46e344fc, 10 October, and c43cee4f, 11 October) came back as new notices at 07:49. The older rows were gone.

**Root causes, found in the code.**

1. The only record that a person had been told was the notice row itself. A row is deleted by "Clear read" (the drawer button: `DELETE ui/notices/clear-read/` deletes every read row of the person, and the toasted notice is marked read at once) and by `notices._prune_user` (30 days or 500 rows, on every create). The Priority 1 email marker rows (`module-job-failed-email:<job id>`, read at creation) are read rows too, so "Clear read" deleted them as well. The email's "already sent" check broke the same way, and the hourly cap count, which counted those marker rows, shrank.
2. The look-back was 7 days. A cleared row for a job finished 3 days ago was raised again on the next tick, as a fresh toast and a Priority 1 email. A person who gained a role, or was first seen days later, also got an old failure.
3. The scheduler tick runs the sweep every minute, so "at install time" was most likely the first tick after the rows were cleared, or after the tick resumed once the install restarted the services. The code has no install hook.

**Checked: nothing rewrites old job files.** For the jobs the sweep reads (Module Management v2), `finished_at` is written in only three places: `scripts/module-v2-job-helper.py` at the end of the job being run (line 1683), `mark_failed` for the job being dispatched (line 1701), and `module_manager_v2._queue_v2` for a job that failed to dispatch. Each writes only the job it is working on; none touches an old job file. So an old job's `finished_at` does not move, and the 7 day window was the whole problem.

**The fix (`module_failure_notices.py`, `notices.py`, `models.py`, migration 0030).**

- **A notice ledger.** New table `TecTacNoticeLedger` (kind `notice` or `email`, the job id as the key, the person, the time; unique on person, kind and key; deleted with the person). The sweep writes it when it stores a notice or tries an email. It reads the ledger together with the notice rows and the old email marker rows, so nothing needs migrating: a notice raised before this release still counts, and the sweep copies those rows into the ledger the first time it sees them. "Clear read" and the 30 day pruning never touch it. The sweep deletes ledger rows older than 7 days.
- **A short window.** `NOTICE_WINDOW_HOURS = 6`, from the job's `finished_at`, for the toast, the history row and the Priority 1 email alike. A job older than that gets no notice, no toast and no email, and a job with no readable `finished_at` is skipped. It stays on the Modules page and in the job log. The cost: if the scheduler tick or Celery is down for more than 6 hours, a failure in that gap is not announced. This is my assumption of Johan's "a few hours" (CQ104 in `reviews/questions/core.md`).
- **Never again.** A job already in the ledger for a person and a kind is never raised again for that person, even when the row was deleted.
- **The email cap counts ledger rows,** not marker rows. Core no longer writes the "Email notice sent" marker rows into a person's notice history.
- **No double email.** The try is recorded in the ledger before the send. If the ledger cannot be written, nothing is sent, and the next tick tries again inside the window. If the ledger cannot be read, the email step sends nothing. A ledger problem for the notices alone never stops the toast.
- **The tick says what it left alone.** The scheduler tick output gains `module_failure_skipped_old`, `module_failure_already_notified` and `module_failure_emails`, and the log gets one line with the counts. Existing fields are unchanged.
- Never raises. Tactical is not affected.

**Was the Priority 1 email sent again for 46e344fc and c43cee4f on 14 October at 07:49?** The code cannot tell. By the code, it was probably sent again: the marker rows (`module-job-failed-email:<job id>`) are read rows, so "Clear read" deleted them together with the notices, and the email only skips a job that has its marker row. Johan can confirm in his inbox, and from the `custom:priority-mail` audit rows (the object id is the job id). The read-only query is in "Dev-server steps" below.

## 2. Terminal input is activity (AD-35 item 1)

The 30 second watcher on a relayed terminal socket hands the time of the last input to `session_security.record_terminal_activity`. That refreshes `last_activity_at`, `last_seen_at` and `idle_expires_at` on the person's `TecTacSessionTrust` row through Core's own session rules: the row is locked, the policy in force now is used, nothing moves backwards, the time is clamped to now, a revoked row is never revived, and there is at most one save a tick. There is no database write per keystroke. Only input and resize frames count (agent: `input` and `resize`; server: `trmmcli.input` and `trmmcli.resize`). Start, kill, disconnect, unknown actions, empty input and output do not. An idle socket closes 4401 and the sign-in and Knox token end. The absolute maximum, a disabled user, a revoked session and a deleted token still close 4401. A removed role, a lost `can_use_terminal` and an agent out of scope close 4003. No typed text, size, ticket or token appears in any log or audit row.

**Reading to confirm.** I read "counts as activity" as input and resize only, so a terminal that only prints output (for example `tail -f`) is still ended by the idle limit. This stands until Johan says otherwise.

**Tactical's own debug log (AD-25, accepted).** Tactical's agent terminal consumer logs each frame's payload at DEBUG level (`[TerminalStreamConsumer] Received action=...`). That includes typed input when Tactical's debug logging is on. Core logs no frame and cannot change Tactical's line. Tactical's server terminal consumer logs no frame.

## 3. Server web terminal (AD-35 item 2)

Tactical's `ws/trmmcli/` is a shell on the server, started as the Tactical service user. It has its own kind so it has its own rules.

- **Ticket.** Single use, 30 seconds, hash only, same store as the agent ticket. Refused in this order: another module than `globalsettings` (403 `websocket_owner_required`); not an effective superuser (403 `superuser_required`); Tactical's switch off or no `can_use_webterm` (403 `server_terminal_disabled`). Each 403 writes one deny row against `globalsettings`. The switch is Tactical's own test (`CoreSettings.web_terminal_enabled`, v1.5.2): off when hosted, when `TRMM_DISABLE_WEB_TERMINAL` or `DEMO` is set, or when the Global Settings toggle is off. An error reading it counts as off.
- **Socket `ws/tfd/server-terminal/<ticket>/`.** Core runs Tactical's own `core.consumers.TerminalConsumer` in process as the ticket's user, after: the ticket consumed once (4401), the Origin check (4003), the sign-in re-check (4401), the superuser re-check (4003), Tactical's switch and `can_use_webterm` (4003), then ONE strict audit row `custom:server-terminal-start` BEFORE the shell starts. If the row cannot be written, the socket closes **4502** and no shell starts. Tactical's consumer starts the shell the moment the socket is accepted, so there is no start frame. Its frames are `trmmcli.input`, `trmmcli.resize` and `trmmcli.disconnect`.
- **Watcher.** Every 30 seconds a daemon thread re-checks the sign-in (idle, absolute, Knox, user) and the superuser standing, the switch and `can_use_webterm`, and on any loss closes the socket and kills the shell.
- **Checked against Tactical v1.5.2** (`core/consumers.py` `TerminalConsumer`, `tacticalrmm/urls.py`): the consumer reads the user from the scope, refuses on the Global Settings switch and `can_use_webterm` (close 4401), accepts, then starts the shell in a thread; `receive_json` takes only `trmmcli.resize`, `trmmcli.input` and `trmmcli.disconnect`; `disconnect` kills the shell. Core's consumer subclasses it and adds only the steps above. One race is left and documented: if the switch flips between Core's check and Tactical's own connect, a start row exists for a shell Tactical then refused.
- **Route.** `ws/tfd/server-terminal/<ticket>/` is installed only where Tactical itself installs `ws/trmmcli/`: not `DEMO`, not `HOSTED`, not `TRMM_DISABLE_WEB_TERMINAL`. If `core.consumers` cannot be imported (it needs `fcntl` and `pty`, so Linux only), the socket closes 4503 and Tactical still starts.
- **Nobody calls it yet.** `globalsettings` and the UI helper still have to adopt it. Both are written as requests (see "Requests written").

## 4. The probe's last steps (AD-35 item 3)

Johan's 1.17.33 run passed the first four steps and failed in the probe itself. `tests/tactical-websocket-runtime-1.17.34.py` replaces the 1.17.33 probe, which stays in the tree.

- **(a) `SynchronousOnlyOperation`.** The foreign-Origin and split-host steps called `issue_ticket` from inside the async leg. `issue_ticket` reads the role scope and writes the deny row through the synchronous ORM, which Django refuses inside a running event loop. Core then logged "Tec-Tac audit write failed module=remote-background action=deny" and the call raised `TicketRefusal object_not_found`. Every ticket call in an async leg now goes through `sync_to_async(new_ticket, thread_sensitive=True)`.
- **(b) The refusal step.** A step of its own asks for an agent outside the probe user's scope, catches `TicketRefusal`, asserts `object_not_found` (404) and that exactly one deny row was written. The agent is one that does not exist, which Core answers with the same text as an out-of-scope agent (the probe user's role has no client or site limit, so there is no real out-of-scope agent to use).
- **(c) The AD-35 steps.** Activity: the probe back-dates its own throwaway session row, calls the same function the watcher calls, and checks that input refreshes `idle_expires_at`, that output alone does not, and that an input after the idle limit ends the session (`session_idle_timeout`). It needs an idle policy of at least 4 minutes and changes no policy. Server terminal: a throwaway `wsprobe-` superuser mints a ticket as `globalsettings`; a non-superuser and the module `remote-background` are refused. **The socket step starts a real shell, so it runs only with `TECTAC_WS_PROBE_SERVER_TERMINAL=1`** and prints a SKIP line otherwise. It sends no input, only Tactical's `trmmcli.disconnect`, then checks one `custom:server-terminal-start` row and a 4401 on reuse. If `globalsettings` is not an enabled core module on the dev server, or Tactical's switch is off, the ticket steps print a SKIP line and the rest is skipped.
- Cleanup is unchanged: it deletes only rows named `wsprobe-` and keeps the probe's audit rows (CQ103 b).
- A PC-side check, `tests/tactical-websocket-probe-1.17.34.py`, reads the probe with `ast`: no ticket call inside an async def, the refusal caught and asserted, the socket step gated on the variable, no input frame to the server terminal, cleanup limited to `wsprobe-`. It fails on the 1.17.33 probe.

## Dev-server steps (Johan)

1. Update the dev server to Core 1.17.34 from `dev`. **Migration `0030_notice_ledger` runs.** If `manage.py migrate` fails, stop and tell me. `manage.py makemigrations --check --dry-run` shows any difference between the hand-written migration and the model.
2. `cp /opt/tec-tac-src/tests/tactical-websocket-runtime-1.17.34.py /tmp/ && chmod 644 /tmp/tactical-websocket-runtime-1.17.34.py` (`/opt/tec-tac-src` is the installer's default source folder; if yours differs, use that path).
3. Check the packages: `sudo -u tactical /rmm/api/env/bin/python -c "import asgiref.testing, channels, uvicorn; print('ok')"`
4. Run the probe: `sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/tactical-websocket-runtime-1.17.34.py'`
   - Choose the agent: `sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && TECTAC_WS_PROBE_AGENT=<agent_id> ../env/bin/python manage.py shell < /tmp/tactical-websocket-runtime-1.17.34.py'`
   - Include the server terminal socket step (a real shell starts and is killed at once; no input is sent): `sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && TECTAC_WS_PROBE_SERVER_TERMINAL=1 ../env/bin/python manage.py shell < /tmp/tactical-websocket-runtime-1.17.34.py'` (both variables can be set together).
   - Expect PASS lines, SKIP lines for what this server cannot do, one `deleted` line per kind, `no wsprobe rows left`, and a last line `tactical-websocket-runtime-1.17.34: ok`. A NATS error after the start is expected with no online agent.
5. Check nothing is left (expect 0): `sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell -c "from django.contrib.auth import get_user_model as g; print(g().objects.filter(username__startswith=\"wsprobe-\").count())"'`
6. Proxy and service: `sudo nginx -T 2>/dev/null | grep -n -A12 'location ~ ^/ws/'` (expect `proxy_pass http://unix:/rmm/daphne.sock`, the `Upgrade` and `Connection` headers, `Host $host`, no rewrite of `Origin`) and `systemctl status daphne --no-pager`.
7. Was the Priority 1 email sent again for jobs 46e344fc and c43cee4f? Read-only: `sudo -u tactical bash -c "cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell -c \"from logs.models import AuditLog as A; rows=[r for r in A.objects.filter(action='custom:priority-mail').order_by('-entry_time')[:500] if str((r.debug_info or {}).get('object_id','')).startswith(('46e344fc','c43cee4f'))]; print(len(rows)); [print(r.entry_time, (r.debug_info or {}).get('object_id')) for r in rows]\""` Then check your inbox for 14 October about 07:49.
8. The notice ledger on the real database (rolls back, leaves nothing behind): `cp /opt/tec-tac-src/tests/module-failure-notices-ledger-runtime-1.17.34.py /tmp/ && chmod 644 /tmp/module-failure-notices-ledger-runtime-1.17.34.py && sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/module-failure-notices-ledger-runtime-1.17.34.py'`. Expect PASS per step and a last line `module-failure-notices-ledger-runtime-1.17.34: ok`. It uses a fake sender: nothing is mailed, and no real administrator is a recipient.
9. Export a fresh public contract. It lists capability `core.tactical_websocket` 1.1.0, the kind `server-terminal`, `superuser_required`, `server_terminal_disabled`, close code 4502 and the terminal-activity rule.
10. Then try a real terminal in the browser (Remote Background). The Origin and nginx entries in `reviews/requests/core.md` close after that.

## What could not run on this PC

Django, channels, Redis, Tactical and nginx are not installed here. So these did not run: migration `0030_notice_ledger` (hand-written; `makemigrations --check` on the dev server is the check), `manage.py shell` probes (`tests/tactical-websocket-runtime-1.17.34.py` and `tests/module-failure-notices-ledger-runtime-1.17.34.py`), Tactical's real `core.consumers.TerminalConsumer` (a stub that follows its source stands in), the real Redis single-use delete, the real ASGI route and watcher thread, and the real database behaviour of the ledger (a fake ledger stands in). The Django-free tests below ran and passed.

## Tests

New:

- `tests/module-failure-notices-1.17.34.py`: raise, Clear read, sweep again: nothing new and no email, even inside the window; old jobs give nothing; once per recipient; a recipient who appears later; the cap counts ledger rows; old rows and markers still count and are copied into the ledger; ledger failures never raise and never double-send; prune; the report; source checks (the default mark, `clear_read` and `_prune_user`, the migration).
- `tests/module-failure-notices-ledger-runtime-1.17.34.py` (dev server only).
- `tests/tactical-websocket-activity-1.17.34.py`
- `tests/tactical-websocket-server-terminal-1.17.34.py`
- `tests/tactical-websocket-probe-1.17.34.py`
- `tests/tactical-websocket-runtime-1.17.34.py` (dev server only)

Changed: `tests/module-failure-notices-1.17.14.py` (6 hour window, ledger defaults off), `tests/priority-mail-1.17.25.py` and `tests/caller-identity-1.17.21.py` (ledger seams), `tests/notices-publish-1.17.16.py` (the ledger model in the stub), `tests/priority-mail-no-private-relay-1.17.28.py` (migration 0030 names 0029 as its dependency), `tests/tactical-websocket-ticket-1.17.31.py` (the activity helper and the superuser fixtures), `tests/tactical-websocket-route-1.17.31.py` (the server route), `tests/browser-contract-rows-1.17.32.py` (the new rows) `tests/runtime-script-imports-1.17.32.py` (the 1.17.34 probe), and the three tests that pin the newest migration (`tests/update-source-1.17.2.py`, `tests/session-theme-1.17.24.py`, `tests/runtime-settings-upload-1.17.14.py`: 0030 is now the newest).

One test fails in this workspace and is not from this release: `tests/contract-export-1.17.18.py` checks the UI source (`tacticalScope` in `workspace/ui`) when `workspace/ui` sits beside Core, and the UI source does not match its pin. It does not read anything Core 1.17.34 changed. The other failures in a full run need Django, Tactical or the dev server, and failed the same way before this release.

## Requests written

- `reviews/requests/core-modules.md`, under globalsettings: use the `server-terminal` ticket for its server web terminal once Core 1.17.34 is signed and exported; hide it for non-superusers and where Tactical turns it off (AD-12, AD-35).
- `reviews/requests/ui.md`: the WebSocket helper must open the `server-terminal` kind (Tactical's `trmmcli.*` frames, no start frame, close 4502 and 4003 as refusals).
- `reviews/questions/core.md`: CQ104 (the notice window length, assumption 6 hours) and CQ105 (the server terminal probe step is opt-in), and the 1.17.34 dev-server note.

## Left out, on purpose

- AU2 (AU16) Patching lifecycle command exit 1: waits on Johan's install log (Question 8 in the findings file).
- The production gate (enforce module categories, AD-21 condition 6): Johan has not named the release.
- Save all UI preferences and module user preferences: a new per-person preference store is a separate design and contract item.
- The other large contract entries (page a whole-list GET on the server, the export audit row for checks, secret storage, system action, universal filters) and the CQ93 revisit.

# Tec-Tac Framework 1.17.32

Date: 14 October 2026.

This patch release fixes three things found after 1.17.31. The dev-server check for the Tactical terminal socket could not run. The
socket rejected every terminal on the standard split-host layout (the API and the web UI on different hosts). And Core still owed the
browser contract rows that the UI releases 0.12.97 to 0.12.102 asked for. Nothing that a module calls changed. The ticket, the close
codes, the messages and the audit row are as they were in 1.17.31.

Capability: `core.tactical_websocket` stays 1.0.0. No migration in this release.

## Module-facing changes

No module needs to change, and `requires.framework` does not move.

- **No contract change.** The ticket route, its body and answers, its refusals, the close codes 4401, 4003 and 4503, the messages and the
  audit row are unchanged. No module in `modules/` calls the terminal socket yet (checked: nothing in `modules/` uses `tacticalWebSocket`,
  `tactical-websocket`, `core.tactical_websocket` or `agent-terminal`).
- **One rule is looser, on the server.** Close code 4003 now also accepts an Origin that equals a frontend origin named in Tactical's own
  `CORS_ORIGIN_WHITELIST` (see "The Origin check" below). It is read from server settings only, never from a request, and it covers
  exact http(s) origins only.
- **The contract export gains rows and details.** Browser rows `ui.authenticated.websocket` (Tactical terminal socket, UI 0.12.102) and
  `ui.authenticated.services` (services, UI 0.12.101 and 0.12.102). Details on the existing rows: `ui.authenticated.header` (`popoverTarget`,
  UI 0.12.101), `ui.authenticated.runtime-context` (`user.id`, UI 0.12.101), `ui.authenticated.popup` (`route.meta.popupPublishers`, the
  route-path rule, the console warnings and `forModule(moduleId, { isAbandoned })`, UI 0.12.97), `ui.authenticated.navigation`
  (`tacticalPermission`, UI 0.12.99) and `ui.authenticated.context-actions` (the right-click menu, UI 0.12.99). The rows are documentation
  only. The export itself is generated on the server after this release.

## What failed on the dev server, and why

The 1.17.31 dev-server script imported `channels.testing`. That module imports `daphne.testing`, and Tactical v1.5.2's venv has no daphne.
Johan's paste shows `ModuleNotFoundError: No module named 'daphne'`. Tactical's own socket service runs `uvicorn --uds /rmm/daphne.sock
tacticalrmm.asgi:application`, so the venv has what the socket needs (channels 4.3.2, channels_redis, asgiref 3.9.1, uvicorn), just not daphne.

`tests/tactical-websocket-runtime-1.17.32.py` replaces the 1.17.31 script. It drives the same ASGI application,
`tacticalrmm.asgi.application` (ProtocolTypeRouter, the Knox middleware stack and the URL router, with Core's route), with
`asgiref.testing.ApplicationCommunicator`. It builds the websocket scope by hand. It keeps every check of 1.17.31 and the rollback, and it
adds three socket checks: a foreign Origin closes 4003, a split-host Origin is accepted when `CORS_ORIGIN_WHITELIST` is not empty, and a
malformed ticket closes 4401. The probe agent is `TECTAC_WS_PROBE_AGENT` if set, else the first agent that is not online, else the first agent
with a printed warning. The header of the file has the commands for the dev server (stdin form and argument form, as the tactical user and
as root). It was not run on this PC: Django, channels, asgiref, Redis, nginx and Tactical are not installed here.

## Import audit (every Core test and script)

An AST scan of `tests/`, `scripts/`, `framwork/`, `extensions/`, `bootstrap-modules/`, `examples/`, `templates/` and `reportsets/` against
Tactical v1.5.2's `requirements.txt` and `INSTALLED_APPS` found one import that the venv does not have: `channels.testing` in the 1.17.31
runtime script. Everything else resolves to the standard library, a Tactical app, `tec_tac` or a Tactical requirement.

`tests/runtime-script-imports-1.17.32.py` keeps it that way. It checks the 32 `manage.py shell` scripts (imports only from the standard library,
Tactical's apps, `tec_tac` and the requirement list, never daphne, channels.testing, pytest, pytest_asyncio, mock, requests_mock or freezegun),
and every other Python file in those folders (never daphne or channels.testing). It also checks the 1.17.32 socket script's shape: asgiref, a
hand-built scope, the rollback and cleanup, 4401, 4003 and one start row. It fails on the 1.17.31 tree and passes on this one.

## The Origin check (a Core defect, now fixed in code)

`origin_allowed()` closed with 4003 unless the Origin's host equalled the request's Host header. Tactical's standard install
(`install.sh`) sets `ALLOWED_HOSTS = [rmmdomain]` and `CORS_ORIGIN_WHITELIST = [https://frontenddomain]`. Tec-Tac's UI is served from
`/tec-tac/` on the frontend host and opens `wss://` on the API host. nginx sends `Host` = the API host and passes `Origin` through. So the
browser's Origin (the frontend) never matched the Host (the API), and every terminal closed 4003. Tactical's own terminal consumers check no
Origin at all (`asgi.py` has no `AllowedHostsOriginValidator`), so the same-host check was an extra layer on top of Tactical.

1.17.32 accepts an Origin that equals a frontend origin from `CORS_ORIGIN_WHITELIST`, or `CORS_ALLOWED_ORIGINS` when present:

- Only exact http(s) origins count. A path, query, fragment, user name, `*`, `null`, a number, a regular expression or a space is ignored.
  The default port is the same as no port. The scheme must match.
- The list comes from server settings only. A failed settings read gives an empty list, so only the same-host rule applies.
- No Origin is still allowed. A `null`, empty or malformed Origin is still refused. The same-host rule is unchanged.
- The ticket, the sign-in re-check, the scope check, the audit row and the watcher are unchanged.

Conditions for the split-host layout (also in `docs/tactical-websocket.md`, "Split-host layout and nginx"): nginx passes `Upgrade` and
`Connection` on `^/ws/` and does not rewrite `Origin`; `Host` is the API host; the frontend origin is in `CORS_ORIGIN_WHITELIST`; Tec-Tac does
not accept a frontend origin that is not in that list. The real proxy and layout are not proved yet. That needs the dev-server steps in
`reviews/questions/core.md` (Core 1.17.32 note).

Tests: `tests/tactical-websocket-origin-1.17.32.py` (stub based, reuses the consumer test's fixtures). It covers the split host through
`connect()`, the foreign Origin, the scheme, the default and non-default ports, the rejected entry forms, empty, missing and failing
settings, the request-supplied headers, no Origin, null, no Host, `CORS_ALLOWED_ORIGINS`, and the 4003 contract text. It fails on 1.17.31 at
the split-host check.

## Browser contract rows (owed to the UI)

- `ui.authenticated.websocket`: operations, events, close codes and their messages, the ticket route with its body, answer and refusals,
  the 30 second single-use ticket, the bound-module rule, no `registerPublic`, at most 8 terminals, no reconnect, UI 0.12.102 and Core 1.17.31.
- `ui.authenticated.services`: `provide`, `has`, `call`, `list`; the name rule; the permission rules; the one-permission rule and its text;
  the refusal codes `service_denied` and `service_unavailable`; the lifetime rule.
- The details listed under "Module-facing changes" above.

`tests/browser-contract-rows-1.17.32.py` checks the new rows and details, and that the real `render_markdown` and `render_text` carry every row
with a plain docs path.

## Closes (reviews/requests/core.md)

- `ui.authenticated.popup: popupPublishers, the route-path rule and the popup warning (ui 0.12.97)`, and `popupPublishers is still not in the
  export (endpoints 0.6.0)`.
- `Contract rows for UI 0.12.99`.
- `Services and the header pop-up layer` and `register(context).context.user.id` (both in "from ui 0.12.101"). `Save all UI preferences` stays open.
- `ui.authenticated.websocket (UI 0.12.102)`, `from ui 0.12.102 (services rule)` and `Contract export check (ui 0.12.102)`.
- The stale `from reportmanager 0.5.4` and `from tacticalupdater 0.2.1` entries. The export `tec-tac-public-contract 1.17.30-0.12.101` lists
  `permissions_any`, `body_max_bytes`, `tacticalupdater.view` and `tacticalupdater.run`, so no code is needed.

`Possible Core defect: the Origin check` gains a status line: the code fix shipped, and only the dev-server confirmation remains open.
`Nginx: the terminal socket route` stays open. The server web terminal (CQ100) stays open for globalsettings.

## What changed

- `framwork/tec_tac/tactical_websocket_consumers.py`: `normal_origin()` and `configured_frontend_origins()` (new); `origin_allowed()` gains the
  configured-origin rule.
- `framwork/tec_tac/tactical_websocket.py`: the 4003 text in `tactical_websocket_contract_metadata()`.
- `framwork/tec_tac/contracts.py`: the two new browser rows and the details on the rows listed above. Both render functions are unchanged.
- `tests/tactical-websocket-runtime-1.17.32.py` (renamed from `-1.17.31.py` with `git mv`, then rewritten), `tests/runtime-script-imports-1.17.32.py`
  (new), `tests/tactical-websocket-origin-1.17.32.py` (new), `tests/browser-contract-rows-1.17.32.py` (new).
- `tests/browser-contract-catalog-1.15.170.py`: its pinned set of browser row ids gains the two new ids (the test asserts an exact set, so
  the two rows cannot land without it). Nothing else in that test changed.
- Header comments only: `tests/tactical-websocket-ticket-1.17.31.py` and `tests/tactical-websocket-consumer-1.17.31.py` name the 1.17.32 runtime file.
- `docs/tactical-websocket.md`: step 3 of "Open the socket", a "Split-host layout and nginx" section, and the Checks list.
- `docs/releases/RELEASE_NOTES_1.17.31.md`: the 1.17.31 notes moved here from the root, unedited (release-integrity wants one root note).
- `VERSION` and `tec_tac_package.json`: 1.17.32.

## Checks run on this PC

- `tests/runtime-script-imports-1.17.32.py`, `tests/tactical-websocket-origin-1.17.32.py`, `tests/browser-contract-rows-1.17.32.py`: pass.
- The existing stub tests `tests/tactical-websocket-ticket-1.17.31.py`, `tests/tactical-websocket-consumer-1.17.31.py` and
  `tests/tactical-websocket-route-1.17.31.py`: pass, unchanged except the header comments above.
- `tests/browser-contract-popup-confirm-1.17.23.py`, `tests/contract-browser-doc-cells-1.17.19.py`, `tests/browser-contract-catalog-1.15.170.py`
  (its pinned set updated, see above), `tests/browser-contract-runtime-surface-1.17.2.py`, `tests/f11-openapi-final-1.15.178.py` and
  `tests/f11-tracker-closure-1.15.184.py`: pass.
- The negative runs on the 1.17.31 tree: the import guard fails on `tests/tactical-websocket-runtime-1.17.31.py` (`channels.testing`), the
  origin test fails at the split-host check, and the contract row test fails on the missing websocket row.
- The full `tests/` folder run with `python -B`, before and after: the same pass/fail set apart from the renamed script and the three new tests,
  except `contract-export-1.17.18.py`, which reads the UI source. It fails here because `workspace/ui/src/main.js` (UI 0.12.102) indents
  `tacticalScope,` by six spaces, not the eight its check expects. No Core change caused it.
- `python -m py_compile` on every changed Python file, and `ruff check` with `pipeline/pyproject.toml`: no new findings in the new and changed
  code. The findings that remain were already in HEAD.

## Not run, and why

- Django, channels, asgiref, Redis, nginx, uvicorn and Tactical are not installed on this PC. The runtime probe, the real consumer, the real
  ASGI route, the watcher and the real proxy are unverified until the dev-server steps in `reviews/questions/core.md` (note of 14 October 2026) run.
- The release pipeline (pack, sign, AI review) was not run. This release is for `release-manager`.

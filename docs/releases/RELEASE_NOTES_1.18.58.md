# Tec-Tac Framework 1.18.58

Date: 26 November 2026. The Engineer Console can now find out which Tec-Tac web page to open for its sign-in, and a Network Probe tunnel ticket can require more than one permission. Core only. `main` stays held.

In plain words: the Console used to guess the web address from the host it enrolled with. On a split layout (API on one host, Tec-Tac pages on another) that guess is wrong. Core now tells the Console the right address. It takes it from a setting an administrator can set, or from the one https origin that Tactical's CORS settings already name. (CORS is the list of web pages Tactical allows to call its API.) Never from the request itself. Separately, a Network Probe custom session needs two permissions at once. Core can now check both, everywhere it checks one today.

## Module-facing change

`core.probe_transport` goes from 1.3.0 to 1.4.0. It is additive.

- `issue_tunnel_ticket` takes `permissions`, a list of 1 to 4 distinct `networkprobe.` permission codes that must all hold, next to the single `permission`. At least one of the two keys is required. If both are sent, `permission` must be in the list. Any other shape is `invalid` with code `invalid_spec`. Core checks every code at the ticket (`denied`, code `permission_missing`), at the Console connect (close 4401 `permission_missing`) and at every re-check: the 5-minute one, the 5-second access-marker tick and the re-check after `set_tunnel_site`. A person who loses any one of them ends the session `ended_by_core` with detail `permission_missing`.
- The single `permission` form is the compatibility path and behaves exactly as in 1.3.0. The ticket value and the session record keep `permission` (the first code of the list when only `permissions` was sent) and add `permissions`. A record made by 1.18.57 has no list and is read as its single `permission`, so a session open at the upgrade keeps working.
- The ticket audit row keeps `permission` and adds `permission_count` when there is more than one code. The list is never written.
- `networkprobe` is the only user of the operation. It sends the single `permission` today (0.2.29) and needs no change. It can adopt the list for a custom session; the request is in `reviews/requests/networkprobe.md`.
- The Tec-Tac web address is Core-internal: the `ui_url` key of the enrol answer, `GET /api/tfd/console-sessions/sign-in-info/` and the runtime setting `console_ui_url`. No capability changed for them and no module uses them (a grep of `modules/` finds no caller).

## Closes

- The ORDER "Core 1.18.58 = Console web address (ui_url) + tunnel permissions list" in `reviews/requests/core.md`, and its two source entries: "Console needs the Tec-Tac web address (UI host differs from the API host)" and "issue_tunnel_ticket takes a list of permissions that must all hold". The permission-list entry was filed twice (once by the networkprobe 0.2.29 run, once by the coordinator) and is built as one item. The release manager moves the entries; Core only names the version.
- The 1.18.57 review Low "the new regression tests passed on source checks only" is answered in part: the Django-dependent tests were run on this PC in the project's `.venv` (see "What could not be run here").

## What changed and why

1. **`ui_url` in the enrol answer.** `POST /api/tfd/console-certificates/enrol/` answers one more key, `ui_url`: the https address of the Tec-Tac web page, always ending `/tec-tac/`, or `null` when Core cannot name one. Enrolment never fails because of it, and the lookup never raises. Every earlier key is unchanged.
2. **`GET /api/tfd/console-sessions/sign-in-info/`.** For a PC that enrolled before this release. No sign-in, no cookie, read-only, answers exactly `{ui_url}`. https only (a request the proxy reports as http is `403 tls_required`). `Cache-Control: no-store` on every answer. 30 requests a minute per address (an IPv6 address counts by its /64), then `429 rate_limited` with `Retry-After: 60`. A cache fault reads as "not limited" and is logged, because the answer holds no user data. No audit row, nothing about any user. When no address can be named: `503 ui_url_unavailable` with a plain message (fail closed).
3. **Where the address comes from.** In this order: (a) the runtime setting `console_ui_url` when an administrator set it; (b) otherwise the single https origin in Tactical's CORS settings (`configured_frontend_origins`) plus `/tec-tac/`. None or several https origins give "unavailable". A stored setting that fails validation (database tampering) is "unavailable", never a silent fall-back to CORS. Core never reads it from the request's `Origin`, `Referer`, `Host` or query string. The older `_tec_tac_ui_url` in `views.py`, which does trust the request, is not used here and not changed.
4. **The runtime setting `console_ui_url`.** Text, https only, a host (and a port), no user info, no query or fragment, and a path of nothing, `/`, `/tec-tac` or `/tec-tac/`. Always stored as the origin plus `/tec-tac/`, at most 300 characters. `null` or empty text resets it. Superuser only, checked before the value, with a deny row on refusal; one strict audit row per change; a failed audit write rolls the change back. Shown in `GET` as `{value, maximum_length: 300, default: ""}`.
5. **Migration `0052_console_ui_url`.** One new column on `TecTacRuntimeConfig`: `console_ui_url` (300 characters, blank, empty default). It depends on `0051_console_enrolment_pkce` only. Written by hand, in the shape of 0051, because `makemigrations` cannot run on this PC. It equals the model (checked by Django's own autodetector, see below).
6. **The permission list.** See "Module-facing change". The code is in `probe_tunnel.py` (`_clean_spec`, `issue_ticket`, `_permissions_of`, `account_refusal`, `console_open`, `console_recheck`). `account_refusal` takes one code or a list and refuses an empty one. `CAPABILITY_VERSION` is `1.4.0`; `permission_count` joins `TUNNEL_AUDIT_KEYS`.
7. **Docs and contract text.** `docs/console-certificates.md` (the enrol answer), `docs/console-sessions.md` (the new route, its errors, the setting, the limits table), `docs/runtime-settings.md`, `docs/probe-transport.md` ("Permission lists (1.4.0)"), `docs/capabilities.md`, and `contracts.py` (the new route row, the enrol answer, the runtime settings rows, the `issue_tunnel_ticket` text, the Core-internal note). Two sentences that said `core.probe_transport` "stays at 1.3.0" now say what is true.
8. **Harness.** `tests/console_certificates_harness.py` stands in for `fcntl` when Windows lacks it, so the Django-dependent tests can run on this PC.

## Assumptions

Recorded as information in `reviews/questions/core.md`. None blocks this release.

- Only https origins count for the CORS fallback; an extra http entry does not make it ambiguous. Two https origins, or a regular expression or allow-all entry alone, give "unavailable".
- The address has no other path than `/tec-tac/`. Say if a proxy mounts it elsewhere.
- `ui_url: null` and `503 ui_url_unavailable` write no audit row.
- Only a superuser sets `console_ui_url`. A wrong address cannot complete a sign-in, because the code still needs the PKCE verifier and the PC's certificate proof.
- `permission` and `permissions` combine as described above; the audit row writes the count, never the list.
- **The plan was wrong in two places, and the code follows the code.** (1) It said a lost permission ends a session with detail `permission_lost`. The code has always used `permission_missing` for this (pinned by `tests/tunnel-scope-recheck-1.18.50.py`), so that stays; docs and tests say `permission_missing`. (2) It said every named file is CRLF. Only `contracts.py`, `models.py` and `docs/capabilities.md` are; the rest are LF. Each file keeps the line endings it had, and the new migration is LF like 0051.
- The 1.18.57 release notes moved to `docs/releases/`, as the 1.18.56 notes did.
- `tests/console-sessions-isolation-1.18.56.py` said no module used the Console-session capability yet. `networkprobe` has used it since its M1, so that check now says only `networkprobe` may.

## New tests

- `tests/probe-tunnel-permissions-1.18.58.py`: on the in-memory harness with the real tunnel code. The single form unchanged; two codes issue only when both hold, in both orders (one deny row, no slot, no rate budget when one is missing); the connect refuses a person who lost either; a live session ends at the next 5-second tick after the access marker and at the 5-minute re-check when either is lost, and an unrelated permission ends nothing; eighteen invalid shapes are `invalid_spec`; a 1.18.57-style value and record still connect and re-check; a malformed list fails closed; the audit row has `permission_count` and no list; `CAPABILITY_VERSION` is 1.4.0 and the operations are unchanged; docs and contract rows name 1.4.0 and the compatibility path.
- `tests/console-ui-url-1.18.58.py`: the setting wins over CORS; one https CORS origin gives origin + `/tec-tac/`; two, none, only http, a regular expression or allow-all alone, and a settings fault give null in the bundle and `503 ui_url_unavailable` on the route; an invalid stored value is unavailable and does not fall back; a request with another `Origin`, `Referer`, `Host` or `?ui_url=` changes nothing; no sign-in; `no-store` on 200, 403, 429 and 503; forwarded http is 403; the 31st request in a minute is 429 with `Retry-After`; IPv6 by /64; a cache fault does not raise; no audit row; exactly one key; the enrol answer keeps every earlier key and adds `ui_url` (also null); the route is the only new unauthenticated pattern.
- `tests/console-ui-url-setting-1.18.58.py`: the validator (accepts `https://host`, `https://host:8443/tec-tac`; refuses http, ftp, user info, query, fragment, other paths, 301 or more characters, non-text, bool); null and empty reset; a non-superuser gets 403 and a deny row before any value check; a mixed body saves nothing; one strict audit row per change and a failed audit write rolls back; the serialised value and default; migration 0052 equals `models.py` (AST, and Django's autodetector) and depends on 0051.
- Changed so they keep passing without weakening: `console-certificates-setting-1.18.52.py` and `console-enrolment-pkce-1.18.57.py` (the migration comparison includes 0052), `console-certificates-enrol-1.18.52.py` (the bundle gains `ui_url`), `console-sessions-isolation-1.18.56.py` and `console-sessions-capability-1.18.56.py` (six routes; the open-route check now names both open routes), `console-sessions-docs-1.18.56.py`, `probe-transport-contract-1.18.47.py` and `probe-transport-docs-1.18.47.py` (1.4.0).
- `tests/version-1.18.58.py`: version, notes, headings, the checklist, the new tests in `release-integrity.sh`, the new code strings and the line endings. The 1.18.57 version test moved to `tests/legacy/`.

## What could not be run here

Django 6.1.2 and `cryptography` are in the project's `.venv` on this PC, so the Django-dependent tests ran (real views and models on SQLite, Django's migration autodetector) with `d:\Visual Studios\Vibe Coding\Tec-Tac Project\.venv\Scripts\python.exe`. The release-integrity run is in the commit report. Not run, because they need the dev server: `manage.py makemigrations --check` with Tactical's other apps, PostgreSQL, Redis, Celery, Knox and a real uvicorn. `tests/release-integrity.sh` itself needs a Linux `python3`; the same tests ran one by one with the `.venv` interpreter. `ruff` has no config file in this repository; its default rules ran, and the changed files add no new finding compared with the previous version of the same files.

## Johan dev02 checklist

You need a test engineer who may enrol a Console, and `examples/console-session-client.py` (Python 3.10 or newer, `pip install cryptography`) as in the 1.18.57 checklist. Core 1.18.58 and migration 0052 must be on dev02, with the web workers and the ASGI service restarted.

**1. `ui_url` in the enrol answer.** Enrol a test PC with the example client (`enrol`). PASS: the answer holds `ui_url`, and it equals dev02's real frontend https host plus `/tec-tac/` (the host that Tactical's CORS settings name, for example `https://tcrm.techxflow.net.za/tec-tac/`). Every other key is as before. FAIL: no `ui_url`, a different host, an http address, or `enrol` fails. Send back: the answer without the code, key or certificate values, and the CORS lines from dev02's Tactical settings.

**2. `sign-in-info/` with no sign-in.** Run `curl -i https://<dev02 API host>/api/tfd/console-sessions/sign-in-info/` with no header. PASS: HTTP 200, the body is exactly `{"ui_url": "..."}` with the same address as step 1, and the headers include `Cache-Control: no-store`. FAIL: a 401 or 403, another key, or no `no-store`. Send back: the full curl output.

**3. The setting.** As a superuser, `PATCH /api/tfd/system/runtime-settings/` with `{"console_ui_url": "https://example.org"}`. PASS: HTTP 200 and the value is `https://example.org/tec-tac/`; step 2 now answers that address; the audit log has one `modify` row for `console_ui_url`. Then send `{"console_ui_url": null}`: the value is empty and step 2 answers the CORS address again. As a person who may manage runtime settings but is not a superuser, the same PATCH is 403 with a deny row. `http://example.org` and `https://example.org/other/` are 400. FAIL: any other status, or the address does not follow the setting. Send back: the four answers and the audit rows.

**4. No address can be named.** With no setting, put a second https origin into Tactical's CORS settings (and restart Tactical's web workers), so two https origins are named. PASS: `sign-in-info/` answers HTTP 503 with code `ui_url_unavailable` and a plain message, and a new enrol answer has `ui_url: null`. Put the CORS lines back afterwards and restart. FAIL: Core names one of them. Send back: the 503 body and the enrol answer.

**5. The rate limit.** Send 31 requests to `sign-in-info/` within a minute from one machine (for example `for i in $(seq 1 31); do curl -s -o /dev/null -w "%{http_code}\n" https://<dev02 API host>/api/tfd/console-sessions/sign-in-info/; done`). PASS: the first 30 print 200 and the 31st prints 429 (`curl -i` shows `Retry-After: 60`). FAIL: no 429. Send back: the 31 codes.

**6. The permission list.** A Network Probe custom session cannot be tested until `networkprobe` adopts the list. Test it with a small script through the capability, or the example harness: ask for a ticket with `permissions: ["networkprobe.tunnel", "networkprobe.tunnel_custom"]` for a test engineer who holds both. PASS: the ticket is issued; remove one of the two permissions from the test role and a live session ends within about 10 seconds with end detail `permission_missing`; a ticket asked for with only one of them held is `denied` with code `permission_missing`. Also confirm the single-permission form still works through networkprobe 0.2.29 unchanged (open a normal tunnel). FAIL: the ticket is issued without one of the permissions, the session survives the removal, or a normal tunnel fails. Send back: the answers and the audit rows (`custom:probe-tunnel-ticket` carries `permission_count`).

## Not in this release

The Core UI field for `console_ui_url` (a UI request), the Engineer Console reading `ui_url` and `sign-in-info/` (a probe-developer request), and `networkprobe` adopting the permission list (a networkprobe request). The older `_tec_tac_ui_url` in `views.py` is not changed. Each waits on this release.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.

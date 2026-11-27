# Tec-Tac Framework 1.18.59

Date: 27 November 2026. The Engineer Console can now call a Tactical-routed Network Probe route without being refused as a replay. Core only. `main` stays held.

In plain words: Tactical runs its own audit step on a request before the view sees it. That step asks Django REST Framework (DRF, the layer that checks who is calling) to authenticate the request, and then the view asks again. Core checked the Console's signed proof both times. The second check found the one-time number (the nonce) it had just stored and refused the request as `proof_replayed`. Core now checks the proof once per HTTP request and gives the same answer to the second ask.

## Module-facing change

No capability, route, class name, signature or version changed. `core.console_session` stays 1.0.0.

- Behaviour inside `ConsoleSessionAuthentication.authenticate()` changed: a second pass over the same request object returns the first pass's answer, the same user or the same refusal. A module that lists the class (only `networkprobe` does, in `console.py` and `channel.py`) needs no change. Its Tactical-routed Console views now succeed.
- A request sent again is a new object. It has no stored answer and is still refused `proof_replayed`.
- One note was added to the `ConsoleSessionAuthentication` entry in the public contract and one sentence to `docs/console-sessions.md`.

## Closes

- The ORDER "Core 1.18.59 = Console request proof checked once per request" in `reviews/requests/core.md`, and its source entry "Console request proof refused as replayed on every Tactical-routed request" (from Engineer Console 0.1.6). The release manager moves the entries; Core only names the version.

## What changed and why

1. `authenticate()` now looks at the Django request behind the DRF request (`_request`). A fingerprint of the request holds the `Authorization` header, the `X-Tectac-Console-Proof` header, the method and the full path. The outcome of the first pass is stored on that object under `_tectac_console_auth_result`: `ok` with the user and `ConsoleAuth`, or `refused` with the exception.
2. A second pass with a matching fingerprint returns the stored user, or raises the stored refusal. It writes no nonce, makes no second lookup chain and writes no second row-end or audit row.
3. A refusal is never turned into an accept. The second pass also keeps the real code (for example `session_revoked` or `account_inactive`) instead of a misleading `proof_replayed`.
4. If the fingerprint differs, the stored answer is ignored and the full check runs. It then fails closed as replayed.
5. When the header is not the `TecTacConsole` scheme, `authenticate()` returns `None` and stores nothing, so other authenticators decide as before.
6. The stored answer lives only on the in-memory request object: nothing in the cache, the database or the logs, and no token or key beyond what the request already holds. The old body of `authenticate()` is now `_authenticate_once()`, unchanged.
7. `ConsoleSessionAuthenticated` is untouched. The activity touch and `tec_tac_session` stay in its `has_permission`, which runs once in the view. `NONCE_SECONDS`, the proof bytes and the capability version did not change. `/api/tfd/` is not excluded from Tactical's middleware.

## Assumptions

Recorded as information in `reviews/questions/core.md`. None blocks this release.

- The middleware path is tested with a stand-in, because Tactical's `AuditMiddleware` cannot be imported here and `reference/` is read-only. The dev02 checklist is the proof through the real middleware.
- A refused first pass is stored and re-raised on the second pass. Only DRF API exceptions are stored; any other fault is not, so a second pass runs the full check and fails closed.
- Housekeeping: `RELEASE_NOTES_1.18.58.md` moved to `docs/releases/` and `tests/version-1.18.58.py` to `tests/legacy/`, as 1.18.57 did.

## New tests

- `tests/console-sessions-once-per-request-1.18.59.py`: source checks (the stored attribute, the fingerprint, no cache or database use for it, `ConsoleSessionAuthenticated` untouched, the doc sentence and contract note, `core.console_session` 1.0.0) and, on the real Django harness: a signed request through the middleware stand-in and then the view on the same request gives 200, one nonce and no second audit row; the same request re-sent is `proof_replayed`; a refused first pass (bad signature, revoked session, inactive account, expired certificate, stale proof, nonce store fault 503) stays refused with the same code and a refusal before the nonce stores none; two requests with fresh nonces both pass; changed headers on the same object are not served from the stored answer; a non-Console header returns `None` and stores nothing.
- `tests/version-1.18.59.py`: version, notes, headings, the checklist, the new tests in `release-integrity.sh` and line endings.
- Every existing Console proof and guard test runs unchanged. None was weakened, skipped or given an exception.

## What could not be run here

Django 6.1.2 and `cryptography` are in the project's `.venv`, so the Django-dependent tests ran there. Tactical's real middleware, PostgreSQL, Redis and a live dev02 Console cannot run on this PC. `ruff` has no configuration in the repo.

## Johan dev02 checklist

Update dev02 to Core 1.18.59 from dev, restart the web workers and the ASGI service. Use Engineer Console 0.1.6.

**1. Signed in for 3 minutes.** Sign in with the Console and use it for 3 minutes: filters, the device list and refresh. PASS: every call answers 200 and you are never signed out. FAIL: any call answers 401 `proof_replayed`, or you are signed out. Send back: the time and the Console log.

**2. No replay rows.** Open the audit log for the Console session. PASS: no `proof_replayed` refusal for your own calls. FAIL: one or more rows. Send back: the rows.

**3. A re-sent request.** Send one signed request with the example client, then send the same bytes again. PASS: the first is 200 and the second is 401 `proof_replayed`. FAIL: the second is accepted. Send back: both answers.

**4. Revoke still works.** Revoke the Console session from the Tec-Tac sessions page, then make a call. PASS: 401 `session_revoked`. FAIL: any other answer. Send back: the answer.

## Not in this release

The wrong path in the worked example of `docs/console-sessions.md` (`/api/tfd/networkprobe/console/connect/` should read `/api/tfd/network-probe/`). It sits inside the signed proof sample and a pinned byte test, so it waits for a later release. Every other open request in `reviews/requests/core.md` and the held findings stay as they were.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.

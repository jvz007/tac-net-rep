# Tec-Tac Framework 1.18.57

Date: 26 November 2026. The Engineer Console can now enrol over a loopback address with PKCE, and a Console session of a deactivated account is refused by the authentication class itself. This is C2 of the Engineer Console sign-in plan (Johan, 26 November 2026) plus the held Low of the 1.18.56 review. Core only. `main` stays held.

In plain words: the browser can hand an enrolment code to the Console through the engineer's own PC. PKCE (a one-time secret that only the Console knows) makes sure the code can only be used by the app that asked for it. A second program on the same PC that sees the code cannot use it. The command-line client, and the Console as it is today, keep working without PKCE.

## Module-facing change

None. No module calls the two routes that change, and no capability version changes.

- `POST mine/enrolment-code/` and `POST enrol/` under `/api/tfd/console-certificates/` gain optional fields (`code_challenge`, `code_verifier`). Both routes are Core-internal: no module has any use for them (a grep of `modules/` finds no caller). A request without the new fields behaves byte for byte as before.
- `ConsoleSessionAuthentication` (capability `core.console_session` 1.0.0) now also refuses an inactive, blocked or installer account itself (`401 account_inactive`, the session ends). This only tightens behaviour. The class name, headers and answers are unchanged. No module serves the Console yet; `networkprobe` M1 is the first user, and it lists the class together with `ConsoleSessionAuthenticated`, which already did this check.
- `core.console_session` stays 1.0.0 and `core.probe_transport` stays 1.3.0.

## Closes

- The ORDER "Core 1.18.57 = C2 enrolment over loopback with PKCE, plus the held 1.18.56 Low" in `reviews/requests/core.md`. The release manager moves the entry; Core only names the version.
- Held Low of the 1.18.56 review: `ConsoleSessionAuthentication` returned an inactive or blocked user (only the permission class refused it). Remove it from `reviews/core/BACKLOG-new-findings.md` once 1.18.57 is signed.

## What changed and why

1. **PKCE on the enrolment code.** `POST mine/enrolment-code/` accepts an optional body `{"code_challenge": "<43 base64url characters>"}`. The challenge is `base64url(SHA-256(verifier))` without padding, S256 exactly as in `docs/console-sessions.md`. Any other key is `400 unknown_field`; a challenge of any other shape is `400 invalid_request` and nothing is stored. An empty body is today's behaviour. Core stores the challenge in the same update that stores the code's hash, so a new code replaces the old challenge, and a code asked for without a challenge has none. The answer keeps its exact keys. The audit row `custom:console-cert-enrol-code` gains `pkce: true|false` and never holds the challenge.
2. **The verifier on enrol.** `POST enrol/` accepts an optional `code_verifier` (43 base64url characters) next to the four required keys. The enrol proof message (`tectac-console-enrol-v1`) did not change, so the CLI client and the existing Console keep working. The code is still burnt first by the one conditional update (which also clears the challenge). Then, after the account check and before the key checks, Core compares `base64url(SHA-256(verifier))` with the stored challenge in constant time. A wrong or missing verifier, or a verifier for a code that had no challenge, is `401 verifier_invalid`. It counts as a failure, writes at most one `custom:console-cert-enrol-refused` row per address per minute under the engineer (reason `verifier_invalid`, never the verifier), and the code stays burnt. The 7-day enrolment stays open, so the engineer presses Enrol again. A badly shaped verifier is `400 invalid_request` before the code is looked at, and the code is not burnt.
3. **Migration `0051_console_enrolment_pkce`.** One new column, `code_challenge` (43 characters, blank, empty default) on `core_console_enrolment`. It depends on `0050_console_sessions` only. Written by hand, because Django cannot run `makemigrations` here. Every place that clears `code_hash` (the burn, administrator authorise, cancel, the expiry sweep and the CA replace) now clears `code_challenge` too.
4. **The class refuses a bad account itself.** `ConsoleSessionAuthentication.authenticate()` now calls `account_problem(user)` after the proof, window and nonce checks. A problem ends the Console session (`account_inactive`) and answers `401 account_inactive`, the same code and message as the permission. An unsigned or badly signed request can never end a row. The permission keeps its own check (defence in depth).
5. **Docs, contract text and the stand-in client.** `docs/console-certificates.md` has the new steps, the exact body and the new error. `contracts.py` carries both route entries and one note on the `ConsoleSessionAuthentication` entry. `docs/console-sessions.md` has one sentence. `examples/console-session-client.py` gains `pkce` (prints a verifier and its challenge) and `enrol --verifier`, so the dev02 checklist can run before the Console app exists.

## Assumptions

Recorded as information in `reviews/questions/core.md`. None blocks this release.

- The verifier travels in the enrol body as an optional key, and the proof message is unchanged. A proof line that binds the verifier would break the existing proofs. The verifier travels over the same TLS request as the proof.
- A verifier with no stored challenge, and a stored challenge with no verifier, both refuse with `401 verifier_invalid` after the code is burnt. A client that cannot say what it holds asks for a new code.
- A wrong verifier gets its own `verifier_invalid`, not `code_invalid`. Only someone who already held a valid code can reach it, so it reveals nothing, and it lets the Console show the right message.
- The account check runs before the verifier check, so an inactive account still gets `account_inactive` as before.
- The new migration file is LF, like `0050`. (The plan said CRLF; `0050` and the version test pin LF for it.)

## New tests

- `tests/console-enrolment-pkce-1.18.57.py`: migration 0051 against the model (field for field, and Django's autodetector where Django is installed); right and wrong verifier, missing verifier, verifier with no challenge, no challenge and no verifier (CLI path), a new code clearing an older challenge, malformed challenge and verifier, API key refusal, the refusal row and the limiter, no secret in any row, log line, answer or database dump; docs and contract text.
- `tests/console-sessions-authenticate-account-1.18.57.py`: the class alone refuses a deactivated, dashboard-blocked and installer account and ends the row; an active account passes; a bad proof does not end a row; a route that pairs the class with `SessionAuthenticated` refuses it.
- `tests/console-sessions-example-client-1.18.57.py` (the 1.18.56 test, extended): `pkce`, and `enrol --verifier` right and wrong.
- `tests/console-certificates-setting-1.18.52.py` (changed): it compares migration 0049 plus the later `AddField` in 0051 with `models.py`, because 1.18.57 adds `code_challenge` in 0051.
- `tests/version-1.18.57.py`: version, notes, headings, line endings, the new tests listed in `release-integrity.sh`. The 1.18.56 version test moved to `tests/legacy/`.
- Unchanged and expected to pass: `console-certificates-enrol-1.18.52.py`, `console-certificates-routes-1.18.52.py`, `console-certificates-apikey-1.18.53.py`, `console-certificates-actor-1.18.55.py`, `console-sessions-request-proof-1.18.56.py`, `console-sessions-revoke-1.18.56.py`.

## What could not be run here

Django is not installed on this PC. The parts of the new tests that need it (the real views on a SQLite file, the autodetector) exit early with a note, so only the source, migration, docs and contract checks ran. The old Console tests that boot Django skip for the same reason. Not run: `makemigrations --check`, PostgreSQL, Knox, Celery and Redis. The dev02 checklist carries the real proof.

## Johan dev02 checklist

You do not need the Console app. Use `examples/console-session-client.py` (Python 3.10 or newer and `pip install cryptography`). In Tec-Tac, allow a test engineer to enrol a Console (Console certificates). Sign in as that engineer in the browser. For the code request you need the `Authorization` value of that browser (developer tools, Network tab, any `/api/` request, the `Authorization` header, which looks like `Token abc...`). Use `--insecure` only if dev02 has a self-signed certificate.

**1. The old path still works.** Ask for a code with no challenge: `curl -k -X POST -H "Authorization: <value>" -H "Content-Type: application/json" -d "{}" https://<dev02 host>/api/tfd/console-certificates/mine/enrolment-code/`. Then run `python console-session-client.py keygen --key console.pem` and `python console-session-client.py --insecure enrol --server <dev02 host> --code <code> --key console.pem --label "Test PC" --state state.json`. PASS: the answer has the same keys as before (no new key), and `enrol` says "Enrolled". FAIL: any error. Send back: both outputs (not the code).

**2. PKCE, the right verifier.** Run `python console-session-client.py pkce` and keep the two lines. Ask for a code with the challenge: the same curl with `-d "{\"code_challenge\": \"<challenge>\"}"`. Then `enrol ... --verifier <verifier> --label "Test PC 2" --state state2.json`. PASS: the code request is HTTP 200, `enrol` says "Enrolled". FAIL: any other status. Send back: both outputs (not the code or the verifier).

**3. A wrong verifier.** Run `pkce` again, ask for a code with its challenge, then run `enrol` with a different verifier (take it from another `pkce` run). PASS: HTTP 401 `verifier_invalid`. Then run `enrol` again with the right verifier and the same code: HTTP 401 `code_invalid` (the code is burnt). The audit log shows one `custom:console-cert-enrol-refused` row under the engineer with reason `verifier_invalid` and no secret. Asking for a new code works. FAIL: the wrong verifier enrols, the burnt code still works, or the row holds a code or verifier. Send back: the three outputs and the audit row.

**4. A verifier with a code that had no challenge.** Ask for a code with an empty body, then run `enrol` with `--verifier <any pkce verifier>`. PASS: HTTP 401 `verifier_invalid`. FAIL: it enrols. Send back: the output.

**5. A deactivated engineer.** Sign in with the example client (`authorise`, `signin`) as a test engineer, as in the 1.18.56 checklist. Deactivate that engineer in Tec-Tac, then run `current --state state.json`. PASS: HTTP 401 `account_inactive`, and Access > sessions no longer lists the session (it ended with reason `account_inactive`). FAIL: HTTP 200. Send back: the output and the sessions list.

## Not in this release

The Core UI pages for sign-in and enrol (`#/console/sign-in` and `#/console/enrol`, UI 0.13.8), the `networkprobe` Console routes (M1), the Engineer Console app (E5, Console 0.1.4), the tunnel check-in, the access-changed event for declared modules and the tunnel end detail key are not in this release. Each belongs to another area and waits on this one. UI 0.13.8 can require Core 1.18.57.

## Main stays held

`main` stays at Core 1.17.110. Only Johan promotes.

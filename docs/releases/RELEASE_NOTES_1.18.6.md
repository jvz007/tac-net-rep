# Tec-Tac Framework 1.18.6

Date: 18 November 2026. This release adds one read-only operation: the address of a request, as Core itself works it out. securityWAF asked for it.

## What changed and why

* **New operation `tec_tac.client_address.client_address(request) -> str`.** A module can now ask Core who the caller is, by address, without reaching into Core's private code. It calls `session_security.effective_client_ip(request)` with no policy argument. The same stored `trusted_proxies` (default: loopback only) and the same parsing apply: `X-Forwarded-For`, then `Forwarded`, then `X-Real-IP`, every hop walked right to left and trusted before the address to its left is accepted. A peer that is not a trusted proxy always gives its own address.
* **It adds no trust.** No route, no table, no audit row, nothing changes. It reports the caller's own request. There is deliberately no `policy` argument, because a module that passed its own proxy list would widen trust.
* **It fails closed.** A request without `META`, a non-request object, no peer address or any internal error returns `''` and never raises. A consumer must treat `''` as unknown and refuse.
* **New capability `core.client_address` 1.0.0** (module `core`, operation `client_address`, needs framework `>=1.18.6`). A module feature-detects it with `has_capability('core.client_address')` and lists it under `dependencies`. It is registered in `apps.py` inside a try/except, like `core.secrets`, so a fault never stops start-up.
* **`core.session_security` stays at 2.0.0.** `install.sh` and the contract-version test pin it, and the new capability leaves it alone. `session_security.py` is not changed.
* **Cost.** One read of the session policy per call. Every signed-in request already does that read. No cache.
* **Docs.** New `docs/client-address.md`, an entry in `docs/capabilities.md`, one row in the contract catalogue (`area client-address`) and one sentence in the module rules.
* **Housekeeping.** `RELEASE_NOTES_1.18.5.md` moved to `docs/releases/`; `tests/version-1.18.5.py` moved to `tests/legacy/`.

Known limit: behind Nginx the answer is the real address only if Nginx forwards `X-Forwarded-For` or `X-Real-IP` from the loopback peer (the same thing Core's session IP-change check already relies on). If it does not, the answer is `127.0.0.1`. A consumer such as securityWAF must also refuse to treat a loopback or private-proxy answer as the person's address. Checklist step 7 collects the Nginx lines.

## Requests closed

"From securityWAF (18 November 2026)" in `reviews/requests/core.md`. The release manager removes it after signing, naming 1.18.6.

## Module-facing

Additive only. No existing contract, capability, route or import changed, and no module needs a change to keep working.

* New capability `core.client_address` 1.0.0 and one new contract row, `tec_tac.client_address client_address`. The public contract export needs a fresh run to show it; the newest file in `docs/contracts/` is older.
* securityWAF 0.5.5 may now list `core.client_address` under `dependencies` and switch adding a block back on. That is its own next patch.
* A grep of `modules/` found one other address helper: userinvite's `_client_ip` (`REMOTE_ADDR` only, by design for its rate limits). It is unaffected and is not asked to change.

## Assumptions (also in `reviews/questions/core.md`)

* The operation is a new capability in a new file, not a new operation on `core.session_security`, to avoid a bump that ripples into `install.sh`.
* It takes no policy argument and adds no caller check, because it reports only the address of the request the module already holds.

## What is not in this release

* Every other open request in `reviews/requests/core.md`, including the networkprobe `secret_store.put_if_absent` (Low, optional; the module's own lock covers it), the import-time performance request and per-endpoint request counts in diagnostics.
* The held findings in `reviews/core/BACKLOG-new-findings.md`. They touch `install.sh` and the update helper, not this code.
* Switching userinvite to the new operation. That is the module's own decision.

## Checks run here

`tests/client-address-1.18.6.py`, `tests/version-1.18.6.py`, `tests/session-security-contract-version.py`, the contract catalogue tests, `tests/caller-identity-1.17.21.py`, `python -m py_compile` on the changed files, `ruff check`, and `bash tests/release-integrity.sh`.

Could not run on this PC: Django, the real capability registry, and a request through Nginx. The test runs Core's real resolver functions (cut out of `session_security.py` by `ast`) with a stub for the policy read.

Line endings: `apps.py`, `contracts.py` and `capabilities.md` are CRLF in the repository and stay CRLF. The new files are LF.

## Johan test checklist (dev02)

Paths come from `install.sh`: `TACTICAL_ROOT` defaults to `/rmm`, Python is `/rmm/api/env/bin/python`, `manage.py` is `/rmm/api/tacticalrmm/manage.py`. Run the shell steps as the Tactical user (the user `rmm.service` runs as; shown as `<tactical user>`).

1. Update the server to Core 1.18.6.
2. Run:
   `sudo -u <tactical user> /rmm/api/env/bin/python /rmm/api/tacticalrmm/manage.py shell -c "from django.test import RequestFactory; from tec_tac.client_address import client_address; r=RequestFactory().get('/', REMOTE_ADDR='127.0.0.1', HTTP_X_FORWARDED_FOR='203.0.113.9'); print(client_address(r))"`
   * PASS: it prints `203.0.113.9`.
   * FAIL: it prints `127.0.0.1` or an error. Send the output and `manage.py tectac_session_policy --show`.
3. Run the same command with `REMOTE_ADDR='198.51.100.7'` and the same `HTTP_X_FORWARDED_FOR='203.0.113.9'`.
   * PASS: it prints `198.51.100.7`.
   * FAIL: it prints `203.0.113.9`. That means header spoofing works. Send the output and `manage.py tectac_session_policy --show`.
4. Run it with `client_address(object())` and with `client_address(None)`.
   * PASS: it prints an empty line each time and raises nothing.
   * FAIL: a traceback or any address. Send the output.
5. In the shell, run `from tec_tac.capabilities import has_capability, capability_status; print(has_capability('core.client_address'), capability_status('core.client_address')['capability_version'])`.
   * PASS: `True 1.0.0`.
   * FAIL: `False`, or another version. Send the output and the Core log lines containing `client_address`.
6. Export a fresh public contract and open the file.
   * PASS: the row `tec_tac.client_address client_address` is present.
   * FAIL: the row is missing. Send the export file name and the Core version it shows.
7. Optional: with a real browser through Nginx, check the address against the IP column for your own session on the Sessions page. Look at the Nginx site file for the `proxy_set_header X-Forwarded-For` and `X-Real-IP` lines.
   * PASS: the same address shows, and the Nginx lines are present.
   * FAIL: the answer is `127.0.0.1` for your own browser. Nginx is not forwarding the address. Send the `proxy_set_header` lines and the Sessions page IP.

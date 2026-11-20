# Tec-Tac Framework 1.18.27

Date: 20 November 2026. core.sandbox gets its readiness gate. The kill switch (`SANDBOX_ENABLED = False`) stays OFF (AD-65's switch-on condition is not recorded as met; see Fixed after review). The build also fixes the two findings held from the 1.18.26 review, because the own-name DNS check must be right before any run can start. `main` stays held.

## Module-facing change

`core.sandbox` gets its readiness gate and stays switched off. The change is additive and the capability goes from 1.0.0 to 1.1.0.

- `status()` still answers `enabled: False` (the shipped constant). It has one new key, `active`, which is `enabled and ready`. Every existing key keeps its name and meaning. `reason` stays the plain selftest reason (`selftest_not_run`, `status_unreadable` or the failing check).
- `start()` and `run()` have a new error code, `sandbox_not_ready` (HTTP 503 on the route). A server whose root selftest is not ready refuses every run with it. Core writes one `sandbox.run.refused` audit row and never starts the helper. `sandbox_unavailable` stays for the helper's own refusals at run time (its own names, the egress door, the skeleton).
- `cancel()` is not gated by readiness. A live run can always be stopped.
- A module can now declare `sandbox_runners` with `allowed_hosts` and require `framework >=1.18.27` to use the gate once the switch is on. The registration rule is unchanged (`requires.framework >=1.17.116`, publisher permission `sandbox.register`, which an administrator grants).
- There is no admin toggle, no new permission and no new route.
- Nothing in `modules/` uses `core.sandbox` yet. A search of `modules/` finds `ai` only in comments, release notes and an `OS_SANDBOX_AVAILABLE` flag, and `certificatemanagement` only in release notes. No module handles `sandbox_disabled` or `sandbox_not_ready`, so no compatibility path is needed. The request for `ai` is filed in `reviews/requests/ai.md`.

Two operator-facing changes: the Core installer's self-check expects `enabled` to equal the shipped constant (False) and `start()` from Core code to be refused with `sandbox_disabled` (nothing is launched; the check follows the constant, so it expects `not_owner` once the switch is on); and a server whose selftest is not ready still installs, with the same warning as before.

## Closes

- The readiness gate of AD-65 (`sandbox_not_ready`). The kill switch stays off, fail closed.
- Held Medium of the 1.18.26 review (`sandbox-helper.py`, own-name DNS): a name counted as answered when only one of its two queries answered.
- Held Low of the 1.18.26 review (`sandbox-helper.py`, DNS reply source): the reply source was compared as text to the `resolv.conf` line.

## What changed and why

### 1. The readiness gate (the switch stays off) (`sandbox.py`, `sandbox-helper.py`, `sandbox-selftest.py`, `sandbox_views.py`)

- `SANDBOX_ENABLED = False` in `framwork/tec_tac/sandbox.py` and in `scripts/sandbox-helper.py`, so every call is refused with `sandbox_disabled` before anything is read. The helper's constant is the one that counts. Both files keep their constants; nothing reads a setting. The text below describes the gate as it behaves once the switch is on, and the tests prove it with the constant patched on.
- Readiness is read fresh on every call, with no cache. In Core, `start()` and `run()` check the caller and the runner first, then call `status()`. If `ready` is not `True` they write one non-strict `sandbox.run.refused` row (code `sandbox_not_ready`, a new run id, the runner, the owner) and raise `SandboxError('sandbox_not_ready', ...)` with the status reason in the text. The helper is never started.
- The helper checks again, so a Django bug cannot skip the check. `ready_status()` raises `Refusal('sandbox_not_ready')` for a missing, unreadable or not-ready `status.json`, and keeps the `skeleton_changed` reason text. `launch()` already calls it first. A refused start is also written to the helper's own log as `start.refused` with the code only.
- `cancel()` and `cancel_by_person()` keep only the kill-switch constant check. Readiness does not gate them (see Assumptions).
- `read_status()` no longer forces `enabled` to False. `sandbox-selftest.py` writes `enabled` from the helper's constant. The value in the status file is information only.
- `sandbox_views.py` maps `sandbox_not_ready` to 503.
- `contracts.py` (CRLF kept), `docs/sandbox-capability.md` and `sandbox_contract_metadata()` are rewritten: no more "switched off", the new code, the `active` key, and `enabled` taken from the constant.
- `install.sh`: `VERIFY_SANDBOX_CODE` asserts `enabled` equals `SANDBOX_ENABLED` and that `start()` from Core code raises `sandbox_disabled` while the constant is False (`not_owner` once it is True). It starts no run. The log line that said the sandbox "stays switched off" says the switch stays off in this release; once it is on, a run starts only while the selftest result is ready. A failed or not-ready selftest still never fails the install. `install.sh` keeps its LF line endings.

### 2. Held Medium: a name is answered only when both queries are (`sandbox-helper.py`)

`dns_lookup_name` now returns `answered` True only when the A query and the AAAA query both got a valid answer. An empty set for NXDOMAIN or NODATA is a valid answer. A timeout, SERVFAIL, a truncated reply and a reply with another id are not. `_resolve_own_names` refuses when any own name is not fully answered at the deadline: `Refusal('sandbox_unavailable')` with a plain reason that counts the names ("1 of this server's 2 own names did not get a full DNS answer"), never an address. Nothing is cached in that case. Addresses from `/etc/hosts` still never count as an answer. The limits are unchanged (2 s per try, 5 s per name, 5 s in all) and check (c), a global address must exist in DNS or on a local interface, stays.

What this means for you: a server whose resolver cannot answer A and AAAA for its own names in time gets no egress for that run. The run is refused, the sandbox status stays ready, and the helper and Core both write a refusal row.

### 3. Held Low: the DNS reply source is compared as an address (`sandbox-helper.py`)

The reply source is now compared with `ipaddress.ip_address(source[0].split('%')[0]) == ipaddress.ip_address(server)` and `source[1] == 53`. A value that is not an address means the packet is ignored. A non-canonically written IPv6 upstream (`2001:4860:4860:0:0:0:0:8888`) now matches its canonical reply. A reply from another address or another port is still ignored.

### 4. The canary (`tests/sandbox-canary-1.18.27.sh`)

Every step id and row id of the 1.18.26 script is kept, and so are the modes (`network`, `patchc`, `before`). What changed:

- The canary is written for the switched-on state. Its helper guard needs `SANDBOX_ENABLED = True`. Step 3c expects a garbage `--start` to be refused with a refused frame and not `sandbox_disabled`. Step 5l expects `--status` to show `enabled` true and `ready` true. Step 5m expects the same kind of refusal after the canary.
- New step 6, the switch-on proofs: 6a (Core's `status()` and the helper's `--status` both show enabled, ready and active true); 6b (a real start of an inert run through the root-only `--canary-launch` path, which runs the same `launch()` as `--start`; it ends `exited`, and the helper's log has `run.started` and then `run.ended` for that run id); 6c (forced not ready: `status.json` is copied aside with `cp -p`, replaced in place by a copy with `ready` false and a plain reason, the same inert run must be refused with `sandbox_not_ready`, the refusal must be in the helper's log, no `run.started` row and no run unit may exist, then `status.json` is put back and its sha256, owner and mode must equal the saved ones; a trap restores it even if the step fails or the script is stopped); 6d (after the restore a start works again). The old step 6 ("YOURS") is step 7.
- A new guard refuses an installed helper from before this release (no full A and AAAA rule).
- The latency row (50 no-op runs, p95 against 400 ms) stays a WARN row. The limit is not changed. On dev02 with 1.18.26 it measured p95 403 ms.
- The own-name DNS fix is exercised by the existing row `pb-proxy-refuse-own-public-address`.

## Proof from 1.18.26

The dev02 canary on 1.18.26 passed in full (read locally from `debug/1.18.26 - canary-tests.log`): `ALL CANARY STEPS PASSED`, modes full, `network` and `patchc`. 146 OK, 0 ATTACK SUCCEEDED, 0 NOT RUN. The 9 proxy rows were OK, including `pb-proxy-refuse-own-public-address`. The 9 Patch C rows were OK. The installed helper hashes matched the source and the selftest file was `root:root 700`. One WARN: the latency row, p95 403 ms against 400 ms.

## Main stays held

AD-65 says the kill switch stays off until the canary passes in full on dev02 and on a second kind of server. Review round 1 blocked the switch-on: no signed amendment is recorded in `docs/review-accepted-decisions.md`, so this build ships the fail-closed constants (`SANDBOX_ENABLED = False` in both files). `main` stays at Core 1.17.110. The switch goes on in a later release, once Johan's AD-65 amendment is recorded or a second kind of server passes the canary.

## Assumptions

- Information, no wait: the switch stays off in this build (AD-65's condition is not met and no amendment is recorded). When it goes on, it fails closed on every server whose root selftest is not ready. There is no toggle and no new permission, and `sandbox.register` still needs an administrator's grant.
- Information, no wait: `cancel()` and `cancel_by_person()` refuse only when the kill-switch constant is off. They do not refuse when the selftest is not ready, because `recheck_skeleton_after_run` can flip `status.json` to not ready after any run that leaves a new entry, and a live run must always be stoppable. The helper's `--stop` touches only units that helper started. `start()` and `run()` refuse as asked, and the refusal is audited.
- Information, no wait: the code for a not-ready server is `sandbox_not_ready` (new, additive). `sandbox_unavailable` keeps its meaning for the helper's runtime refusals.
- Information, no wait: AAAA is required as well as A. NODATA and NXDOMAIN count as answers. The cost is that a server whose resolver never answers AAAA gets `sandbox_unavailable` with a plain reason until its DNS is fixed. dev02 answered both in the 1.18.26 canary.
- Information, no wait: the canary forces "not ready" by swapping `status.json` for a copy with `ready` false under a trap that restores the original byte for byte and checks the sha256. No systemd or selftest setting is changed. While the file is swapped (a few seconds) a real start by a module would be refused, so run the canary when nothing else uses the sandbox.
- Information, no wait: the 1.18.26 latency WARN (p95 403 ms against 400 ms) is recorded only; the limit is not changed here.

## Retired or changed checks

Retired to `tests/legacy` (the copies that expected the OFF state, the old DNS rule, `sandbox_unavailable` for a not-ready status or named the 1.18.26 canary files): `sandbox-contract-1.17.116.py`, `sandbox-launch-1.17.118.py`, `sandbox-django-launch-1.17.118.py`, `sandbox-canary-1.17.118.py`, `sandbox-private-network-1.18.24.py`, `sandbox-run-private-1.18.15.py`, `sandbox-selftest-split-1.18.26.py`, `sandbox-own-public-address-1.18.26.py`, `sandbox-canary-network-1.18.26.py`, `sandbox-canary-network-driver-1.18.26.py`, `sandbox-canary-patchc-1.18.26.py`, `sandbox-canary-patchc-driver-1.18.26.py`, `sandbox-canary-script-1.18.26.py`, `sandbox-doc-text-1.18.25.py` (superseded by the 1.18.26 text, which it also repeats), `sandbox-doc-text-1.18.26.py`, `sandbox-egress-own-names-1.18.25.py`, `sandbox-file-view-1.18.8.py`, `sandbox-helper-register-1.17.116.py`, `sandbox-installer-1.17.116.py`, `sandbox-selftest-1.17.116.py`, `sandbox-unit-builder-1.17.118.py`, `sandbox-skeleton-run-1.18.13.py`, `version-1.18.26.py`. Each has a 1.18.27 copy in `tests/` (the 1.18.25 doc-text test is covered by `sandbox-doc-text-1.18.27.py`). The older `tests/sandbox-canary-1.18.26.sh` stays in `tests/`, as the earlier scripts did. `RELEASE_NOTES_1.18.26.md` moved to `docs/releases/`.

Changed because a behaviour changed (the assertions are kept; only the expected value changes):

- Contract, launch, Django launch, canary 1.17.118, private network, run private, selftest split: the switch is True. Where a test proves the off path (`sandbox_disabled` before any read, `main(['--start'])` refusing before it reads stdin), it forces the constant to False inside the test, so the off path is still covered. The new assertions prove that with the real value `main(['--start'])` reads the header.
- Start with a not-ready status: `sandbox_unavailable` became `sandbox_not_ready`, plus the audit row.
- Contract rows: `core.sandbox 1.1.0`, the key `active`, the new code and the `Readiness never gates cancel` sentence.
- `sandbox-own-public-address-1.18.27`: three assertions said a name was answered when at least one query answered. They now expect a partial answer to be not answered, a refusal when one name is late, and the new refusal text.
- `sandbox-canary-script-1.18.27`: the OFF checks are replaced by their flipped forms, with checks for step 6, the trap and the new guard. It runs step 6 in Git Bash against stand-ins, including a failing step that must still restore `status.json`.
- Older checks that only changed an expected value: `sandbox-file-view`, `sandbox-helper-register`, `sandbox-selftest` (`enabled` comes from the constant, True; where a test proves the off path it forces the constant to False), `sandbox-installer` (`VERIFY_SANDBOX_CODE`), `sandbox-egress-own-names` (a name that does not exist is a full, empty NXDOMAIN answer and still does not block the others), `sandbox-unit-builder` and `sandbox-skeleton-run` (a not-ready status, including a skeleton that changed, now gives `sandbox_not_ready` with the same reason text), `sandbox-doc-text` (capability 1.1.0).
- Edited in place, only a file name: `sandbox-shebang-1.18.26.py` (the Patch C driver), `sandbox-skeleton-root-1.18.12.py` and `sandbox-no-plus-1.18.14.py` (the moved selftest, unit-builder and skeleton-run tests).
- Tests that only mention `SANDBOX_ENABLED`, `sandbox_disabled` or "switched off" in other areas (scheduler, patch lockdown, module lock) are about wording unrelated to core.sandbox and are unchanged.
- The installer warning text `Sandbox is off: <reason>. ai ChatGPT stays off.` is kept as it is. Three tests assert it, and for a server that is not ready it is still true: no run can start there.

## New tests

`sandbox-switch-on-1.18.27` (the constants, `status()` with `active`, start and run refused and audited with the helper never called, the strict `run.started` row first when ready, cancel not gated, the helper's `ready_status()` and `read_status()`, the selftest `enabled`, the 503 mapping, the contract text and the install text), `sandbox-own-name-dns-1.18.27` (both queries, NXDOMAIN and NODATA, SERVFAIL, no caching of a partial answer, the hosts-style answer, the canonical IPv6 source, port 5353, zone suffix; stubbed sockets only), `version-1.18.27`.

All of them stub the socket layer, bind nothing on `0.0.0.0` and contact no public address.

## What could not be run

Django is not installed on this PC, so the Django-bound tests, the contract export test (`tec_tac_check_contract_export`) and a fresh export into `docs/contracts` did not run. The release manager exports the contract after signing. The root helper, systemd, the real DNS and the dev02 canary cannot run here: `tests/sandbox-canary-1.18.27.sh` was syntax-checked and its functions, including step 6 with its trap, ran in Git Bash against stand-ins. The root-only drivers (`sandbox-canary-network-1.18.27.py`, `sandbox-canary-patchc-1.18.27.py`) need root and Linux, and were not run. The Core-side `start()` refusal for a not-ready server is proven by unit tests only, because the canary has no registered module runner to call it with. The canary proves the helper side, and Core's `status()` through the real file.

## Johan dev02 checklist

This build ships with the switch off, so no canary run is needed for it. The switched-on canary (`tests/sandbox-canary-1.18.27.sh`) belongs to the release that turns the switch on, after AD-65's condition is met.

a. Update dev02 to Core 1.18.27 from the dev branch, then run `cd /opt/tec-tac-src/framework && cat VERSION`.
   PASS: it prints `1.18.27`.
   FAIL: any other version. Send the output and stop.

b. Run the installer and read its log for the sandbox line.
   PASS: the log shows `TEC-TAC core.sandbox verification OK: ready=... enabled=False`, and the install finishes.
   FAIL: the verify step "Core sandbox capability" fails. Send the install log.


## Where the plan did not fit the code

- **Step 6b and 6c use the root-only `--canary-launch` path, not the sudo-reachable `--start`.** The sudo-reachable `--start` needs a registered runner, and registering one needs a signed module. `--canary-launch` runs the same `launch()` with the canary's own inert row, so it proves the same readiness gate. The sudo-reachable `--start` is still covered by steps 3c and 5m (a garbage header is refused, not with `sandbox_disabled`).
- **Core's own `start()` is not called from the canary.** The caller check needs a real module on the call stack. The canary calls Core's `status()` (the real `sandbox.py` of the source tree, with a stand-in for its one Django-bound import) and the helper path. The Core `start()` refusal is covered by `sandbox-switch-on-1.18.27` and `sandbox-django-launch-1.18.27`.
- **The helper did not write a refusal row.** The plan said the helper audits the refusal. In 1.18.26 `start_command` only emitted the frame. This release adds an audit row `start.refused` (code only) for `sandbox_not_ready`. It holds no run id, because a refusal can come before the header is read. Other refusals keep what they had.
- **The `before` mode** runs against an installed 1.18.7, whose switch is off, so its guard accepts either value of the constant. Every other mode requires `SANDBOX_ENABLED = True`.


## Exit list

For this build: the install verify step logs `TEC-TAC core.sandbox verification OK` with `enabled=False`, and every sandbox call is refused with `sandbox_disabled`. The full switched-on canary and the plan entry "core.sandbox: consolidated fix plan, three patches" stay open until AD-65's condition is met and `main` is promoted by Johan.

## Fixed after review

Round 1 (blocked), two findings.

1. High, kill switch on before AD-65's condition and with no recorded amendment. Fixed the safe way. `SANDBOX_ENABLED` is `False` again in `framwork/tec_tac/sandbox.py` and `scripts/sandbox-helper.py`, so every `start`, `run` and `cancel` refuses with `sandbox_disabled` before it reads anything, and `status()` answers `enabled` false and `active` false. The readiness gate (`sandbox_not_ready`), the `active` key, capability 1.1.0 and the DNS fixes ship unchanged and are tested with the constant patched on inside the tests. `install.sh` verification and its log line, the contract notes in `contracts.py`, the docstrings and the docs now say the switch is off. Question for Johan in `reviews/questions/core.md`: record the AD-65 amendment (switch on after the dev02 canary alone, dev servers only) and the switch goes on in the next release. `tests/sandbox-switch-on-1.18.27.py` now asserts both shipped constants are `False`, that `start`, `run` and `cancel` raise `sandbox_disabled` and reach no helper, and that the contract metadata says `enabled` false. The other 1.18.27 sandbox tests assert the shipped `False` and then patch the constant on to keep proving the gate.
2. Low, `docs/capabilities.md` still described `core.sandbox` 1.0.0. It now names 1.1.0, `sandbox_not_ready` (503), the `active` key and that `cancel` is not gated by readiness, and says the switch stays off. `docs/sandbox-capability.md` carries the same wording. `tests/sandbox-doc-text-1.18.27.py` checks it.

Round 2 (blocked, 1.18.27-1), three findings.

1. Critical, `install.sh` (`VERIFY_SANDBOX_CODE`). The self-check expected `not_owner`, but with the switch off `start()` raises `sandbox_disabled` before it checks the caller, so a fresh install would have failed the verify step. The check now imports `SANDBOX_ENABLED` and expects `enabled` to equal it and the refusal code to be `not_owner` when it is True and `sandbox_disabled` when it is False. New test `tests/sandbox-verify-code-1.18.27.py` runs the real body of `VERIFY_SANDBOX_CODE` against the real `tec_tac.sandbox` (only the Django-bound `tec_tac.capabilities` is stubbed), proves it prints `TEC-TAC core.sandbox verification OK`, and proves the old fixed `not_owner` expectation fails. `tests/sandbox-installer-1.18.27.py` pins the new wording. The dev02 install run is Johan's step b above.
2. Medium, `contracts.py` and `docs/sandbox-capability.md`. The `status`, `start` and `cancel` entries, the Core sandbox rule text and the status row of the doc said the switch was on and `enabled` was True. They now say `enabled` stays False until AD-65's condition is met, that `active` is therefore False, and that `sandbox_not_ready` applies once the switch is on. `tests/sandbox-doc-text-1.18.27.py` now fails if `kill switch is on`, `True since Core 1.18.27` or similar appears in either file while `SANDBOX_ENABLED` is False. `contracts.py` keeps its CRLF endings.
3. Low, these release notes. They now describe one state: switch off, gate built, installer check expecting `sandbox_disabled`. The sentence that told modules to require `framework >=1.18.27` as proof of a live switch is gone, and the dev02 checklist no longer asks for the switched-on canary.

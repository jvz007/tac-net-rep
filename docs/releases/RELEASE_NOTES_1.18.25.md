# Tec-Tac Framework 1.18.25

Date: 20 November 2026. core.sandbox: the dev02 canary of 1.18.24 passed everything except step 5v. This release fixes that clean-up, closes the held Medium (the egress proxy now refuses every name of this server, not only one), corrects the sandbox text, and adds the Patch C canary rows. The sandbox stays off (`SANDBOX_ENABLED = False`).

## Module-facing change

There is none. Part 1 changes helper-internal clean-up and refusal rules only. The status route text gains two key names (`network_private_ok` and `egress_ok`, which `status()` has returned since 1.18.24). No route, permission, key, response value, capability or contract version changes: `core.sandbox` stays 1.0.0. No module uses `allowed_hosts` or `pattern` today. Only `modules/ai` reads `core.sandbox`, and it declares no `sandbox_runners`. A manifest that needs `allowed_hosts` must require `framework >=1.18.24`: older Cores refuse the key.

## Closes

- dev02 canary 1.18.24, step 5v (held Low, `sandbox-helper.py` `egress_clean`): the egress state folder was left behind after every run.
- Held Medium (`sandbox-helper.py` `egress_start`, AD-65 condition): the proxy must refuse all of this server's own names.
- Held Low: `docs/sandbox-capability.md` and the status route text still described the removed network rule.

## What changed and why

### 1. Step 5v: the audit state symlink is removed

The proxy service uses `DynamicUser=yes` with `RuntimeDirectory=tec-tac-sbx-egress/%i`. For a dynamic user, systemd keeps the real folder at `/run/private/tec-tac-sbx-egress/<run id>` and makes `/run/tec-tac-sbx-egress/<run id>` a symlink to it. `egress_clean` called `shutil.rmtree(..., ignore_errors=True)` on that path. `rmtree` refuses a symlink and `ignore_errors` hid the refusal, so the link and `audit.jsonl` (host names) stayed after every run.

- New `egress_remove_state(run_id)` in `scripts/sandbox-helper.py`. It is built only from the validated 32-hex run id and uses `os.lstat`.
- A plain directory goes with `rmtree`. A plain file is unlinked.
- A symlink is followed only when its target, joined to the link's folder and normalised lexically (`posixpath.normpath`, never resolved), is exactly `EGRESS_PRIVATE_ROOT/<same run id>` and that target is itself a real directory. Then the target goes, then the link.
- Any other symlink (points elsewhere, another run id, a target that is a symlink or a file, a `..` that climbs out) is unlinked alone. Nothing it points to is touched.
- It never raises. `egress_clean` calls it after the door folder and configuration are removed. The order stays: `egress_stop` first.
- The sweep calls the same function for the state folder, so a stale link and its target both go. A live or young run keeps both.
- `RuntimeDirectoryPreserve=yes` stays in `install.sh`, because the helper reads `audit.jsonl` after the proxy stops.
- The canary step 5v keeps its text and its condition. Its failure output also lists `/run/private/tec-tac-sbx-egress`, so a leftover there is visible.

### 2. The proxy refuses every name of this server

Before: `egress_start` passed only `socket.getfqdn()`. On a server behind NAT, an allowed host that resolves to the server's public address (on no local interface, so the own-address list, the `bind()` probe and `IPAddressDeny` all miss it) would loop back to the server's own nginx on 443.

- New `own_server_names()` in `scripts/sandbox-helper.py` returns the set of this server's names: `socket.getfqdn()`, `socket.gethostname()` when it has a dot, and the host names in Tactical's `local_settings.py` (`/rmm/api/tacticalrmm/tacticalrmm/local_settings.py`, the same file as `install.sh` `LOCAL_SETTINGS`): `ALLOWED_HOSTS` (`*` skipped, leading dot stripped), `CORS_ORIGIN_WHITELIST`, `CORS_ALLOWED_ORIGINS` and `MESH_SITE` (the host part of each URL).
- The file is read as root with `O_NOFOLLOW`, a regular file of at most 256 KiB, parsed with `ast` and never imported or run. Only top-level literal assignments to those four names count. Names are lower-cased, validated as DNS names, and IP literals and single labels are dropped.
- Fail closed: a file that cannot be read or parsed, or a result with no dotted name at all, raises `Refusal('sandbox_unavailable', <plain reason>)` in `egress_start` before anything is created. The selftest `egress_proxy` row reports the same plain reason.
- `resolve_own_names()` looks the names up in worker threads, 5 seconds in all, and caches the answer for 60 seconds in the helper process. A name that does not resolve is still refused by name. If no lookup finishes in time, it fails closed.
- The per-run proxy configuration gains `own_names` (sorted) and `own_name_addresses`. The old `fqdn` key stays.
- `scripts/sandbox-egress.py`: a `CONNECT` to any own name is refused 403 with the new audit reason `own_name`, even when the run lists that name in `allowed_hosts`. The proxy resolves every own name at start-up and merges those addresses with `own_name_addresses`. `address_problem` refuses any address in that union (`address_blocked`). The audit schema keeps its six keys. `own_name` is added to `EGRESS_REASONS` in the helper.
- Canary row `pb-proxy-refuse-own-domain` (step 5t, Patch B table): the driver picks one dotted own name that is not the fqdn (a Tactical API, RMM or Mesh domain, else the fqdn), adds it to the run's `allowed_hosts`, sends `CONNECT <name>:443` through the door and expects a 403 with the audit reason `own_name`. The driver reads the reason from the `run.egress` row the helper writes. A refusal for any other reason is NOT RUN, because it proves the wrong rule. The row is NOT RUN with a plain reason only when the helper itself fails closed. The exit list now has 8 proxy rows.

### 3. Sandbox text

- `docs/sandbox-capability.md` "The smaller sandbox" now describes the real rule: an empty network space (`PrivateNetwork=yes`), no loopback to the host, no DNS, and one door, the per-run egress proxy, to the runner's `allowed_hosts` on port 443 (`CONNECT` only, no IP literals, private and own addresses and names refused, one `run.egress` audit row). A run without `allowed_hosts` has no network at all. The text says plainly that `allowed_hosts` needs `requires.framework >=1.18.24`. The old sentences ("Public HTTPS stays open", "There is no host list and no proxy") and the `resolv.conf` bind text are gone.
- `framwork/tec_tac/contracts.py`, route `/api/tfd/system/sandbox/status/`: the response text names `network_private_ok` and `egress_ok`, and a note says "Added in 1.18.25 text only; the keys exist since 1.18.24". Text only. The `pattern` wording in the manifest rule stays (Patch C removes it later). The file keeps its CRLF line endings.

### 4. Patch C canary rows (Part 2 adds test tooling only)

Rows only. No Patch C fix is built: no launcher kill, no contract text about untrusted credentials, no selftest split, no `-I` shebang, no type checks, no `pattern` removal, no seccomp change. Part 2 adds test tooling only. The one production-installed file it touches is `scripts/sandbox-canary-runner.py`, which gains two groups in a new `PATCHC_GROUPS` dict. The helper's `CANARY_GROUPS` stays as it is, so nothing reaches those groups through `--start`.

New step 5w in `tests/sandbox-canary-1.18.25.sh`, driver `tests/sandbox-canary-patchc-1.18.25.py`. Every row is expected to read ATTACK SUCCEEDED on this build (AD-65 canary first, as 1.18.23 did for Patch B):

| Row | Reads ATTACK SUCCEEDED when |
|---|---|
| `pc-leftover-before-credential` | a run's runner forks a leftover that keeps rewriting `$SANDBOX_OUT/credential`, and the credential returned to the host carries the marker (three tries, it is a race) |
| `pc-returned-credential-untrusted` | neither the contract text nor `docs/sandbox-capability.md` says a returned credential is untrusted and must be checked against the same account |
| `pc-selftest-in-sudoers` | the helper file the Tactical user may run as root still contains `def selftest`, `def run_canary`, `--selftest` and `--canary` (read as text, nothing is run) |
| `pc-helper-shebang-no-i` | the first line of the installed helper is not a `python -I` line |
| `pc-registration-type-checks` | the registration validator accepts, or dies with an uncaught `TypeError` on, a `max_length`, `minimum` or `maximum` that is a string or a boolean (nothing is written to the registry) |
| `pc-pattern-field` | the same validator accepts a `pattern` field |
| `pc-io-uring-reachable`, `pc-userfaultfd-reachable`, `pc-keyctl-reachable` | the raw syscall is not refused by the filter inside a run (success, or any errno other than `EPERM`) |

A row may be NOT RUN, with a printed reason, only where the machine cannot show it: an unknown architecture, `ENOSYS`, `kernel.io_uring_disabled=2`, or no credential returned. A row that shows OK fails step 5w, because it proves nothing. Step 5w prints `PATCH C ROWS: n ATTACK SUCCEEDED, m NOT RUN (reason), k OK` and passes only when `k` is 0 and the driver exits 0 (0 table as expected, 1 an OK row or a wrong NOT RUN, 2 a unit could not start). The script also has a mode `patchc` (guards, selftest and 5w only). Steps 5t to 5v keep their text, apart from the proxy row count and the 5v failure listing.

### 5. Script `tests/sandbox-canary-1.18.25.sh`

The 1.18.24 script with the changes above. Every step id is kept. New guards refuse an installed helper without `egress_remove_state` and `own_server_names`, and an installed runner or egress program without `patchc_syscalls` and `own_name` ("update Core first").

## Assumptions

- The source of this server's own names is Tactical's `local_settings.py`, read with `ast`, plus `getfqdn` and the host name. The sandbox fails closed when no dotted own name can be read. A server with a moved Tactical root reports the sandbox unavailable, never a weaker mode.
- `RuntimeDirectoryPreserve` stays `yes`. The fallback (`no`, with the audit read before the stop) was not needed.
- The `userfaultfd` probe passes `UFFD_USER_MODE_ONLY` (flag 1) instead of flags 0. Without it, a kernel with `vm.unprivileged_userfaultfd=0` refuses the call itself with `EPERM`, which would read as the filter holding. With the flag the call is allowed for an unprivileged caller, so `EPERM` can only come from the filter.
- The proxy's own-name check comes before the `allowed_hosts` check, so a listed own name reads `own_name`, not `not_listed`.

## Where the plan did not fit the code

- The plan says step 5w shows ten rows. The row list in the plan has nine, and nine are built. The summary line and the notes say nine.
- The leftover row needs a runner program that forks a leftover. The plan names only `patchc_syscalls`, so a second in-unit group, `patchc_leftover`, sits in the same `PATCHC_GROUPS` dict with the same rules (not in `GROUPS`, not in `CANARY_GROUPS`).
- The `userfaultfd` flag choice is under Assumptions.
- `tests/sandbox-egress-audit-1.18.24.py` called the real `egress_start`, which now reads Tactical's settings file. The 1.18.25 copy passes the own names in (`own=`), and it adds the symlink sweep case where the PC allows symlinks.

## Not built: Patch C fixes

Johan said canary rows only. The fixes (launcher kill before the credential read, the untrusted-credential contract text, the selftest and canary split out of the sudo-reachable file, the `python -I` shebang, registration type checks, removing `pattern`, denying `io_uring`, `userfaultfd` and `keyctl`) are a later release, after dev02 shows these rows as ATTACK SUCCEEDED. Also not in this release: the held 1.18.23 canary findings in `BACKLOG-new-findings.md`, install-speed work, probe transport, and every other open entry in `reviews/requests/core.md`.

## Retired checks

Moved to `tests/legacy/`, each replaced by a 1.18.25 copy with the new rows or arguments. No check of a still-existing behaviour was dropped.

- `sandbox-canary-network-1.18.24.py` (the driver), `sandbox-canary-network-driver-1.18.24.py` (its test) and `sandbox-canary-network-runner-1.18.24.py` (the in-unit test): they assert 29 rows and 7 proxy rows. The 1.18.25 copies assert 30 and 8.
- `sandbox-canary-network-driver-1.18.23.py`: it compares the 1.18.23 driver's rows with the runner's list, which now has 30 rows (the 1.18.25 driver test covers the current list). The 1.18.23 root drivers and script stay in `tests/`.
- `sandbox-canary-script-1.18.24.py`: it reads the 1.18.24 script. The 1.18.25 copy adds 5w, the `patchc` mode and the new guards.
- `sandbox-egress-proxy-1.18.24.py` and `sandbox-egress-audit-1.18.24.py`: superseded by the 1.18.25 copies, which contain every old case plus the new ones.
- `version-1.18.24.py`, and `RELEASE_NOTES_1.18.24.md` moved to `docs/releases/`. `tests/sandbox-canary-1.18.24.sh` stays in `tests/`, as the 1.18.23 script did.

## New tests

- `tests/sandbox-egress-clean-1.18.25.py`: link to the expected target, link outside, wrong id, target that is a symlink or a file, climbing link, plain directory, plain file, missing entry, invalid ids. Where the PC refuses `os.symlink` it uses a stub layer.
- `tests/sandbox-egress-audit-1.18.25.py`: the 1.18.24 audit and sweep test with the symlink sweep case.
- `tests/sandbox-egress-own-names-1.18.25.py`: the settings parser (never runs code, skips `*` and IP literals, refuses symlink, oversize and unparsable files), `own_server_names`, `resolve_own_names` (cache, timeout, fail closed), the config keys, and `egress_start` failing closed.
- `tests/sandbox-egress-proxy-1.18.25.py`: the 1.18.24 proxy test plus own names, NAT-public addresses (a documentation address stands in), `own_name_addresses`, start-up-only names and the positive control. Loopback only, resolver and dial stubbed.
- `tests/sandbox-doc-text-1.18.25.py`: the stale sentences are gone, the new text is present, and every key `status()` returns appears in the route text.
- `tests/sandbox-canary-network-1.18.25.py`, `-driver-1.18.25.py`, `-runner-1.18.25.py`: the own-domain row and the audit-reason check.
- `tests/sandbox-canary-patchc-1.18.25.py`, `-runner-1.18.25.py`, `-driver-1.18.25.py`: the Patch C driver, the in-unit groups with a stubbed syscall layer, and the driver verdict rules.
- `tests/sandbox-canary-script-1.18.25.py`, `tests/version-1.18.25.py`.

## What could not be run

On the development PC (Windows, no Django): the real launcher, systemd and socket activation, real DNS and real symlinks (where `os.symlink` is refused), seccomp state, and the Django-based contract export test (`tec_tac_check_contract_export` runs on the dev server). The whole 1.18.25 canary needs root, systemd and cgroup v2 and runs on dev02 only.

## Johan dev02 checklist

Run this once the release is signed and Core is updated on dev02. Send the whole output either way.

a. Update dev02 to Core 1.18.25 from the dev branch. Run `cd /opt/tec-tac-src/framework && cat VERSION && sudo sha256sum /usr/local/lib/tec-tac/sandbox/sandbox-helper.py scripts/sandbox-helper.py`.
   PASS: it prints `1.18.25`, and the two hashes match.
   FAIL: any other version, or two different hashes. Send the output and stop.

b. Run the full canary: `cd /opt/tec-tac-src/framework && cat VERSION && sudo bash tests/sandbox-canary-1.18.25.sh 2>&1 | tee ~/sandbox-canary-1.18.25-$(date +%Y%m%d-%H%M).log`
   PASS: `ALL CANARY STEPS PASSED` with 0 FAIL steps, step 5v PASS, the 147 Patch B rows OK plus `pb-proxy-refuse-own-domain` OK, 0 ATTACK SUCCEEDED and 0 NOT RUN in the normal table (`pb-tcp-443-ipv6` may be SKIPPED), the selftest time reported, and `SANDBOX_ENABLED` still False.
   FAIL: any `FAIL` line, `n STEP(S) FAILED`, an `ATTACK SUCCEEDED` or `NOT RUN` row in the normal table. Send the whole log. Do not switch anything on.

c. Step 5t on its own, with the new row: `cd /opt/tec-tac-src/framework && sudo bash tests/sandbox-canary-1.18.25.sh network`
   PASS: step 5t shows all 8 proxy rows OK (`pb-proxy-refuse-own-domain` with the audit reason `own_name`), 0 NOT RUN, 0 ATTACK SUCCEEDED.
   FAIL: any other result. Send the table. A `pb-proxy-refuse-own-domain` row that says ATTACK SUCCEEDED means a name of this server is reachable through the proxy.

d. Step 5w, the Patch C rows: `cd /opt/tec-tac-src/framework && sudo bash tests/sandbox-canary-1.18.25.sh patchc`
   PASS: step 5w prints `PATCH C ROWS: 9 ATTACK SUCCEEDED, 0 NOT RUN (reason), 0 OK`, or some rows as NOT RUN with a printed reason (for example the kernel has `io_uring` off). The summary has 0 OK.
   FAIL: any row that reads OK (it proves nothing), or a NOT RUN without a printed reason. Send the table.

Exit list: 0 FAIL steps (5v passes); 8 proxy rows OK; step 5w shows its rows as ATTACK SUCCEEDED (or NOT RUN with a printed reason); nothing else changed; `SANDBOX_ENABLED` stays False.

## For the release manager

- After signing 1.18.25, remove from `reviews/core/BACKLOG-new-findings.md` the three held 1.18.24 findings: the Medium (the proxy must refuse all of this server's own names) and the two Lows (`egress_clean` leaves the runtime-directory symlink; the sandbox text and status route text describe the removed rule). Name Core 1.18.25.
- Annotate the "core.sandbox: consolidated fix plan, three patches" entry in `reviews/requests/core.md`: Patch C step 1 (canary rows, `tests/sandbox-canary-1.18.25.sh`, step 5w) shipped in 1.18.25; the fixes are open.

# Tec-Tac Framework 1.18.26

Date: 20 November 2026. core.sandbox Patch C (AD-65), plus the three findings held from the 1.18.25 review. The canary rows that read ATTACK SUCCEEDED on 1.18.25 now have their fixes, so the same rows must read OK. The sandbox stays off (`SANDBOX_ENABLED = False`).

## Module-facing change

There is none. The contract wording is additive (the `start()`, `run()` and `sandbox_runners` text gains sentences "Since 1.18.26") and `core.sandbox` stays 1.0.0. One manifest rule is removed: `pattern` is no longer a field of a sandbox runner parameter. Nothing in `modules/` declares `sandbox_runners` (a search of `modules/` found none; `modules/ai` only names `core.sandbox` in its README, its release notes and an `OS_SANDBOX_AVAILABLE` flag), so nothing breaks. A stored older row that still holds a `pattern` is not honoured: the run is refused with a plain reason. `server_maintenance_actions` are not touched: they keep their own parameter rules, `pattern` included.

One operator-facing change: the install selftest and the canary no longer run as `tec-tac-sandbox --selftest [--canary]`. They are `sudo /usr/bin/python3 -I /usr/local/lib/tec-tac/sandbox/sandbox-selftest.py --selftest [--canary]`.

## Closes

- Patch C 1 to 6 of the plan "core.sandbox: consolidated fix plan, three patches" (rows `pc-leftover-before-credential`, `pc-returned-credential-untrusted`, `pc-selftest-in-sudoers`, `pc-helper-shebang-no-i`, `pc-registration-type-checks`, `pc-pattern-field`, `pc-io-uring-reachable`, `pc-userfaultfd-reachable`, `pc-keyctl-reachable`). The plan entry stays open: its exit needs the dev02 canary to pass and a second kind of server to be tested.
- Held Medium of the 1.18.25 review (`sandbox-helper.py`, own names): the proxy must also refuse the server's PUBLIC addresses for its own names.
- Held Low: `resolve_own_names` could raise `RuntimeError` instead of `Refusal`.
- Held Low: `sandbox-egress.py` resolved the own names one after another with no time limit at proxy start.

## What changed and why

### 1. The launcher stops leftover processes before it reads the returned credential (`scripts/sandbox-launcher.py`)

After the runner exits, and before `read_credential`, the launcher now kills every other process of the unit's own user and waits until none is left (about 2 seconds at most). A unit's `DynamicUser` is unique to the unit, so only this run's processes are hit. `os.kill(-1, SIGKILL)` never signals the caller and never reaches process 1. The launcher then reaps its own children and reads `/proc` (own uid, not itself, not a zombie) until it is clean. If the table cannot be read, or a process is still alive at the deadline, it sends NO credential frame: the helper then reports no `credentials_out`. The forwarder is still closed first, `read_credential` still uses `lstat`/`O_NOFOLLOW`, a regular file and 16 KiB, and the nonce frame is unchanged. Only a run with `--return-credential` pays for this.

### 2. A returned credential is untrusted (`framwork/tec_tac/contracts.py`, `docs/sandbox-capability.md`)

One sentence, the same in `start()`, `run()` and the doc: "A returned credential is untrusted: `credentials_out` comes from a program that ran in the sandbox, so before you store it, check that it is for the same account as the credential you handed in." Wording only. `contracts.py` keeps its CRLF line endings. The matching check belongs to the module that stores the credential: see the request filed for `ai`.

### 3. The selftest and the canary left the sudo-reachable helper

- New `scripts/sandbox-selftest.py` holds `selftest`, the probes, `run_selftest`, the `CANARY_*` constants, `canary_row`, `collect_run`, `run_canary`, `run_canary_command` and every parse and row helper of the canary (120 statements, 1,380 lines of the old helper). It is installed by `install.sh` through `install_root_script` and then set to root:root 0700. It is not in sudoers and not linked into `/usr/local/sbin`.
- It loads the installed helper beside it by path and reaches the helper's constants, launch code and unit builder as `H.<name>` (the canary runs exactly the code a real run uses). It takes only `--selftest`, `--selftest --canary` and the root-only `--canary-launch` that the canary's cancel rows start (now `python3 -I`).
- `start_command` gains a `row=` argument. Only the selftest file passes it. `main` never does, so `--start` always reads the root-owned registry. The helper no longer defines `canary_row` or `core.canary`.
- The helper's `main` refuses `--selftest`, `--selftest --canary` and `--canary-launch` with the usage text. Sudoers still names exactly `--start`, `--stop` and `--status`.
- `install.sh` runs the install selftest from the new file (same timeout, a failed selftest still only warns). The docs and the canary script say `sudo /usr/bin/python3 -I /usr/local/lib/tec-tac/sandbox/sandbox-selftest.py --selftest [--canary]`.
- Real size: `sandbox-helper.py` is 3,446 lines (it was 4,639; the plan hoped for 1,500 to 2,500) and `sandbox-selftest.py` is 1,706 lines. The plan's figure is not reachable by this move alone: what is left is the registration, the launch path (`launch`, `_supervise`, the cgroup watch), the unit builder, the egress proxy control and the sweep, which the sudo rule or the root job helpers must reach. Splitting `start_command` and `launch` further would not take any test code out of the sudo-reachable file, so it was not done.
- The selftest and canary output keys are unchanged: `status.json`, `canary.json` and the printed table have the same shape.

### 4. `python -I` shebang (`scripts/sandbox-helper.py`, `scripts/sandbox-selftest.py`)

The first line of both is exactly `#!/usr/bin/python3 -I` (one argument, valid on Linux). LF endings are kept; `install_root_script` strips a CR.

### 5. Registration type checks and no `pattern` field (`registry.py`, `sandbox-helper.py`)

- `max_length`, `minimum` and `maximum` must be real whole numbers. A string, a bool, a float or `null` is refused with a plain message by both validators (`RegistryError`, `RuntimeError`), never an uncaught `TypeError`. `max_length` is 1 to 65536, `minimum` and `maximum` are within plus or minus 2^31, and `minimum` may not be above `maximum`. A spec that is not an object is a `RuntimeError` too (it was a `TypeError`).
- `pattern` is refused at registration: "pattern is not supported; use enum choices or max_length". `validate_run_parameters` no longer has a pattern branch and checks the stored limits again: a malformed stored row is `Refusal('runtime_unverified')`, not a crash.
- In `registry.py` the new function `_sandbox_parameter_limits` runs for `sandbox_runners` only. The shared `_sm_parameters` is untouched, so `server_maintenance_actions` still accept `pattern` (the plan named `registry.py` line 283, which is that shared function, so changing it there would have broken server maintenance).
- The contract paragraph for `sandbox_runners` and the doc say pattern is not a parameter field.

### 6. io_uring, userfaultfd and keyctl are denied in every unit (`scripts/sandbox-helper.py`)

One more fixed Core constant in `UNIT_FIXED_PROPERTIES`: `SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register userfaultfd keyctl add_key request_key`. `SystemCallErrorNumber=EPERM` stays, so a refused call reads EPERM. No module text or number goes into any property, and the closed property set accepts exactly this line. There is no allow path for the Claude or Codex CLIs (see Assumptions).

### 7. Held Medium: the proxy refuses the server's public addresses for its own names (`sandbox-helper.py`, `sandbox-egress.py`)

`getaddrinfo` reads `/etc/hosts`, where a Tactical server maps its own names to `127.0.1.1`, so the public NAT address was never learned. `resolve_own_names` now asks real DNS from the host:

- New `dns_query_packet`, `dns_parse_answer`, `dns_lookup_name` (a plain UDP query, A then AAAA, standard library only). The id is random per query. An answer with another id, another source or another question, a truncated answer, a short packet and a record that runs past the packet are ignored. 2 seconds per try, 5 seconds per name.
- `upstream_resolvers` reads `/run/systemd/resolve/resolv.conf` (the real upstreams), else `/etc/resolv.conf`, with every loopback stub removed (127.0.0.0/8 and `::1`).
- Every address any own name returns is collected and handed to the proxy (`own_name_addresses`); the proxy rule is unchanged. The old `getaddrinfo` answer may add to the set but never stands in for the real answer.
- Fail closed with `Refusal('sandbox_unavailable')` and a plain reason when (a) no upstream resolver is usable, (b) no own name got a DNS answer, or (c) no own name has a global address AND no local interface holds one (the public address is then unknown). Results are cached for 60 seconds as before.
- Held Low (race): results and the answered set are guarded by one lock and copied under it; a lookup that finishes after the deadline writes harmlessly. Any unexpected fault in `resolve_own_names` is a `Refusal`, so `egress_start` and `_probe_egress`, which catch only `Refusal`, never crash. A worker thread never dies with a traceback.
- Held Low (proxy start): `Egress._fqdn_addresses` uses the helper's addresses and does no lookup when it has them. Only when that list is empty does it look the names up itself, in worker threads, with a total limit of 3 seconds (`OWN_LOOKUP_SECONDS`). A name that misses the deadline adds nothing and stays refused by name.
- New canary row `pb-proxy-refuse-own-public-address` (step 5t, now nine proxy rows): `CONNECT` to a name that is NOT an own name but answers the server's public address (a dashed-IP wildcard name, `<a-b-c-d>.sslip.io`, listed in the run's `allowed_hosts`) must get 403 with the audit reason `address_blocked`. NOT RUN only with a printed reason (no public address known, the wildcard name does not resolve to it).

### 8. The canary

- `tests/sandbox-canary-1.18.26.sh` is the 1.18.25 script with every step id kept. Step 5w is flipped: all nine Patch C rows must read OK; NOT RUN only with a printed kernel reason (io_uring turned off, ENOSYS, unknown architecture); an ATTACK SUCCEEDED row or a NOT RUN without a reason fails the step. Step 5t lists nine proxy rows. The 12 Patch B rows, 5v and the normal table keep passing as before.
- New guards: the installed helper, selftest file, launcher, egress program and canary runner must equal the source by SHA-256; the selftest file must be root:root 0700; the first line of the helper and of the selftest file must be the -I shebang; the sudoers line must be exactly the three commands and never name the selftest file; the helper must hold no selftest or canary code. The new steps 3g to 3i prove the Tactical user cannot run the selftest file through sudo and that the helper refuses `--selftest` and `--canary-launch`. Modes kept: full, `network`, `patchc`, `before`.
- The leftover row was redesigned (see "Where the plan did not fit the code").
- The shell script has not run on this PC. Its functions were run in Git Bash against a fake driver and a fake audit file by `tests/sandbox-canary-script-1.18.26.py`.

## Assumptions

- Information, no wait: when real DNS gives only private addresses for the server's own names (a split-horizon or on-premise server) and no local interface holds a public address, the public address is unknown. The sandbox then reports itself unavailable with a plain reason (option a). An admin-set public address (option c) can follow if a real server needs it. This does not widen trust.
- Information, no wait: `keyctl` is denied as a whole (`keyctl`, `add_key`, `request_key`), not only the last two, because the canary row calls `keyctl` itself. `io_uring_setup`, `io_uring_enter`, `io_uring_register` and `userfaultfd` are denied. Fail closed for every run. The Claude and Codex CLIs are not proven on these calls yet; if one needs a call, that is a question for Johan, never a silent wider filter.
- Information, no wait: the selftest and canary code lives in a new root-only file, and the root-only `--canary-launch` mode and the `core.canary` row moved with it. The sudo-reachable helper keeps register, start, stop, status and sweep only.
- Information, no wait: the `pattern` field is removed from runner parameters. Nothing in `modules/` declares `sandbox_runners`.
- Information, no wait: the new proxy row needs a name that answers the server's public address. The assumption is a dashed-IP wildcard name from `sslip.io`; it is NOT RUN with a printed reason when it does not resolve. If Johan prefers a name under his own domain, say so.
- `install_root_script` installs the selftest file 0755 for a moment and the next line sets 0700. The file holds no secret, and the folder is root-owned.

## Retired or changed checks

Retired to `tests/legacy` (the 1.18.25 copies that expected ATTACK SUCCEEDED or the old helper): `sandbox-canary-network-1.18.25.py`, `sandbox-canary-network-driver-1.18.25.py`, `sandbox-canary-network-runner-1.18.25.py`, `sandbox-canary-patchc-1.18.25.py`, `sandbox-canary-patchc-driver-1.18.25.py`, `sandbox-canary-patchc-runner-1.18.25.py`, `sandbox-canary-script-1.18.25.py`, `version-1.18.25.py`. The older `tests/sandbox-canary-1.18.25.sh` stays in `tests/`, as the earlier scripts did. `RELEASE_NOTES_1.18.25.md` moved to `docs/releases/`.

Changed in place, every assertion kept (mechanical, through the one shared loader `tests/sandbox_test_support.py`: `load_helper(root, name)` returns the helper and `scripts/sandbox-selftest.py` as one object, so a test keeps patching and calling the same names; source-text reads join the helper and selftest files): `sandbox-allowed-hosts-1.18.24`, `sandbox-bpf-info-1.17.120`, `sandbox-canary-detail-1.18.22`, `sandbox-canary-ids-1.18.15`, `sandbox-canary-rootview-1.18.8`, `sandbox-canary-script-1.18.22`, `sandbox-canary-table-1.17.122`, `sandbox-contract-1.17.116`, `sandbox-credential-frame-1.17.123`, `sandbox-credential-lingered-1.18.15`, `sandbox-credential-slots-1.18.8`, `sandbox-egress-audit-1.18.25`, `sandbox-egress-clean-1.18.25`, `sandbox-egress-units-1.18.24`, `sandbox-file-view-1.18.8`, `sandbox-harness-1.17.118` (the shared harness; this is what most others reach), `sandbox-memory-1.17.123`, `sandbox-memory-1.17.124`, `sandbox-memory-1.18.15`, `sandbox-memory-1.18.16`, `sandbox-no-plus-1.18.14`, `sandbox-run-private-1.18.15`, `sandbox-run-seen-1.18.16`, `sandbox-selftest-1.17.116`, `sandbox-selftest-network-1.18.24`, `sandbox-skeleton-root-1.18.12`, `sandbox-skeleton-run-1.18.13`, `sandbox-unit-result-1.18.17`.

Changed because a behaviour changed (assertion text adjusted, intent kept):

- `sandbox-canary-1.17.118`: `--selftest --canary` and `--canary-launch` as a normal user are now refused by `sandbox-selftest.py`; `start_command(canary=True)` is `start_canary`.
- `sandbox-installer-1.17.116`, `sandbox-installer-skeleton-1.18.8`: the install selftest line runs the new file.
- `sandbox-credential-hold-1.17.122`: reads the helper and the selftest file as one text.
- `sandbox-egress-own-names-1.18.25`: `resolve_own_names` now asks real DNS; the stubs give it a `lookup`, a resolver list and a public answer.
- `sandbox-percent-refuse-1.17.120`: the pattern lines now assert that a pattern is refused.
- `sandbox-unit-builder-1.17.118`: the golden property list gains the new syscall-denial line.
- `sandbox-harness-1.17.118`, `sandbox-credential-slots-1.18.8`: on a PC with no `/proc` or user ids they run a COPY of the launcher whose `kill_leftovers` answers True (`launcher_for_tests`); the real file is never edited. A server runs the real launcher.

## New tests

`sandbox-launcher-patchc-1.18.26` (kill before read, a survivor sends no frame, a clean run still sends it), `sandbox-doc-text-1.18.26`, `sandbox-selftest-split-1.18.26`, `sandbox-shebang-1.18.26`, `sandbox-registration-types-1.18.26`, `sandbox-syscall-filter-1.18.26`, `sandbox-own-public-address-1.18.26` (DNS builder and parser on fixed bytes, a fake UDP socket, the race), `sandbox-egress-proxy-1.18.26`, `sandbox-canary-script-1.18.26`, and the three canary driver tests (`sandbox-canary-network-driver-1.18.26`, `sandbox-canary-network-runner-1.18.26`, `sandbox-canary-patchc-driver-1.18.26`, `sandbox-canary-patchc-runner-1.18.26`), `version-1.18.26`. All use stubs: 127.0.0.1 only, no real DNS, no public contact, no listener on 0.0.0.0.

## Where the plan did not fit the code

- **The leftover row could never turn OK as planned.** The 1.18.25 row read ATTACK SUCCEEDED when the returned credential carried the leftover's marker. The leftover writes that marker within 20 ms of starting, so it is in the file long before the launcher kills anything. The fixed launcher would have returned the same marker and the row would have stayed red. The row now compares two numbers. The leftover writes `<marker> <n>` into the credential and prints `LEFTOVER <n>` to the shared stdout after each write. The credential carries the last `n` before the read. A leftover that was still alive after the read prints a larger `n` (ATTACK SUCCEEDED). A leftover killed before the read cannot print above it (OK). Three tries, because it is a race. The in-unit group in `sandbox-canary-runner.py` changed to match.
- **`registry.py` line 283 is shared.** `_sm_parameters` serves `server_maintenance_actions` as well, so the pattern refusal went into a new sandbox-only function (see item 5).
- **The helper does not reach 1,500 to 2,500 lines** (see item 3).
- **The old helper test loaders could not stay.** About 43 tests load the helper and use moved names, and about 20 read the helper's source text; the shared loader and a joined text read replace the old loading in each.
- **`resolve_own_names` keeps its `resolver=` hook** (the old `getaddrinfo` stand-in) so the proxy start path and older callers keep working; it adds addresses but never replaces the real DNS answer. The new `lookup=` and `servers=` hooks are for tests.

## What could not be run

Django is not installed on this PC, so the Django-dependent tests, the contract export test (`tec_tac_check_contract_export`) and a fresh export into `docs/contracts` could not run. The live canary, systemd, real DNS, the real `/proc` and `kill(-1)` of the launcher, the fork branch of the leftover group in `sandbox-canary-runner.py` and the real install on a server could not run here (they need root and Linux). `tests/sandbox-canary-1.18.26.sh` was syntax-checked and its functions were run in Git Bash against fakes. The three root-only drivers (`sandbox-canary-network-1.18.26.py`, `sandbox-canary-patchc-1.18.26.py`, and the older network driver) need `os.geteuid` and fail on Windows by design; their tests with stubs pass.

## Johan dev02 checklist

Do these in order. Send the whole output of each step, whether it passed or not.

a. Update dev02 to Core 1.18.26 from the dev branch, then run `cd /opt/tec-tac-src/framework && cat VERSION`.
   PASS: it prints `1.18.26`.
   FAIL: any other version. Send the output and stop.

b. Run `cd /opt/tec-tac-src/framework && sudo sha256sum /usr/local/lib/tec-tac/sandbox/sandbox-helper.py scripts/sandbox-helper.py /usr/local/lib/tec-tac/sandbox/sandbox-selftest.py scripts/sandbox-selftest.py /usr/local/lib/tec-tac/sandbox/sandbox-launcher.py scripts/sandbox-launcher.py /usr/local/lib/tec-tac/sandbox/sandbox-egress.py scripts/sandbox-egress.py /usr/local/lib/tec-tac/sandbox/canary/sandbox-canary-runner.py scripts/sandbox-canary-runner.py` and `sudo stat -c '%U:%G %a %n' /usr/local/lib/tec-tac/sandbox/sandbox-selftest.py`.
   PASS: each installed file has the same hash as its source in `scripts/`, and the selftest file shows `root:root 700`.
   FAIL: any hash differs or the selftest file is missing or not `root:root 700`. Send the output; the install did not finish.

c. Run the full canary: `cd /opt/tec-tac-src/framework && sudo bash tests/sandbox-canary-1.18.26.sh 2>&1 | tee ~/sandbox-canary-1.18.26-$(date +%Y%m%d-%H%M).log`.
   PASS: the output ends with `ALL CANARY STEPS PASSED`; step 5v passes; step 5t shows 9 proxy rows OK, including `pb-proxy-refuse-own-domain` and `pb-proxy-refuse-own-public-address`; the normal table has 0 ATTACK SUCCEEDED and 0 NOT RUN; step 5w prints `PATCH C ROWS: 9 OK, 0 ATTACK SUCCEEDED, 0 NOT RUN (reason)` (a NOT RUN is fine only with a printed kernel reason, for example io_uring turned off by the kernel).
   FAIL: any `ATTACK SUCCEEDED` row (a real hole), any hash mismatch, a NOT RUN with no reason, or any other FAIL line. Send the whole output and the last 40 lines of `/var/lib/tec-tac/sandbox/audit.jsonl`.

d. Run the two short modes: `sudo bash tests/sandbox-canary-1.18.26.sh network` and `sudo bash tests/sandbox-canary-1.18.26.sh patchc`.
   PASS: both end with `ALL CANARY STEPS PASSED`.
   FAIL: any FAIL line. Send the output.

If `pb-proxy-refuse-own-public-address` says NOT RUN, send the line that explains why (the usual reason is that the wildcard name does not resolve from dev02). Then tell me whether to use a name under your own domain.

## Exit list

Step 5w, all nine OK: `pc-leftover-before-credential`, `pc-returned-credential-untrusted`, `pc-selftest-in-sudoers`, `pc-helper-shebang-no-i`, `pc-registration-type-checks`, `pc-pattern-field`, `pc-io-uring-reachable`, `pc-userfaultfd-reachable`, `pc-keyctl-reachable`. Step 5t, nine proxy rows OK, including `pb-proxy-refuse-own-domain` and `pb-proxy-refuse-own-public-address`. The 12 Patch B rows, 5v and the normal table (147 OK expected, 0 ATTACK, 0 NOT RUN; `pb-tcp-443-ipv6` may be SKIPPED) unchanged. After this passes on dev02, the entry stays open until a second kind of server passes; the sandbox switch-on and the `ai` adoption wait for that and for the `ai` credential check.

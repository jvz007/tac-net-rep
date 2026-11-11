# Tec-Tac Framework 1.17.116

Date: 11 November 2026. Core gets the foundation of the sandbox (`core.sandbox`, AD-63): a signed module can now declare programs that a later release will run as an unprivileged, resource-limited process. **Nothing can run yet.** The kill switch is a constant inside the root helper and stays off. This release registers programs, tests the server and publishes the contract.

Request: `core.sandbox` (Johan, 11 November 2026, "Module runner" in `reviews/requests/core.md`). **It stays open.** It closes only when Patch 2 (the launch path) and the full canary on dev02 are signed, and ai switches ChatGPT on. Nothing is removed from `reviews/requests/core.md` for this release.

**Flagged for human review: security items.** A new publisher permission (`sandbox.register`), new root-only code (the helper, the install and uninstall changes), and a new sudo rule. See `reviews/questions/core.md`, Core 1.17.116. None of it widens a signed decision: AD-63 signed all of it, and nothing is switched on.

## What changed and why

1. **New manifest key `sandbox_runners` and publisher permission `sandbox.register`** (`registry.py`, `scripts/privileged-trust.py`).
   * Why: ai cannot create an operating-system user or a sandbox from inside its own package. Core has to hold the rules, so the module only declares what it needs.
   * The key is optional, for extensions only, at most 4 entries. A manifest without it, or with an empty list, parses exactly as before and its `PluginSpec` is unchanged.
   * Every entry is checked: `id` (`<module-id>.<name>`, unique), `description` (1 to 200 plain characters), `executable` (a file below `sandbox/runners/`, relative, no `..`, no symlink, must exist), `argv` (literal strings or `{"param": name}`, at most 64, no shell text), `parameters` (string, integer, boolean or enum), `environment` (fixed non-secret text; `HOME`, `TMPDIR`, `SSL_CERT_FILE`, `SANDBOX_WORK` and `SANDBOX_OUT` are Core's), `runtime_roots` (absolute normalised paths with a signed `tree_sha256_file`), `credential_files` (at most 2 names), `credential_return` (needs a name), `limits` (whole numbers at or below the Core ceilings) and `revision`. Any other key is refused.
   * `allowed_hosts` is refused with a plain message: the smaller sandbox (plan section 15) has no host list.
   * The module must declare `publisher_permissions` `sandbox.register` and `requires.framework >=1.17.116`. A missing or lower floor is refused.
   * The plugin-cache fingerprint covers the runner executables and the tree-hash files, so a swap on disk invalidates the cache.
   * The root trust gate treats `sandbox.register` like `server_maintenance.register`: a package that declares it needs a signature (`signature_required`) and a publisher that holds it (`publisher_permission_denied`). `install.sh` grants it to nobody.
2. **New root helper `scripts/sandbox-helper.py`** (kill switch off).
   * `--register-module <id>` and `--unregister-module <id>` (root only). The helper reads the root-owned installed manifest with no-follow checks, applies every rule again (never job metadata), copies each program root-owned 0755 to `/usr/local/lib/tec-tac/sandbox/runners/<module>/` with its SHA-256, and writes `registry/<runner-id>.json`. A runner id owned by another module is refused. An upgrade drops stale runners and programs; a module that now declares none loses all.
   * Each `runtime_roots` folder is checked against its signed listing: root-owned, no group or world write along the whole parent chain, no symlink, exactly the listed files with the listed hashes. A failure still registers the runner, marked `runtime_unverified` with a plain reason. A missing folder is the normal first state, because the module builds its runtime after install.
   * `--selftest` (root) proves systemd 249 or newer, cgroup v2, a transient unit, a dynamic user, a hidden file system with a read-only bind, `LoadCredential` (the file arrives, mode 400, source removable), `ProtectProc`, the section 15 address filter and a DNS reply from inside the filtered unit. The address filter is proven both ways: the helper opens its own loopback listener and the filtered probe must not reach it, and the same probe without the filter must connect, so a probe that cannot connect anyway is never read as a pass. Any failed check is `ready: false` with a plain reason. There is no weaker mode. The result is `/var/lib/tec-tac/sandbox/status.json` (root-owned 0644, written atomically).
   * `--status` (the Tactical account, through sudo) is read only. `--sweep` (root; boot and daily) checks the runtime folders again and removes stray `selftest-*` folders. `--start` and `--stop` read nothing and print `{"t":"refused","code":"sandbox_disabled"}`.
   * The helper keeps its own append-only log, `/var/lib/tec-tac/sandbox/audit.jsonl` (registered, removed, selftest, sweep). It never holds a credential.
3. **The two module job helpers call register and unregister** (`module-job-helper.py`, `module-v2-job-helper.py`).
   * `sync_sandbox_runners` runs right after each existing `sync_server_maintenance_actions` call (install, upgrade, uninstall), and the v2 rollback puts the earlier runners back (`restore_sandbox_runners`).
   * No sandbox helper on the server and nothing declared is a silent no-op, so a module without runners is not touched. A module that declares runners on a server without the helper fails the job with a plain message. A helper that is not root-owned, or is writable, is never run.
4. **`install.sh` and `uninstall.sh`.**
   * New layout under `/usr/local/lib/tec-tac/sandbox` and `/var/lib/tec-tac/sandbox`. The helper goes in through `install_root_script` (the CR strip).
   * One sudo rule, validated with `visudo -cf`, with exactly three commands and no wildcard: `--start`, `--stop`, `--status`.
   * A slice, `tec-tac-sandbox.slice`, with a server-wide `MemoryMax=6G`, `MemorySwapMax=0` and `TasksMax=2048`, and a sweep service with a boot and daily timer.
   * The installer runs `--selftest`. A failed or not-ready selftest never fails the install. It prints `Sandbox is off: <reason>. ai ChatGPT stays off.`
   * A new verify step, "Core sandbox capability": registered, `status()` answers, `start` refuses with `sandbox_disabled`.
   * `uninstall.sh` removes the helper, the sudo rule, the lib folder, the slice and its drop-in, the sweep timer and service, and the tmpfs folder. It keeps `/var/lib/tec-tac/sandbox` (the helper's own log), like the other persistent records.
5. **Public contract `core.sandbox` 1.0.0** (`tec_tac/sandbox.py`, `apps.py`, `contracts.py`, `docs/sandbox-capability.md`, `docs/capabilities.md`, `docs/trusted-publisher-verification.md`).
   * `status()` returns `{enabled, ready, reason, systemd_version, address_filter_ok, dns_ok, selftest_at, runners}` from the root-owned `status.json` and registry. A file that is missing gives `selftest_not_run`. A file that is a link, not root-owned, writable by others, too big or not JSON gives `status_unreadable`. Only listed keys are copied, so no credential-like key can appear.
   * `describe(runner_id)` is for the owning module only (AD-26: Core finds the caller from the call stack). Any other module, Core, a generated frame and an unverifiable caller get `not_owner`. A module cannot tell another module's runner from a missing one.
   * `start`, `run` and `cancel` exist now, so a module can code against the final shape, and raise `SandboxError` `sandbox_disabled` before they read anything.
   * Registered in its own guarded block in `apps.py`, like `core.secrets`: a fault never aborts start-up. Five new contract rows (area `sandbox`) and two new rule texts (the manifest key, written as its own sentence beside the 1.17.17 one, and a module-facing summary).
   * No Django audit row, no permission and no HTTP route in this release. Those arrive with Patch 2 (plan section 11). Registration and selftest are audited by the helper's own log.
6. **Housekeeping.** `RELEASE_NOTES_1.17.115.md` moved to `docs/releases/` (the integrity test allows exactly one root note).

## Module-facing changes

All additive. Nothing in `modules/` uses any of it (a search of `modules/` finds no `sandbox_runners`, `core.sandbox` or `sandbox.register`). ai is the first user, later.

* **New optional manifest key** `sandbox_runners` (see item 1 and `docs/sandbox-capability.md`). A manifest without it is unchanged.
* **New publisher permission** `sandbox.register`. A module that declares `sandbox_runners` must declare it, and an administrator must grant it to the signing publisher on the server. `install.sh` grants it to no one.
* **New capability** `core.sandbox` 1.0.0 (`status`, `describe`, `start`, `run`, `cancel`), needing framework `>=1.17.116`. Check `has_capability('core.sandbox')` first. In 1.17.116 only `status` and `describe` do anything.
* **The pipeline validator** under `pipeline/` may refuse the manifest key `sandbox_runners` until its allowed-key list learns it. Core does not touch `pipeline/`. No module needs it before Patch 2.

## Where the plan was wrong, and what I did

* The plan said `scripts/privileged-trust.py` has two `allowed = {...}` sets. It has one (the installed-target check of a hotfix). The package path has no set: an unknown permission there is refused as a permission the publisher does not hold. Both are covered by `tests/privileged-trust-sandbox-permission-1.17.116.py`.
* The plan said `executable` needs a "depth at least 3". I read that as `sandbox/runners/<file>`: the prefix plus a file name, which is three parts. A file in a deeper folder is allowed too.
* The plan did not say how the selftest should judge a private-range probe on a server with no route to a range. The probe sends one UDP packet to a fixed address in each range (and to 169.254.169.254). It passes when none is sent and at least one is refused outright. A server with no route to any of them cannot be judged, so the selftest fails closed with a plain reason.
* The resolver parser skips a zone id (`fe80::1%eth0`), because it cannot be allowed by address. It allows up to three name servers from `/etc/resolv.conf`, each by its own address, and the DNS probe passes when any one answers.

## Checks

Run here (Windows, Python 3.12, no Django, no Linux): `tests/sandbox-registry-1.17.116.py`, `tests/sandbox-helper-register-1.17.116.py`, `tests/sandbox-selftest-1.17.116.py`, `tests/sandbox-job-helpers-1.17.116.py`, `tests/sandbox-installer-1.17.116.py`, `tests/sandbox-contract-1.17.116.py`, `tests/privileged-trust-sandbox-permission-1.17.116.py`, and the existing `server-maintenance-module-actions-1.17.17.py`, `privileged-trust-register-permission-1.17.17-1.py`, `contract-text-spacing-1.17.112.py`, `root-script-crlf-1.17.15.sh`, `release-integrity.sh`. Plus `python -m py_compile` on every changed Python file, `ruff check` on the new files, and `bash -n` on `install.sh`, `uninstall.sh` and the runtime script.

**Could not run here:** Django (so nothing that imports it, including the full capability registration at start-up), systemd, cgroups and the address filter, `nftables` (not used any more), `visudo`, root, and the real selftest and helper as real root. The file-system answers in the helper tests (owner, mode, symlink) come from a fake layer limited to temp folders. `tests/sandbox-selftest-runtime-1.17.116.sh` covers the rest on dev02.

## Assumptions (information, in `reviews/questions/core.md`, Core 1.17.116)

1. The sudo rule lists `--start`, `--stop` and `--status` now, so Patch 2 changes no sudoers. The two stubs read nothing and refuse.
2. `status()` reports `address_filter_ok` and `dns_ok` (section 15 replaced `nft_ok` and `proxy_ok`).
3. A boot and daily sweep re-checks runtimes now, because ai builds its runtime after install.
4. `allowed_hosts` is refused (fail closed).
5. `sandbox.register` is granted to nobody automatically, not even the development publisher.
6. Server-wide slice caps: 6 GiB memory, no swap, 2048 tasks.
7. Environment names starting `LD_` or looking like a secret are refused.

## Johan's checklist (dev02, after this release is signed and installed)

Run as root: `sudo bash tests/sandbox-selftest-runtime-1.17.116.sh`. Steps 1 to 5 are scripted and print PASS or FAIL. Step 6 is yours.

1. **Core installs.** Update dev02 to Core 1.17.116. **FAIL** if the update stops. If the install prints `WARNING: Sandbox is off: ...`, that is not a failure of the install. Send back that line.
2. **The script.** It must end with `ALL SCRIPTED STEPS PASSED`. **FAIL** if any line says FAIL. Send back the whole output, `sudo /usr/local/sbin/tec-tac-sandbox --status`, `systemctl --version`, `uname -r`, `cat /etc/os-release` and the last 30 lines of `/var/lib/tec-tac/sandbox/audit.jsonl`.
3. **Versions.** The script prints the systemd version. The plan expects 249, 252 or 255. Note it down. **FAIL** only if the selftest table has a `NO` row. A `NO` row names the wall that did not hold on this server.
4. **What sudo shows.** `sudo -l -U tactical` shows exactly three sandbox commands (`--start`, `--stop`, `--status`). **FAIL** if it shows more, or a `*`.
5. **status().** The script's step 4 prints `status()`: `ready` true, `enabled` false, reason `ready`. **FAIL** if `enabled` is true. Whether `ready` is false on dev02 is information, not a failure of Core: send the reason.
6. **An unrelated module still installs and upgrades** (yours, in the browser). **FAIL** if either stops. Send the job log from the Modules page: it names the stage.
7. **Export the contract.** Export a fresh public contract into `docs/contracts` on the server. Claude can't: it is generated on a running server. Module work keeps using the newest file until then.

## Fixed after precheck (round 0)

- `scripts/system-update-helper.py`: `INSTALLER_VERIFY_STEPS` now ends with "Core sandbox capability", so a timed-out sandbox verify step during a system update is reported as a verify timeout. It holds all 13 fatal labels in install.sh order.
- Tests updated for the 1.17.116 changes: `installer-verify-timeout-1.17.96.py` and `installer-rollback-verify-1.17.98.py` (14 steps, 13 fatal labels, the new step's message), `scheduler-person-actions-1.17.80.py` (the supported-keys tail no longer ends at `scheduler_person_actions`), `module-job-retention-1.17.60.py` (carve-out for the sandbox block in `module-v2-job-helper.py`).
- New `tests/sandbox-verify-step-1.17.116.py` pins the helper tuple to the fatal labels in install.sh.
- Not module-facing. The tests ran here; Django-dependent tests and the dev-server timeout run did not.

# Tec-Tac Framework 1.17.117

Date: 11 November 2026. Three findings the 1.17.116 review held are fixed. They all sit in the `core.sandbox` foundation and the server-backup rollback list. **Nothing can run in the sandbox yet.** The kill switch stays off.

Request: none closes. The `core.sandbox` request in `reviews/requests/core.md` stays open until Patch 2 (the launch path) and the full canary on dev02 are signed. Nothing is removed from that file for this release.

**Flagged for human review: security items.** The first fix narrows what a manifest may ask the root helper to read. The second makes the daily check stricter. The third widens rollback coverage. None of them widens a signed decision. See `reviews/questions/core.md`, Core 1.17.117.

## What changed and why

1. **A runtime path must sit inside the module's own folder** (held finding, Medium, security).
   * Before: `runtime_roots` accepted any absolute path. The root helper walked it and put what it found into a registry file that every user can read.
   * Now: every `runtime_roots` path must be strictly below `/opt/tec-tac/runtimes/<module id>/`, at least one folder deeper. It must also be normalised, with no `..`, no empty part, no backslash, no control character, and at most 512 characters. `/opt/tec-tac/runtimes/ai/claude` stays valid for module `ai`. The module folder itself, `/opt/tec-tac/runtimes` alone, another module's folder and the prefix trap `/opt/tec-tac/runtimes/ai2/x` are refused.
   * Both parsers use the same rule and the same wording: `registry.py` (`_sandbox_runtime_path`, now given the module id) and `scripts/sandbox-helper.py` (`_check_runtime_path`, now given the module id). The sweep also checks the path of every stored row against the row's owner. A row from an older registration with a path outside the root is marked unverified (`unsafe_path`) and never walked.
2. **`runtime_reason` holds a fixed code and a fixed sentence, never a name** (same finding).
   * The helper's `verify_runtime` now returns `(ok, code)`. A small table turns a code into one fixed sentence. `register_module` and `sweep` build the text from the root's number and the code only, for example `root 1: hash_mismatch (a file in the runtime folder differs from the signed listing)`.
   * Codes: `runtime_missing` (the normal "not built yet" state), `unreadable`, `unsafe_path`, `unsafe_entry` (a link, a special file, or an entry that is not root-owned or is writable by others, anywhere in the path or tree), `extra_file`, `missing_file`, `hash_mismatch`, `too_many_files`, `listing_empty`, `listing_unreadable`, `listing_changed`, `listing_not_recorded`.
   * The `os.walk` in `verify_runtime` is the only place that touches names. No name, path or error text leaves it. A module author finds the differing file by running their own tree-listing tool again.
   * `describe()` copies up to 2000 characters of the string now (was 300), so eight roots still fit whole. The output shape is unchanged: `runtime_reason` is still a string.
3. **The sweep compares with the listing recorded at registration** (held finding, Low).
   * Registration records the SHA-256 of each tree listing file in the registry row: `runtime_roots` entries are now `{path, tree_sha256_file, listing_sha256}`. The row stays 0644 and holds a hash only, no names. The `runner.registered` audit line carries the hashes too.
   * `_tree_listing` reads the trusted file once and returns the hash and the parsed listing from the same bytes, so there is no check-then-read gap.
   * The sweep reads the listing again and compares its hash first. A difference gives `runtime_unverified` with `listing_changed` and the runtime folder is not walked. The change is audited as `runtime_state_changed`, as before.
   * A row with no recorded hash (a runner registered by 1.17.116 on dev02) fails closed: `listing_not_recorded`, until the module registers again. Nothing can start yet, so no run is affected.
   * A legitimate change to a listing (a module upgrade) registers again and records the new hash. The module job helpers call `sync_sandbox_runners` on every install action (install, upgrade, reinstall) in both `module-job-helper.py` and `module-v2-job-helper.py`. There is no separate hotfix action in them, so no helper change was needed. Without a register the runner stays unverified, which is the safe direction.
4. **The server-backup rollback list covers the sandbox installer targets** (held finding, Medium).
   * `TEC_TAC_PRIVILEGED_INSTALL_PATHS` now holds `/usr/local/sbin/tec-tac-sandbox` and `/etc/sudoers.d/tec-tac-sandbox`.
   * `TEC_TAC_SYSTEMD_INSTALL_UNIT_NAMES` now names `tec-tac-sandbox.slice`, `tec-tac-sandbox.slice.d/limits.conf`, `tec-tac-sandbox-sweep.service` and `tec-tac-sandbox-sweep.timer`. The unit scan only adds files it finds, and it skips the drop-in folder. Naming them records their absence, so rollback removes them if a failed restore introduced them.
   * `/usr/local/lib/tec-tac/sandbox` was already covered by `/usr/local/lib/tec-tac`. `/var/lib/tec-tac/sandbox` (the helper's own audit log) is kept on purpose, like the other persistent records.

## Module-facing changes

Nothing in `modules/` uses any of it (a search of `modules/` finds no `sandbox_runners`, `core.sandbox`, `sandbox.register` or `runtime_roots`). ai is the first user, later. The contract output shape is unchanged.

* **A manifest that declares `runtime_roots` outside `/opt/tec-tac/runtimes/<module id>/` is now refused** at install time (and again by the root helper). A module with `runtime_roots` must place its runtime under `/opt/tec-tac/runtimes/<its own id>/`, one folder deeper. For ai that is `/opt/tec-tac/runtimes/ai/claude`.
* **`runtime_reason` is now a code plus a fixed sentence per root** (see item 2). It is still a string. A module that matched the old free text must match the code instead.
* **A module must register again after its tree listing changes.** An upgrade does this. Until then the runner is `runtime_unverified` (`listing_changed`).

## Where the plan was wrong, and what I did

* The plan asked for a `listing_unreadable` code only for the sweep. Registration still refuses a listing it cannot read or parse (a plain refusal, as in 1.17.116), because there is nothing to record. Only the sweep turns that failure into the code.
* `tests/server-backup-host-rollback.py` imports `fcntl`, which Windows lacks, so it cannot run here. The new test stubs `fcntl`, `grp` and `pwd` and answers the helper's root-owned-bash check while the module loads (Windows only), so it runs on this PC. The existing test is unchanged.
* `tests/sandbox-selftest-runtime-1.17.116.sh` put its probe runtime under `/usr/local/lib/tec-tac/sandbox`, which the new rule refuses. The probe now lives in `/opt/tec-tac/runtimes/sbprobe/probe`, and the cleanup removes that folder. Not run here (needs root on dev02).

## Checks

Run here (Windows, Python 3.12, no Django, no Linux):

* New: `tests/sandbox-runtime-roots-1.17.117.py` (both parsers over 23 path cases, fixed reason codes with a planted `SECRET_NAME_MARKER` name, no walk for an unsafe path or a changed listing, hash recorded and re-recorded, a row without a hash) and `tests/server-backup-sandbox-rollback-1.17.117.py`.
* Updated to the codes and the new path rule: `tests/sandbox-helper-register-1.17.116.py`, `tests/sandbox-registry-1.17.116.py`, `tests/sandbox-contract-1.17.116.py`.
* Unchanged and passing: `tests/sandbox-selftest-1.17.116.py`, `sandbox-job-helpers-1.17.116.py`, `sandbox-installer-1.17.116.py`, `sandbox-verify-step-1.17.116.py`, `privileged-trust-sandbox-permission-1.17.116.py`.
* `bash tests/release-integrity.sh`, `python -m py_compile` on every changed Python file, and `ruff check` with the repo's config.

**Could not run here:** Django (so nothing that imports it), the helper as real root, systemd, and `tests/server-backup-host-rollback.py` as it stands (`fcntl`). The file-system answers in the helper tests come from a fake layer limited to temp folders. `tests/sandbox-selftest-runtime-1.17.116.sh` covers the rest on dev02.

## Assumptions (information, in `reviews/questions/core.md`, Core 1.17.117)

1. The fixed root for a runner's runtime is `/opt/tec-tac/runtimes/<module id>/` (the reviewer's proposal), at least one folder deeper. Nothing creates it in `install.sh`; `ai.install-runtime` builds it after install.
2. The registry row records the SHA-256 of the listing file's bytes, not the parsed listing.
3. `runtime_reason` shows a code and a fixed sentence only. A module author no longer sees which file differs.

## Johan's checklist (dev02, after this release is signed and installed)

1. **Core installs.** Update dev02 to Core 1.17.117. **FAIL** if the update stops. Send back the job log.
2. **The runtime script.** Run `sudo bash tests/sandbox-selftest-runtime-1.17.116.sh` as root. It must end with `ALL SCRIPTED STEPS PASSED`. **FAIL** if any line says FAIL. Send back the whole output.
3. **The status row.** Run `sudo /usr/local/sbin/tec-tac-sandbox --status`. **FAIL** if any `runtime_reason` shows a file name or a path. A runner registered by 1.17.116 may show `listing_not_recorded`. That is expected until its module registers again.
4. **An unrelated module still installs and upgrades** (in the browser). **FAIL** if either stops. Send the job log from the Modules page.

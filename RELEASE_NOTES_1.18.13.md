# Tec-Tac Framework 1.18.13

Date: 19 November 2026. The sandbox keeps working after a real run. On dev02 the first run made a folder we did not expect, and every later run was refused. We now expect that folder. If anything else appears, we name it at once.

## What changed and why

Johan's dev02 canary on Core 1.18.12 (Ubuntu 24.04.5, systemd 255.4) showed `ready: true` in the selftest, then refused every run after the first. A real run makes systemd add `run/systemd` and `run/systemd/incoming` inside the sandbox root. The selftest probes did not carry a credential, so they never made those folders. The next start saw two unexpected entries and said only `sandbox_unavailable`.

### Changes

1. `run/systemd` and `run/systemd/incoming` are now part of the skeleton: empty folders, `root:root`, mode 0755. `install.sh` builds them. An existing copy left by the dev02 run is kept and its mode repaired. A child inside is removed. Any other name in `run` is still removed and still refused. `root` stays 0700. The helper lists the folders in the same order as `install.sh` (`SKELETON_DIRS`, `SKELETON_ENTRIES`).
2. The canary's allowed `/run` view accepts `systemd` (`CANARY_VIEW_ALLOWED['/run']` is `credentials`, `systemd`). Nothing deeper is allowed.
3. After every run ends, the helper looks at the skeleton again (new `skeleton_changes`, called after the `run.ended` audit row). A clean skeleton writes nothing. Otherwise it writes one `skeleton.changed` audit row with the relative paths (names only, at most 10, each at most 100 characters, no file content, no host path). It also sets `status.json` to not ready, with the reason `a run left a new entry in the sandbox root: <names>`. The next start is refused with that reason, and the status endpoint shows it. Only a new selftest (the install runs one) makes it ready again. The entry is reported, never accepted. The re-check never raises and never changes the run's result.
4. The selftest has a new probe, `real_unit_shape`. It runs one unit with the shape of a real run: the real file view (`file_view_properties()`), `DynamicUser=yes`, `LoadCredential` and the `ExecStartPost` that removes the source. It runs after the credential probe and before `sandbox_root_after`, so the install catches an entry only the real shape makes. It uses only properties the real builder uses. If the sandbox root is already wrong, it is skipped with `not run: the sandbox root folder is wrong`. The probe is only as honest as real systemd shows it. The dev02 re-run decides.
5. `tests/legacy/version-1.18.11.py` line 20 is restored to `assert "parents[2]" in legacy and "parents[1]" not in legacy` (a held Low finding; the old text could never be true).
6. `docs/sandbox-capability.md` has the folders, the probe and the post-run re-check.

Request closed: "core.sandbox: a real run leaves `run/systemd/incoming` in the sandbox root, so every later run is refused" (reviews/requests/core.md).

Tests: new `tests/sandbox-skeleton-run-1.18.13.py` and `tests/version-1.18.13.py`. Updated: `sandbox-selftest-1.17.116.py` and `sandbox-fake-runner-1.17.120.py` (the fakes answer the new probe; the check list gains `real_unit_shape`), `sandbox-installer-skeleton-1.18.8.py` (`run` and `run/systemd` are no longer empty), `sandbox-canary-rootview-1.18.8.py` (the `/run` set gains `systemd`). `RELEASE_NOTES_1.18.12.md` moved to `docs/releases/`, `tests/version-1.18.12.py` to `tests/legacy/`.

## Module-facing change

None. No contract, capability, endpoint or import changes. The modules `ai` and `reportmanager` use the sandbox contract only and are unaffected.

## Johan test checklist (dev02)

Install Core 1.18.13 (`sudo bash install.sh`, or the Module Manager update).

a. `find /usr/local/lib/tec-tac/sandbox/root -mindepth 1 -maxdepth 3 | sort | grep run` must show exactly `run`, `run/systemd` and `run/systemd/incoming`. `ls -la` on each must read `drwxr-xr-x root root`, and `incoming` must be empty. FAIL if a name is missing or extra, or the mode or owner differs.

b. `sudo /usr/local/sbin/tec-tac-sandbox --selftest; echo exit=$?` must end `exit=0` with `ready: true`. The checks `real_unit_shape` and `sandbox_root_after` must both be ok true. FAIL if either is false.

c. `sudo bash tests/sandbox-canary-1.18.8.sh` must end `ALL CANARY STEPS PASSED`, with 0 NOT RUN and 0 ATTACK SUCCEEDED. The audit `started` count must equal the number of runs. FAIL on any other result.

d. Run the canary a second time. The listing in (a) must be unchanged, and the audit log must hold no `skeleton.changed` row. FAIL if the listing changes or a row appears.

Send back on FAIL: the whole selftest JSON, the `find` listing with `ls -la` of each folder, and the canary log from `debug/`. If a `skeleton.changed` row exists, send it too, with the status reason (`a run left a new entry in the sandbox root: ...`). The names in it tell us what systemd added.

## What could not be run

Django is not installed on this PC, so no Django test ran. systemd, cgroups and root are not available here either, so the install block ran under Git Bash with ownership faked, and the unit runs used test fakes. The mode systemd gives these folders is unconfirmed until the dev02 run.

## Assumptions

- systemd makes `run/systemd` and `run/systemd/incoming` as 0755 `root:root`. The install sets that explicitly, so an existing folder is repaired. This does not widen trust: both are empty, and any other name stays refused.
- The canary allows only the top name `systemd` in `/run`. It lists no deeper folder.
- A new entry makes the sandbox not ready until the next selftest. This is the fail-closed choice.
- No contract change: modules keep building against the previous contract.

## What is not in this release

Patch B and Patch C of core.sandbox, the install-speed request, and the held Medium and Low findings in `reviews/core/BACKLOG-new-findings.md`.

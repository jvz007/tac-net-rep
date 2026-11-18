# Tec-Tac Framework 1.18.9

Date: 18 November 2026. Welcome can now tell you whether the server's source folders and the UI sync program are set up safely. Two new read-only checks join the diagnostics report. Nothing is repaired, and no new permission is added.

## What changed and why

Request R2 from Welcome (18 November 2026) asked for two more checks in `GET /api/tfd/system/diagnostics/`. They sit in the existing "Runtime services" section, in the same shape as the other checks (`id`, `label`, `status`, `summary`, `details`, `help_id`, `metadata`).

**`core.install.source-ownership`.** The system updater runs as root inside the source checkouts. It refuses to do that when a folder above a checkout belongs to someone else. This check applies the same rule ahead of time, so you learn about it before an update fails.

- It reads `TEC_TAC_FRAMEWORK_SOURCE` and `TEC_TAC_UI_SOURCE` (defaults `/opt/tec-tac-src/framework` and `/opt/tec-tac-src/ui`). It never resolves them.
- Every folder from `/` down to each checkout's parent must be a real folder (not a symbolic link), owned by root, and not writable by group or others. The rule text is the same as `open_source_checkout` in `scripts/system-update-helper.py`.
- The checkout folders themselves belong to the Tactical account by design (1.17.98). They only have to be real folders. A missing checkout is noted and does not fail.
- `fail` names the first failing folder and gives the fix, for example `Run: sudo chown root:root /opt/tec-tac-src && sudo chmod 0755 /opt/tec-tac-src`. A folder that cannot be read gives `unknown` with the reason.

**`core.ui.module-sync`.** Root module jobs run a root-owned copy of the UI sync script. This check looks at three facts and reports each one in `details`.

1. Published: the script and its `tec-tac-config.sh` are regular files (not links), root-owned, not writable by others, the script is executable, and every folder above it is root-owned and not writable by others.
2. Current: the script is not older than the installed UI `VERSION` file, which the `tec-tac-ui-sync-publish.path` unit watches.
3. Path unit: `systemctl is-enabled tec-tac-ui-sync-publish.path` says `enabled`.

The result is `pass` only when all three pass. It is `fail` when any one definitely fails, and the summary names the part and the fix. It is `unknown` with the reason when nothing failed but something could not be read.

Both checks use only `lstat` on a handful of paths. The second adds one `systemctl is-enabled` call with a 3 second limit. No root, no sudo, no helper call, no new sudoers line. The logic lives in the new Django-free file `framwork/tec_tac/diagnostics_install.py`. `diagnostics.py` holds two thin wrappers. `docs/troubleshooting-diagnostics.md` has a table for both.

Limit, stated plainly: the sync check cannot prove the published bytes match the signed UI release, because that needs root. It proves the script is published, root-owned, not writable by others and not older than the installed UI.

## Module-facing change

- Two new additive check ids in `GET /api/tfd/system/diagnostics/`: `core.install.source-ownership` and `core.ui.module-sync`.
- Welcome 1.2.13 and 1.2.14 already read both ids and show "Not checked yet" until they appear. No existing id, field or status value changes.
- The `overall` and `counts` fields now include the two new checks. A failing source folder turns `overall` to `fail`, and an `unknown` result counts as a warning, as for every check.
- `grep modules/` found no other reader of the diagnostics route or of these ids. The check ids are not listed in `contracts.py`, so no contract file changes. Ask for a fresh export only if you want one.

## Closes

Request R2 in `reviews/requests/core.md`, in part. The original wording also asked the sync check to list the enabled modules whose authenticated UI is not reported. That part stays open: Core holds no root-free record of which module UIs are reported. Welcome should word its pass text as "the sync program is in place".

## Assumptions

- "Current" means the published script is not older than the deployed UI `VERSION` file. The root helper writes no version or hash record when it publishes, and checking bytes needs root. One false "stale" is possible: a UI release that ships no sync script leaves the old copy in place. It reports `fail` with a fix sentence, never `pass`.
- An unreadable fact is `unknown` with the reason, never `pass`.
- A missing `tec-tac-config.sh` next to the script is a `fail`, because the installer publishes both together.
- A definite fail wins over an unknown in the same check.

## What is not in this release

- Every other open request (R1, R3 and the rest). This run was R2 only.
- The enabled-modules list in the sync check (see Closes).
- A root-written marker or byte comparison for the sync script.
- Held backlog items in `reviews/core/BACKLOG-new-findings.md`. None touch diagnostics.

## What could not be run

Django is not installed on this PC. `diagnostic_report()` and the two Django wrappers did not run. The Django-free logic is tested with fake `lstat` tables. Real Linux ownership, real `systemctl` and the path unit could not be checked here, so the checklist below covers them on dev02.

## Johan test checklist (dev02)

1. Open Welcome, or call `GET /api/tfd/system/diagnostics/`, on a healthy server. Find both ids in the "Runtime services" section. **PASS:** both say `pass`, and the call answers in under about 2 seconds.
2. As root, run `chmod 0775 /opt/tec-tac-src`, then call the route again. **PASS:** `core.install.source-ownership` is `fail`, names `/opt/tec-tac-src` and shows the `chown`/`chmod` fix. Then run `chmod 0755 /opt/tec-tac-src` and confirm it returns to `pass`.
3. As root, run `systemctl disable --now tec-tac-ui-sync-publish.path`, then call the route. **PASS:** `core.ui.module-sync` is `fail` and names the path unit. Then run `systemctl enable --now tec-tac-ui-sync-publish.path` and confirm `pass`.
4. Open Welcome. **PASS:** checks C2 and C4 show results instead of "Not checked yet".

**FAIL if:** a check says `pass` while the folder is writable or the unit is disabled; the diagnostics call takes longer than about 2 seconds; or the call errors.

**Send back:** the JSON of both checks, the output of `ls -ld / /opt /opt/tec-tac-src`, and the output of `systemctl is-enabled tec-tac-ui-sync-publish.path`.

## Files

New: `framwork/tec_tac/diagnostics_install.py`, `tests/diagnostics-install-checks-1.18.9.py`, `tests/version-1.18.9.py`. Changed: `framwork/tec_tac/diagnostics.py`, `docs/troubleshooting-diagnostics.md`, `VERSION`, `tec_tac_package.json`. Moved: `RELEASE_NOTES_1.18.8.md` to `docs/releases/`, `tests/version-1.18.8.py` to `tests/legacy/` (root resolved as `parents[2]`). `install.sh` is untouched.

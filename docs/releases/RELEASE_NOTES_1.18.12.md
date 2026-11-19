# Tec-Tac Framework 1.18.12

Date: 19 November 2026. The sandbox can start again. On dev02 every run was refused because systemd added a folder we did not expect. We now expect it, and we check that nothing else appears.

## What changed and why

Johan's dev02 canary on Core 1.18.11 (Ubuntu 24.04.5, systemd 255.4) failed 52 steps, with 0 ATTACK SUCCEEDED. All came from one cause. The sandbox root is a folder of empty mount points that a run uses as its file system. Because the units set `ProtectHome=yes`, systemd creates an empty `/root` mount point inside it. The skeleton check saw an unexpected top-level name and refused every start and the selftest (`filesystem_view: bad: root`).

After the selftest's probe units, the skeleton on dev02 had exactly one new entry, `root` (`drwxr-x--- root root`). No `home` and no `run/user` appeared.

### Changes

1. `root` is now part of the skeleton. `install.sh` builds it as an empty folder, `root:root`, mode 0700. Every other skeleton folder stays 0755. An existing 0750 `root` from the dev02 run is repaired by the install; no `rmdir` by hand. The helper lists it in `SKELETON_DIRS`, `SKELETON_TOP` and the empty-folder list of `SKELETON_ENTRIES`. `check_skeleton` requires it to be a real, root-owned, non-writable, empty folder, and it is the only extra top-level name accepted. Any other name (`home`, `snap`) still refuses the run.
2. `root` is in the canary's allowed `/` view (`CANARY_VIEW_ALLOWED['/']`). That feeds the selftest's `ls -A /` check, the canary plan and the canary's root-view rows. What a run sees there is systemd's inaccessible mount, never host content. The canary's `/root` marker rows must still read OK.
3. The selftest checks the skeleton again after its probe units (new check `sandbox_root_after`). If a probe changed the folder, the selftest is not ready, and the install cannot log `Sandbox selftest passed` on that skeleton.
4. `ProtectHome=yes` and every other unit property stay as they were.
5. `docs/sandbox-capability.md` has one sentence on this.

This is proven for systemd 255.4 by the dev02 log, not by systemd's source (the source could not be read offline). A different systemd may make other names. They stay refused and show up in `sandbox_root_after`.

Request closed: "core.sandbox: systemd creates `root` inside the sandbox root, so every run is refused" (reviews/requests/core.md).

Tests: new `tests/sandbox-skeleton-root-1.18.12.py` and `tests/version-1.18.12.py`. Updated: `sandbox-selftest-1.17.116.py` (check list gains `sandbox_root_after`), `sandbox-canary-rootview-1.18.8.py` (the `/` set gains `root`). `RELEASE_NOTES_1.18.11.md` moved to `docs/releases/`, `tests/version-1.18.11.py` to `tests/legacy/`.

## Module-facing change

None. No contract, capability, endpoint or import changes. The modules `ai` and `certificatemanagement` use the sandbox contract only and are unaffected.

## Johan test checklist (dev02)

Install Core 1.18.12 (`sudo bash install.sh` as for 1.18.11, or the Module Manager update). No before run is needed: the 1.18.11 log is the before run.

a. `ls -la /usr/local/lib/tec-tac/sandbox/root | grep -w root` must show `drwx------ root root ... root`. It must stay unchanged after step b. FAIL if the mode differs or the entry changes.

b. `sudo /usr/local/sbin/tec-tac-sandbox --selftest; echo exit=$?` must end `exit=0` with `ready: true`. The checks `sandbox_root`, `filesystem_view` and `sandbox_root_after` must all be ok true, and no `bad: root` anywhere. FAIL if any is false. Send back the whole JSON and `ls -la /usr/local/lib/tec-tac/sandbox/root`. If a name other than `root` appears, send that listing too.

c. `sudo bash tests/sandbox-canary-1.18.8.sh` must end `ALL CANARY STEPS PASSED`. FAIL lines, the count of ATTACK SUCCEEDED rows (must be 0) and the step 1 skeleton listing go back, with the log in `debug/`.

d. Run the selftest a second time. The listing in (a) must be identical. FAIL if it differs.

## What could not be run

Django is not installed on this PC, so no Django test ran. systemd, cgroups and root are not available here either. The real systemd behaviour is proven only by the dev02 re-run above.

## Assumptions

- Only `root` is added. `home` and `run/user` are not, because the dev02 log shows systemd 255.4 did not create them. Any other name stays a refusal (fail closed).
- 0700 is safe: the folder is only a mount point that systemd covers, and the helper's trust test refuses only group or world write.

## What is not in this release

Patch B and Patch C of core.sandbox, and the held Medium and Low findings in `reviews/core/BACKLOG-new-findings.md`.

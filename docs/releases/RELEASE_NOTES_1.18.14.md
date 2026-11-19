# Tec-Tac Framework 1.18.14

Date: 19 November 2026. The sandbox now cleans up after itself without asking systemd to run commands for it. On dev02 those commands could not see the server, so the credential clean-up and the end-of-run hand-over never worked. The helper does both work itself now.

## What changed and why

Johan's dev02 selftest on Core 1.18.13 (Ubuntu 24.04.5, systemd 255.4) failed the probe `real_unit_shape` with "the source file was not removable after the start". The cause is in how systemd 255 runs a property command that starts with `+`. It gets full privileges, but it still runs inside the unit's `RootDirectory`, which is our small skeleton folder. The skeleton has no `secrets` folder and an empty `/usr/local`. So two commands could never work:

- `ExecStartPost=+/bin/rm -rf <secrets folder>` could not reach the credential folder.
- `ExecStopPost=+/usr/local/sbin/tec-tac-sandbox --finish <run id>` could not find the helper, so it never ran. Today's memory evidence already came from the helper's own live cgroup poll, and `result` in the hand-over was always empty.

### Changes

1. No unit property runs a command any more. `build_properties` no longer adds `ExecStartPost` or `ExecStopPost`. `check_unit_properties` drops both from its closed set and refuses any property that starts with `Exec`, so a later edit cannot bring a `+` command back.
2. New `remove_credentials_when_active(unit, folder, slots)` in the helper. It polls `/run/credentials/<unit>.service/<slot>` (the constant `CREDENTIALS_RUNTIME`) every 20 ms. When every copy exists with the same size as its source, it removes the run's credential folder and returns True. It reads sizes only, never content. If the unit never shows its copies, it gives up after 15 s and leaves the folder to the existing clean-up.
3. `launch()` starts that function in a daemon thread right after the unit is spawned. The existing `finally` block is unchanged and stops the thread first. So a run that never becomes active, a dead helper's sweep and every error path still remove the folder. The folder stays root 0700 on tmpfs, and the module never sees it.
4. The end frame's hand-over is built in memory. After the unit exits, `in_memory_handoff` uses the last forced cgroup sample. `result` is `oom-kill` only when the poll saw one or more kills and the exit code is not 0. It is `timeout` only when no helper stop reason is set and the run lasted at least `run_seconds` plus the timer slack. Otherwise it is empty. `merge_memory_evidence` keeps its signature and the `poll` evidence. The end frame keys and the reasons (`exited`, `oom`, `timeout`, `cancelled`, `output_limit`, `start_failed`) are unchanged.
5. The root-only `--finish` mode, `finish_run` and `read_handoff` are removed. `--finish` was never in sudoers, so removing it widens nothing. `HANDOFF_ROOT`, the layout entry, the sweep and the `finally` unlink stay, so a file left by 1.18.13 is still cleaned and the canary row "handoff empty" still holds.
6. The selftest probes `credential` and `real_unit_shape` keep their names. The probe now runs its unit under a name the helper knows (`UnitRunner.run_unit` takes an optional `unit=`) and removes the probe folder with the same helper function. It passes only if the token still arrives after the source is gone, and says "the source file was not removed by the helper once the unit was active" otherwise.
7. Two new canary rows, written first in the credential group: "credential source folder is gone while the run is still active" and "no host command property on the live unit" (`ExecStartPre`, `ExecStartPost` and `ExecStopPost` must all be empty in `systemctl show`). A row that cannot be read is NOT RUN, never OK.
8. `docs/sandbox-capability.md` and the helper docstring say how the clean-up works now. `file_view_properties` has a comment that a property command sees only the skeleton, so no host path may be used there.
9. New `tests/sandbox-canary-1.18.14.sh`: a copy of the 1.18.8 script with the `finish_run` comments replaced, a guard for the new helper names, and steps 4t and 4u for the two new rows.

Request closed: "core.sandbox: `+` commands run inside RootDirectory on systemd 255, so credential clean-up and `--finish` break (dev02, 19 November 2026)" (reviews/requests/core.md).

Tests: new `tests/sandbox-no-plus-1.18.14.py` and `tests/version-1.18.14.py`. Updated because they named the removed lines: `sandbox-launch-1.17.118.py`, `sandbox-memory-1.17.124.py`, `sandbox-cgroup-evidence-1.18.8.py`, `sandbox-unit-builder-1.17.118.py`, `sandbox-template-1.18.8.py`, `sandbox-selftest-1.17.116.py`, `sandbox-skeleton-run-1.18.13.py`, `sandbox-skeleton-root-1.18.12.py`, `sandbox-file-view-1.18.8.py`, `sandbox-credential-mode-1.17.120.py`, `sandbox-harness-1.17.118.py` (the fake systemd no longer runs `ExecStartPost` or writes a hand-over; it copies credentials where systemd does) and `sandbox-fake-runner-1.17.120.py` (the fake takes `unit=` and waits for the helper to remove the source). `RELEASE_NOTES_1.18.13.md` moved to `docs/releases/`, `tests/version-1.18.13.py` to `tests/legacy/`.

## Module-facing change

None. The sandbox contract, the end frame keys, the refusal reasons and the module job helpers are unchanged. The modules `ai` and `reportmanager` use the sandbox contract only and are unaffected. One visible difference: the end frame's `peak_mb` and `oom_kills` now come only from the live cgroup poll (they already did on dev02).

## Johan test checklist (dev02)

a. Install Core 1.18.14 (`sudo bash install.sh`, or the Module Manager update). FAIL if the install stops; send the last 40 lines.

b. `sudo /usr/local/sbin/tec-tac-sandbox --selftest; echo exit=$?` must end `exit=0` with `ready: true`. The checks `credential`, `real_unit_shape` and `sandbox_root_after` must all be ok true. FAIL on anything else: send the whole selftest JSON.

c. `find /usr/local/lib/tec-tac/sandbox/root -mindepth 1 -maxdepth 3 | sort` must show the same 29-entry skeleton as on 1.18.13, including `run`, `run/systemd` and `run/systemd/incoming`, and no new name. FAIL if a name is added or missing: send the listing with `ls -la`.

d. `sudo bash tests/sandbox-canary-1.18.14.sh` must end `ALL CANARY STEPS PASSED`, with 0 NOT RUN and 0 ATTACK SUCCEEDED. The two new rows (steps 4t and 4u) must end OK. The audit `started` count must equal the number of runs. FAIL on any other result: send the canary log from `debug/`.

e. Run the canary a second time. The listing in (c) must be unchanged and the audit log must hold no `skeleton.changed` row. FAIL if either changes.

f. `ls -A /run/tec-tac/sandbox/secrets /run/tec-tac/sandbox/handoff /run/tec-tac/sandbox/runs` must print nothing for all three folders after the runs. FAIL if any name shows: send the names.

Send back on FAIL: the selftest JSON, the `find` listing, the canary log, and `journalctl -u 'tectac-sbx-*' --since '30 min ago'`. Names and states only; never a credential.

## What could not be run

Django is not installed on this PC, so no Django test ran. systemd, cgroups and root are not available either. Only the helper tests ran, with a fake file system, a fake `systemd-run` and `systemctl`, and fake probe runners. They prove the helper's logic, not how systemd behaves. Whether systemd 255 shows its credential copies at `/run/credentials/<unit>.service/<slot>` before the unit's process starts is the one thing only dev02 can show. The dev02 canary decides.

## Assumptions

- The end frame's `result` is derived in the helper from the cgroup poll (oom-kill needs a polled kill and a non-zero exit; timeout needs no helper stop reason and the elapsed time at or past the limit plus slack). A kill between the last 0.2 s poll and the cgroup going away is reported as unknown, not guessed. The memory and OOM evidence now comes only from the live cgroup poll, because the helper `--finish` had never run on dev02.
- The root-only `--finish` mode is removed, not kept unused. The handoff folder and its sweep stay, so a file left by 1.18.13 is cleaned.
- No contract change: modules keep building against the previous contract.
- This does not widen trust. The credential folder is still root 0700 on tmpfs, the module has no view of it, and every failure path still removes it. It now stays for a few milliseconds longer than the intended `ExecStartPost` would have kept it.
- Line endings: the plan expected every touched file to be CRLF. They are LF, except some tests (`sandbox-fake-runner-1.17.120.py`, `sandbox-selftest-1.17.116.py`, `sandbox-credential-mode-1.17.120.py`), which stay CRLF. Each file keeps its own.

## What is not in this release

Patch B (PrivateNetwork, egress proxy) and Patch C of core.sandbox, the install-speed request, the three held Lows of 1.18.13 (they touch other lines), and every other open item in `reviews/requests/core.md`.

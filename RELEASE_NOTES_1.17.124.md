# Tec-Tac Framework 1.17.124

Date: 11 November 2026. `core.sandbox` canary: four fixes from the dev02 run of Core 1.17.123 (116 OK, 2 ATTACK SUCCEEDED, 1 NOT RUN, 0 SKIPPED), plus the two held Lows of that review. **Nothing can run in the sandbox yet.** `SANDBOX_ENABLED` stays `False`.

Request: "core.sandbox canary 1.17.123 on dev02: 2 ATTACK SUCCEEDED, 1 NOT RUN (Core 1.17.124)" in `reviews/requests/core.md`. It stays open. It ends only when a signed Core 1.17.124 is installed on dev02 and its canary finishes with `ALL CANARY STEPS PASSED` (0 ATTACK SUCCEEDED, 0 NOT RUN, no security row SKIPPED), with the kill switch still off.

Every change here narrows trust or measures more honestly. Nothing widens a signed decision. Two questions for Johan are recorded as information in `reviews/questions/core.md` (Core 1.17.124): the `AF_UNIX` decision and the new memory evidence rule.

## What changed and why

### 1. No `AF_UNIX` for runs (closes Medium R1, abstract unix sockets)

dev02 showed `abstract sockets (...)` connecting to `@/org/kernel/linux/storage/multipathd`. The abstract unix namespace belongs to the network namespace, and `IPAddressDeny` does not change that, so a run with `AF_UNIX` could reach the host's abstract listeners.

* **The unit property** is now exactly `RestrictAddressFamilies=AF_INET` (IPv6 stays off). `socket(AF_UNIX)` fails with `EAFNOSUPPORT` before any connect, for pathname and abstract sockets alike.
* **Why runners should still work.** systemd documents that `RestrictAddressFamilies` covers `socket()` only. `socketpair()`, pipes and inherited file descriptors are not affected, so libuv's stdio pipes (the Claude and Codex CLIs) and the launcher's `subprocess.Popen` keep working. This is not yet proven for the real CLIs; see "Not run here".
* **`ExecStopPost=+`** (`--finish`, which needs `AF_UNIX` for `systemctl`) is a fully privileged `+` command and is not filtered by the unit's seccomp. That is a dev02-only check: the memory row's `oom_kills` value only appears if `--finish` still works.
* **Runner probes no longer crash.** `g_sockets` now makes the socket inside its `try`, because with `AF_UNIX` gone `socket()` raises before `connect`. The 13 `unix <path>` rows are always printed: OK when socket creation is refused or the connect fails (with the errno shown), ATTACK SUCCEEDED only when it connects.
* **`_abstract_connect`** returns three states: `connected`, `unreachable`, or `refused` (with the errno name, when no socket could be made). It never raises on a creation failure. `g_abstract` reports `all refused: EAFNOSUPPORT` as OK, a connect as ATTACK SUCCEEDED (naming the cleaned names), and the probe-listener information row reports a refusal the same way.
* **New canary rows** (in the `sockets` group): `unix socket creation refused (stream)`, `(dgram)` and `(seqpacket)` and `unix pathname socket refused` are OK only for `EAFNOSUPPORT` or `EPERM`. A socket that is created is ATTACK SUCCEEDED (the filter is not in force). Any other error is NOT RUN.
* **Positive controls** (each its own row, OK only when it works): `socketpair round trip`, `pipe round trip`, `child process with stdio pipes`. A failure is NOT RUN with `control failed`: never an attack, but it fails the canary. The existing `public tcp 443` row is the `AF_INET` control.
* **`CANARY_REQUIRED`** lists the new exact row names. The path rows now count the prefix `unix /` (13 required), so the new `unix ...` rows cannot stand in for them.
* **Docs:** `docs/sandbox-capability.md` (the canary paragraph and the not-in-this-version line) now say runners no longer keep `AF_UNIX`, why, and that a CLI that later needs it is a new request to Johan (option b, `PrivateNetwork=yes` plus a bridge), never re-added silently.
* **Correction of the 1.17.123 notes.** `docs/releases/RELEASE_NOTES_1.17.123.md` (section 5) says `AF_UNIX` must stay in `RestrictAddressFamilies` and that the unit cannot keep abstract sockets out. That decision is superseded by this release. The 1.17.123 file is kept as written.

### 2. The memory row is judged on kernel evidence and the peak (closes held Low "OK with no evidence")

dev02 showed `allocated 112 MiB, ended exited (exit 1)` with `MemoryMax=128M`: no peak (`MemoryPeak` was empty) and a launcher exit of 1 (`systemd-run --wait` returns 1 for a unit ended by a signal). The 1.17.123 test called that an attack. Its opposite hole (OK with no allocation, no peak and a bare `oom` label) was the held Low.

* **New rule.** OK only when (A) the kernel stopped the run (end reason `oom`, or the end frame's `oom_kills` is at least 1) or the probe reported a refused allocation (`CANARYEND memoryerror` or `enomem`), AND (B) the allocated MiB and the peak, whichever are known, are at or below `MemoryMax` (no 16 MiB tolerance) and at least one of them is known.
* **ATTACK SUCCEEDED:** allocated or peak above `MemoryMax`, the probe finished the whole allocation (`CANARYEND done`), or a normal exit 0.
* **NOT RUN, never OK:** no end frame, no evidence, or an end nothing explains (exit 1 or 137 with no `oom_kills` and no `CANARYEND`, including dev02's case). The text names the stderr line.
* **Evidence plumbing.** `--finish` (root, `ExecStopPost=+`) now reads the unit's cgroup `memory.events` (`oom_kill`) and `memory.peak` while the cgroup exists (`systemctl show -P ControlGroup`, then `/sys/fs/cgroup<path>/...`; a missing file or odd path is `None`, never an error) and writes `oom_kills` and a peak fallback to the handoff file. `launch()` adds `oom_kills` to the end frame as an additive key. Core's own reader of end frames (`framwork/tec_tac/sandbox.py`) takes named keys only, so the extra key is ignored there.
* **Probe output.** `g_mem` prints a flushed `CANARYEND<TAB><word>` line (`memoryerror`, `enomem`, `other:<ExceptionName>`, `done`) in a `finally`. `parse_end_word` reads it with the same exact-line rule as `parse_progress`; it is never a table row.
* **Table.** `format_table` keeps up to 140 characters in the `actual` column (was 60) so the end of the memory row (oom_kills, peak) and the stderr text are visible. The other columns keep 60.

### 3. The 127.0.0.53 probes run in parallel so every row reports

dev02 reported `1 of 6 results`: dropped TCP connects to loopback time out (the egress filter drops the SYN, no EPERM), the probes ran one at a time at 1.5 s, and the 20 s run budget ended before the stub rows.

* `g_loopback` probes with a pool of at most 12 workers (the canary row has `TasksMax=64`; threads count), about 1.0 s per probe, the six stub ports first, then 127.0.0.1, then ::1.
* An in-unit deadline (`loopback_seconds`, 40) stops new probes; a probe that did not finish by then prints no row, and the table says NOT RUN through the existing missing-row rule (`CANARY_REQUIRED`: 127.0.0.53 on 6 ports stays). The loopback group now starts with `run_seconds=60`, still under the Core ceiling.
* `row()` prints under a lock so lines never interleave. The result words are unchanged: connected is SUCCEEDED, a timeout or errno is OK.

### 4. The abstract-socket list is capped below the 64 KiB stdin read (closes held Low)

`collect_run` sends `json.dumps(plan)` (ASCII-escaped) and the runner reads at most 65536 characters. 200 names of 107 latin-1 bytes encode to about 128 000 characters, so `json.loads` failed, the plan became `{}` and the abstract row was NOT RUN for no visible reason.

* **`fit_abstract_names(names, budget=49152)`** keeps names in order while the exact JSON length of the kept list stays within the budget and returns `(kept, left_out_count)`. `run_canary` puts both into the plan (`abstract_left_out`).
* The runner prints an information row `abstract sockets left out (information)` (OK) and its main row says `N listed, M left out`. Because `AF_UNIX` is gone, every left-out name is covered by the `unix socket creation refused` rows, so a non-zero count does not fail the canary. The required main-row prefix is now `abstract sockets (`, so the information row cannot stand in for it.
* **The runner no longer continues silently with `{}`.** A stdin text that does not parse (or is not an object) prints one row `plan unreadable` (NOT RUN) and the group does not run. The 64 KiB read limit is kept.

### 5. The canary script

`tests/sandbox-canary-1.17.124.sh` is the 1.17.123 script with the same steps 1 to 6 and these changes: the helper guard also needs `CANARYEND`, `oom_kills` and `fit_abstract_names` and refuses a helper that still says `AF_INET AF_UNIX`; step 2 prints the unit's `RestrictAddressFamilies` value and the host's abstract listener names (names only) as information; step 4 requires the new rows (checks 4n, 4o and 4p, plus tighter 4h and 4i), 0 ATTACK SUCCEEDED, 0 NOT RUN and no security row SKIPPED (only `public tcp 443`). The padding-safe patterns are kept. It never enables the kill switch and holds no secret. Send back the whole output.

## Module-facing

No contract, capability, endpoint or manifest key changed. The only change a module could see is one additive key (`oom_kills`) in the root helper's internal end frame, which Core's own reader ignores; the public `core.sandbox` result shape is unchanged. The `ai` module has not adopted `core.sandbox` yet (no `sandbox_runners` or `sandbox.register` in `modules/ai`), so nothing in `modules/` is affected. A request to `reviews/requests/ai.md` records that runs now have no `AF_UNIX` and that ai must prove the Claude and Codex CLIs on `socketpair` alone before it adopts the sandbox.

## Assumptions (also in `reviews/questions/core.md`)

* **Q1, `AF_UNIX`:** option (c), drop it (the coordinator's decision of 11 November 2026 under the decide-build-record rule). It only narrows trust. If a CLI later needs it, it comes back to Johan as option (b), never re-added silently.
* **Q2, memory evidence:** an unexplained end is NOT RUN (it fails the canary), not OK.

## Tests

New, each written to fail against the 1.17.123 code: `tests/sandbox-unix-1.17.124.py`, `tests/sandbox-memory-1.17.124.py`, `tests/sandbox-loopback-1.17.124.py`, `tests/sandbox-abstract-cap-1.17.124.py`, `tests/sandbox-canary-script-1.17.124.py` and the script `tests/sandbox-canary-1.17.124.sh`.

Superseded assertions, edited to the new behaviour:

* `tests/sandbox-unit-builder-1.17.118.py`: `RestrictAddressFamilies=AF_INET AF_UNIX` became `AF_INET`, and it now asserts there is no `AF_UNIX`.
* `tests/sandbox-abstract-1.17.123.py`: `_abstract_connect` fakes return the three-state result; the row texts carry `(N listed, M left out)`; the table filters on `abstract sockets (`; the docstring marks the 1.17.123 `AF_UNIX` decision as superseded.
* `tests/sandbox-memory-1.17.123.py`: the 1.17.123 row cases that now differ (exit 137 with no kernel evidence, 144 MiB, a peak-only run, timeout and exit 1) are changed; the limit-rows case now carries `oom_kills`.
* `tests/sandbox-canary-1.17.118.py`: the scripted canary table has the new socket rows, the memory evidence and the new `stub_ports` order.
* `tests/sandbox-launch-1.17.118.py`: the handoff file now also holds `oom_kills`.

## Held findings closed here

* 1.17.123 Low: memory row OK with no evidence (section 2).
* 1.17.123 Low: abstract-socket list against the 64 KiB stdin read (section 4).

## Not run here

Real systemd, root, Linux, cgroups, seccomp, Django and dev02 could not run on this PC. So these are unproven until dev02 runs `sudo bash tests/sandbox-canary-1.17.124.sh`: that `socket(AF_UNIX)` really fails with `EAFNOSUPPORT` in the unit, that `socketpair` and a child with stdio pipes still work there, that `--finish` still reads `memory.events` under the privileged `+` command, that the kernel's `oom_kill` counter is what the unit shows, that all six `127.0.0.53` rows report in time, and that the Claude and Codex CLIs run without `AF_UNIX`.

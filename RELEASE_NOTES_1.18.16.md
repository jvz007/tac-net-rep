# Tec-Tac Framework 1.18.16

Date: 19 November 2026. The last row of the sandbox canary that had no proof now shows the kernel's own evidence, and two small accuracy gaps from the 1.18.15 review are closed. This finishes Patch A of the sandbox plan. Nothing changes for modules, and the sandbox stays off.

## What changed and why

On dev02, Core 1.18.15 passed every canary row except the memory row. The probe reached 112 MiB and stopped with exit 1. The peak was 127.9 MiB of 128 MiB. The kill count read 0, so the row stayed NOT RUN. We now read more of what the kernel tells us.

### 1. Memory row: the kernel's counters decide

- `memory.events` has four counters we care about: `max`, `high`, `oom` and `oom_kill`. A new `parse_memory_counters` reads all four (same rule as before: only exact `<word> <digits>` lines count). `parse_memory_events` stays as a thin wrapper, so older tests and callers are unchanged.
- `CgroupWatch` keeps the highest value of each counter it sees, at every poll (every 0.02 s for canary runs) and in the forced re-read after the process exits.
- The end frame gains one key, `memory_events`, with the counters that were read. It is additive and internal (see Module-facing change).
- The row is OK on any one of three proofs:
  1. the kernel killed the run: end reason `oom`, or `oom_kill` of 1 or more;
  2. `memory.events` `max` of 1 or more, with a known peak at or below MemoryMax, an allocation at or below MemoryMax, and a probe that did not finish and did not exit 0 (the limit was hit and held);
  3. the probe itself reported `MemoryError` or `enomem`.
- ATTACK SUCCEEDED rules are unchanged: allocation or peak above MemoryMax, the probe finished, or exit 0. A missing peak is never OK on the `max` path. With no counters, no word and no kill, the row stays NOT RUN, so the 1.17.123 hole ("OK with nothing to show") stays closed.
- The row text ends with the proof it used: `proof: oom_kill N (memory.events)`, `proof: memory.events max N, peak X MiB <= Y MiB` or `proof: probe MemoryError at N MiB`. The counters (`max`, `high`, `oom`, `oom_kill`) are always printed when they were read.
- Why exit 1 printed nothing. We read the code: the probe's stderr is never dropped (error frames are collected into the result). A kernel SIGKILL cannot print, and `systemd-run --wait` returns exit 1 for a unit ended by a signal, so empty stderr is the expected result of a kill. This is inferred from the code and was not shown on this PC. The row now always adds the probe's first stderr line when there is one (before, only on NOT RUN), and the counters will show the cause on dev02.

### 2. Sweep: no second `run.ended` (held Low of the 1.18.15 review)

`note_swept_run` now checks `audit.jsonl` first. A new helper, `run_already_ended`, reads only the last 1 MiB of the file, parses only lines that contain `"run.ended"`, and compares `detail.run_id`. If the run already has its own row, the sweep writes no `swept` row. It also checks that the record file still exists immediately before writing. The record is still removed as before. An unreadable audit file claims nothing, so the one row is still written. The canary's step 5o now also fails when one run id has two `run.ended` rows.

A race of a few microseconds remains between that check and the launcher's own unlink-then-append. A duplicate row would be an accuracy gap in a log, not a security hole. A per-run lock would close it and comes back as a request if dev02 ever shows a duplicate. The canary's `sweep(min_age=0)` still can write a `swept` row, and remove the record, for a production run that has written its record but whose unit is not yet active. That is not in this request and stays in the backlog for a later patch.

### 3. `/run` privacy probe: seen or not seen, no cut (held Low of the 1.18.15 review)

The next-run probe listed `/run` but printed only the first 200 names. A marker sorting after 200 other names could be missed and the row would read OK. Now the helper puts the marker name in the plan (`{"run_marker": <name>}`, checked by the same name rule as in the writes probe). The probe prints one line, `CANARYRUNSEEN<TAB>1` or `0`. If `/run` cannot be checked or the plan has no valid name, it prints nothing, and the row is NOT RUN ("the next run could not report on /run"). `parse_run_listing` is replaced by `parse_run_seen`. The row text for the OK case is unchanged, so step 4v still matches `private per-run /run`.

## Module-facing change

None. The end frame gains an additive internal key, `memory_events`. Core's `_end_event` picks end-frame keys by name and drops the rest, so the module-facing result and the `RunHandle` end event do not change. The key is not in the `run.ended` audit row (the step 5o allow-list is unchanged). The sandbox contract, the refusal reasons and the helper modes are unchanged. `SANDBOX_ENABLED` stays False. Only `ai` and `reportmanager` use the sandbox contract, and nothing they call changed.

## Johan test checklist (dev02)

Run these in order. Each step says what a pass looks like and what to send back on a FAIL.

a. Install Core 1.18.16. PASS: the install ends without an error. FAIL: send the last 40 lines of the install output.

b. `sudo /usr/local/sbin/tec-tac-sandbox --selftest`. PASS: it ends `exit=0` with `ready true`. FAIL: send the selftest JSON.

c. List the skeleton again (`sudo find /usr/local/lib/tec-tac/sandbox/root | sort`). PASS: still 29 entries, no new name. FAIL: send the listing.

d. `sudo bash tests/sandbox-canary-1.18.16.sh`. PASS: it ends `ALL CANARY STEPS PASSED`, with all of these:
   - the memory row is OK and its text ends with a proof: `oom_kill N`, `memory.events max N` with a peak of 128 MiB or less, or `probe MemoryError` (step 4u);
   - `write /run` is OK and says `private per-run /run` (step 4v);
   - step 5o shows `problems=0` and no second `run.ended` for any run id;
   - 0 rows ATTACK SUCCEEDED and 0 rows NOT RUN.
   FAIL: send the canary log from `debug/`, the memory row (with its counters), the selftest JSON, and `journalctl -u 'tectac-sbx-*' --since '30 min ago'` (names and states only).

e. Run the canary a second time. PASS: the skeleton listing is unchanged and the audit log has no `skeleton.changed` row. FAIL: send the listing and the audit rows.

f. `sudo ls -A /run/tec-tac/sandbox/secrets /run/tec-tac/sandbox/handoff /run/tec-tac/sandbox/runs`. PASS: all three print nothing. Then check that the Tactical web page and an agent check-in still work. FAIL: send the listing and what you saw.

## What could not be run

Django is not installed on this PC, and there is no systemd, no cgroup v2 and no root. These could not run: the kernel's `memory.events`, the real OOM kill, the unit's own `/run`, the sweep against a real unit, the sudo rule and the installer. What ran: `bash tests/release-integrity.sh`, the new and touched sandbox tests with a fake systemd and file layer, `python -m py_compile` and `ruff check`. The dev02 canary is the proof.

## Assumptions

- Memory proof 2 (`max` of 1 or more with the peak at or below MemoryMax) is enough when no `oom_kill` was seen. On dev02 the kill count is probably missed because the cgroup of a `--collect` unit vanishes. The extra guards (known peak, allocation within the limit, probe not finished) keep it from passing on nothing.
- The additive end-frame key is the simplest way to hand the counters to the canary. A separate canary-only channel would add code and no trust.
- The sweep guard is a check, not a lock (see item 2).
- Deviation from the plan's wording: the row names its proof with `proof:` and not `evidence:`. The 1.18.8 test (unchanged) forbids the word "evidence" in the memory rows it covers, and the row already prints `evidence poll` for where a kill count came from.

## What is not in this release

- Patch B and Patch C of the sandbox plan: Patch B waits for a fully passing canary.
- The install-speed request ("Core install is slow again") and the probe transport request: they start after Patch C passes.
- The `sweep(min_age=0)` false `swept` row for a run whose unit is not yet active (see item 2).
- A read-only `/run` except the credentials directory: waits for the proof row to be OK on dev02.
- The other held sandbox Lows in the backlog.

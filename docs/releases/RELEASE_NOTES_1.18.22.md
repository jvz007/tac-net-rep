# Tec-Tac Framework 1.18.22

Date: 19 November 2026. The sandbox canary now prints the full text of any row the table cuts, so step 4u can see the memory row's proof. Enforcement does not change. `SANDBOX_ENABLED` stays `False`.

## Module-facing change

None. Canary output and a test script only. No contract, capability, endpoint or import changes.

## What changed and why

### 1. A DETAIL line for every cut row

The dev02 canary of 1.18.21 ran 153 steps OK and 1 failed: step 4u. The memory row was judged OK (step 4h passed). But `format_table` cuts the "actual" column at 140 characters (`ACTUAL_COLUMN_MAX`), so the `; proof: systemd unit result oom-kill` at the end of the row never reached the script's grep.

- New helper `detail_lines(table)` in `scripts/sandbox-helper.py`. For each row whose "actual" text is longer than the column, it returns `DETAIL <row id> <full actual text>`.
- The text is one line, printable ASCII only (anything else becomes `?`) and at most 600 characters. The ids are the same as the ROW lines (`assign_row_ids`, including the `-2` repeat rule).
- `run_canary_command` prints the DETAIL lines after the ROW lines and before the totals line.
- The table, the ROW lines, the verdicts, `canary_record` and `canary.json` are unchanged. `memory_row` judges exactly as before.

Why a detail line and not a wider column: the table width is for people reading it, and a wider column would only move the cut. `canary.json` holds no row text by design.

### 2. New script `tests/sandbox-canary-1.18.22.sh`

A copy of the 1.18.17 script with every step and number kept. Changes:

- Version strings and the copy hint say 1.18.22. The helper guard also needs the marker `detail_lines`, so a helper from before 1.18.22 is refused.
- Step 4u reads `DETAIL memory-beyond-memorymax` (and falls back to the table line when there is none). It passes when the detail holds `proof: (oom_kill|memory.events max|probe|systemd unit result oom-kill)`, or holds all of `ended oom`, `unit result oom-kill` and `evidence unit_result`. Step 4h still needs the row to end OK, so a NOT RUN or ATTACK SUCCEEDED memory row never passes through the new alternative.
- Steps 4k, 4l and 4m (and the information lines) ignore DETAIL lines, so a detail line is never counted as a verdict.

The 1.18.17 script stays in `tests/`.

### 3. Wording: who the end frame's exit and signal describe (held Low, 1.18.17 review)

The end frame's `exit` and `signal` come from systemd's record of the unit's main process. That process is `sandbox-launcher.py`. It runs the runner as a child and returns 128 plus the signal when the child died by a signal. So the values describe the launcher, not the sandboxed program. "killed by signal 9" means the launcher was ended by signal 9, because the cgroup OOM kill took the whole unit.

We corrected the words only: the comment in the end-frame code and the `memory_row` docstring. The row text, the end frame keys and their values do not change. `sandbox-memory-1.18.17.py` and `sandbox-unit-result-1.18.17.py` pass unchanged.

### 4. Held Low: manual check step d

The dev02 checklist below says what the memory row must show. "killed by signal N" and "unit result oom-kill" appear when the unit record held them. They are not required: a run where the program itself is killed can show "exit N" instead.

### Release bookkeeping

`RELEASE_NOTES_1.18.21.md` moved to `docs/releases/`. `tests/version-1.18.21.py` moved to `tests/legacy/`. New: `tests/version-1.18.22.py`, `tests/sandbox-canary-detail-1.18.22.py`, `tests/sandbox-canary-script-1.18.22.py`.

## Johan dev02 checklist

a. Update dev02 to Core 1.18.22 from the dev branch. PASS = the update finishes and Core starts. FAIL = it does not: send the error.
b. From the source folder (with its `tests/` and `scripts/` folders), run exactly: `sudo bash tests/sandbox-canary-1.18.22.sh`. PASS = it starts and prints step 1 lines. FAIL = "the installed helper is older than Core 1.18.22": the update in step a did not reach the installed helper.
c. PASS = the last line is `ALL CANARY STEPS PASSED`, with 0 ATTACK SUCCEEDED, 0 NOT RUN and 0 STEP(S) FAILED. FAIL = any `FAIL` line: send that line.
d. The memory row: step 4h and step 4u both show PASS. PASS = the row ends OK and the `DETAIL memory-beyond-memorymax` line names a proof. "killed by signal N" and "unit result oom-kill" show when the unit record held them. They are not required. FAIL = the row is NOT RUN or ATTACK SUCCEEDED, or the DETAIL line names no proof: send the DETAIL line.
e. Step 4u. PASS = it shows PASS. FAIL = it shows FAIL: send the `DETAIL memory-beyond-memorymax` line, the memory row and the unit cgroup path.
f. Confirm the sandbox is still off: `SANDBOX_ENABLED` is `False` and the status shows it disabled. PASS = off. FAIL = on: send the status output.

## What could not be run

- The real canary. It needs root, systemd, cgroup v2 and a Linux server (dev02).
- Anything that imports Django. Django is not installed on this PC. This release touches no Django code.

## Assumptions

- A DETAIL line instead of a wider column (see above). Not a security change.
- Wording only for the launcher: no behaviour or end-frame value changed. Not a security change.

## What is not in this release

- Any change to the sandbox's enforcement, limits, unit properties or kill switch.
- Mapping the launcher's 128+N exit back to "program killed by signal N".
- The open requests in `reviews/requests/core.md` and the backlog findings about the module install run. This release has one theme.

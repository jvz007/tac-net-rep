# Tec-Tac Framework 1.18.15

Date: 19 November 2026. The sandbox canary on dev02 now proves the one thing 1.18.14 left open, and its checker no longer fails on a row that passed. This release finishes Patch A of the sandbox plan. Nothing changes for modules, and the sandbox stays off.

## What changed and why

Johan's dev02 canary of Core 1.18.14 ended with 150 OK, 1 ATTACK SUCCEEDED (`write /run`), 1 NOT RUN (the memory row) and 10 failed steps. Most of those steps failed only because of those two rows. Five items fix the rest.

### 1. `write /run`: prove it, do not assume

With a private root folder, systemd gives each unit its own tmpfs on `/run`. We need that for the credential copies. The row said "written" and counted as an attack. Now it is a proof.

- The writes probe no longer deletes its file in `/run`. It writes a marker named by the helper (`.tectac-run-marker-` plus 16 random hex digits; a name from the plan, never a path) and prints the name.
- The helper checks from the host that the marker is not in the skeleton's `run/` folder (`SANDBOX_ROOT/run`, an empty mount point). It then starts one more small run (`runview`) that lists its own `/run`, and checks that the marker is not there either.
- The row is OK only when both hold. Its text then reads "written, private per-run /run: not in the skeleton, not seen by the next run". The marker in either place stays ATTACK SUCCEEDED. A check that cannot be made (no marker reported, skeleton unreadable, the next run did not list) is NOT RUN. A refused write (read-only `/run`) stays OK as before.
- The other eight `write /` rows are unchanged, and the group still needs nine of them.
- The helper removes nothing it did not create. The marker lives in the unit's tmpfs and goes away with the unit.

**Decision: no unit property changed for `/run`.** We did not add `TemporaryFileSystem=/run:ro` or a size cap. Whether systemd 255 still mounts `/run/credentials/<unit>.service` under a read-only `/run` cannot be shown on this PC (no systemd, no root, no Django). A wrong property would break credential delivery for every real run. The kernel charges tmpfs pages to the run's memory cgroup, so a run cannot fill `/run` past its memory limit. That is kernel behaviour and is not proven here: the canary does not measure it. Follow-up for Patch B or C review: mount `/run` read-only except the credentials directory, only if dev02 proves it. `check_unit_properties` and the exact property sets are untouched.

### 2. Memory row NOT RUN

- The probe now allocates in 4 MiB steps, writing every page, up to twice MemoryMax. The helper asks for `2 x memory_mb` (256 MiB for the 128 MiB row) instead of the fixed 600. It prints `CANARYMEM` after each step and sleeps about 20 ms between steps.
- A refused allocation prints the row `MemoryError at <N> MiB` (or `enomem at <N> MiB`) and the end word, and no longer crashes the probe. The table row now also names it: "probe memoryerror, MemoryError at N MiB". Any other exception still ends with `CANARYEND other:<Name>`.
- Held Low (end-of-run evidence): the cgroup of a `--collect` unit is gone by the time `systemd-run --wait` returns, so a kill in the last poll interval was lost. `CgroupWatch` takes an interval. Production runs keep 0.2 s, so their cost is the same. Canary runs poll every 0.02 s and the supervise loop wakes at the same rate for them. The forced re-read after the process exits stays for the cases where the cgroup still exists.
- `memory_row` keeps its rules. Swap is already denied (`MemorySwapMax=0`, `MemoryZSwapMax=0` on 255), so an `oom_kill` is expected. If dev02 still shows no evidence, the stderr text and the slow steps will say why.

### 3. Step 4t false FAIL

The canary checker looked for the full label with `grep -F`, but the table cuts a column at 60 characters. The label 'credential source folder is gone while the run is still active' is 62 characters (the request said 69; the cause is the same).

- After the table and before the totals, the helper prints one machine line per row: `ROW <id> <verdict>`. The id is the row's own `id` or a slug of its label (`[a-z0-9-]`, at most 40 characters, unique in the table). It is never a path or module text.
- Every verdict lookup in step 4 of the new script reads those lines by id. The table stays for people and for the steps that check what a row says (the MiB, the oom_kills, the listener counts). `canary.json` keeps its fields.
- The two credential clean-up rows carry explicit ids (`credential-source-gone`, `no-host-command-property`).
- Check of every 4x lookup: only 4t's label was longer than 60 characters. All others are under 60. The new test `sandbox-canary-ids-1.18.15.py` fails if a script lookup ever relies on a longer label, and checks that every label in the helper and the runner gives a unique id.

### 4. Step 5o: run a56fed3d has no `run.ended`

The request called it an old run. Reading the code and the log shows it is this canary's own "SIGKILL the helper" run. A killed helper never reaches its `finally` block, so it writes no `run.ended`. The canary's own sweep at the end of the Cancel group then removes the run file. (The log prints it first because the table prints last.) The fix is the one the request asks for, with that corrected finding:

- The sweep writes `run.ended` with reason `swept` for every `runs/<32 hex>.json` it removes. It never does this for secrets or handoff entries, and never for a live unit (the sweep already skips active units and young files).
- The run record written at launch gains `person` (the person key hash already used in the audit) and `canary`. A record from an earlier build has neither: its swept row then has `person` empty and `canary` false.
- The swept row holds only `runner`, `run_id`, `person`, `canary` and `reason`. It uses `append_audit_safely`. The sweep's own `removed` list is unchanged. No credential, input, output or path.
- Step 5o still counts only audit rows after the lines that existed when the canary started, accepts a swept row as the ended row of a started run, and prints the number of swept rows.

### 5. Credential remover gives up with no record (held Low)

`launch()` threw away what `remove_credentials_when_active` returned. A small wrapper, `remove_credentials_noted`, now writes the root audit row `run.credentials_lingered` with `run_id`, `runner` and `seconds` only when the remover timed out and its stop event was not set. A run that ended early or a successful removal writes nothing. The `finally` block still removes the folder on every path, so trust is not widened. The canary script has a new step (5p) that fails if its window holds such a row. A healthy dev02 shows none.

## Module-facing change

None. The sandbox contract, the end frame keys, the refusal reasons and the helper modes are unchanged. Only `ai` and `reportmanager` use the sandbox contract, and nothing they call changed. The new audit events and keys (`run.ended` reason `swept`, `run.credentials_lingered`, the `ROW` lines, `person` and `canary` in the run record) are root-helper internals and additive. `SANDBOX_ENABLED` stays False.

## Johan test checklist (dev02)

Run these in order. Each step says what a pass looks like and what to send back on a FAIL.

a. Install Core 1.18.15. PASS: the install ends without an error. FAIL: send the last 40 lines of the install output.

b. `sudo /usr/local/sbin/tec-tac-sandbox --selftest`. PASS: it ends `exit=0` with `ready true`, and `credential`, `real_unit_shape` and `sandbox_root_after` all ok. FAIL: send the selftest JSON.

c. List the skeleton again (`sudo find /usr/local/lib/tec-tac/sandbox/root | sort`). PASS: still the same 29 entries as for 1.18.14, no new name. FAIL: send the listing.

d. `sudo bash tests/sandbox-canary-1.18.15.sh`. PASS: it ends `ALL CANARY STEPS PASSED`, with all of these:
   - `write /run` is OK and its text says `private per-run /run` (step 4v);
   - the memory row is OK, with a kernel `oom_kills` of at least 1 or `MemoryError at N MiB` (step 4u);
   - step 4t is OK;
   - step 5o shows `problems=0` and a swept count (expected: 1);
   - step 5p finds no `run.credentials_lingered` row;
   - 0 rows ATTACK SUCCEEDED and 0 rows NOT RUN.
   A latency p95 above 400 ms stays a WARN and is not a failure (unchanged). FAIL: send the canary log from `debug/`, the selftest JSON, the `find` listing and `journalctl -u 'tectac-sbx-*' --since '30 min ago'` (names and states only).

e. Run the canary a second time. PASS: the skeleton listing is unchanged and the audit log has no `skeleton.changed` row. FAIL: send the listing and the audit rows.

f. `sudo ls -A /run/tec-tac/sandbox/secrets /run/tec-tac/sandbox/handoff /run/tec-tac/sandbox/runs`. PASS: all three print nothing. Then step 6 as before: the Tactical web page and an agent check-in still work. FAIL: send the listing and what you saw.

## What could not be run

Django is not installed on this PC, and there is no systemd, no cgroup v2 and no root. These could not run: the unit's own `/run`, the kernel's OOM kill, the supervise loop against a real cgroup, systemd's credential copies, the sudo rule and the installer. What ran: `bash tests/release-integrity.sh`, the new and the touched sandbox tests with fake systemd and a fake file layer, `python -m py_compile` and `ruff check`. The dev02 canary is the proof.

## Assumptions

- The marker check is a proof of privacy from outside (skeleton and next run). We assume a unit that wrote to a shared `/run` would show the marker in one of those two places.
- Writing `person` and `canary` into the run record is safe: the person key is the same hash the audit already holds, and the runs folder is root 0700.
- The 15 s window of the credential remover is unchanged. A record is written only for a genuine timeout.
- Item 4: the finding was corrected as described above; the fix is the one the request asked for.

## What is not in this release

- Patch B (PrivateNetwork, egress proxy) and Patch C: Patch B waits for this canary to pass.
- The install-speed request ("Core install is slow again"): it starts after Patches A to C pass.
- Latency p95 452 ms (target 400): stays a WARN.
- The optional selftest-readiness gate for the credential remover: a separate theme that would change readiness. Only the audit row is built.
- The other held Lows of 1.18.13 (post-run re-check owner and mode, a re-check overwriting a newer status, `/run/systemd` contents unchecked).
- A read-only `/run` or a size cap on it: see item 1.

# Tec-Tac Framework 1.17.79

Date: 26 October 2026. Fixes the three held findings of the 1.17.78 review on the background send-command path (`agent.command`). No migration, no new route, no new setting, no contract change. `core.system_actions` stays at 1.5.0.

## What changed

1. **MEDIUM: a refused route no longer burns the command id.** `run_one` now runs the route check before the per-run count and before the 24-hour claim. Before, `_send` ran it after the claim and the audit row, so a refusal left the claim in place and a retry read as `duplicate_command`. A refusal now leaves no claim, no count and no audit row. `_send` keeps its own check as a second guard.
2. **LOW: the owner check is honest about what it does.** The check compares the fixed id `OWNER_MODULE` with Core's static owner table, so it always passes today. It does not read whether Remote Background is installed or enabled. I corrected the 1.17.78 notes instead of adding a lookup: the caller-verified path already fixes the owner, and a lookup would widen what Core reads. The 1.17.78 checklist step 3 (disable Remote Background) is withdrawn for that reason.
3. **LOW: release notes.** The 1.17.78 notes called two tests pre-existing failures although that release edits them. The wording is fixed. The 1.17.78 notes moved to `docs/releases/`; only the current notes stay at the root, as `tests/release-integrity.sh` requires.

## Module-facing change

None. Same contract, routes and refusal reasons. A refused route is still `function_unavailable`.

## Tests

`tests/system-command-1.17.79.py` (new, no Django) goes through `run_one`: a refused route leaves no claim, no count, no audit row and no send; the retry with the same command id runs; a second run is still `duplicate_command`.
`tests/system-command-worker-schedule-1.17.77.py` now stubs `_check_route` because `run_one` calls it; the owner table stays covered by the 1.17.78 and 1.17.79 tests.

Not run here: Django, Tactical's real view dispatch, `system-writes-runtime-1.17.70.py`.

## Test checklist (dev02)

1. Run a Communicator background schedule for one endpoint (Run now). **Expected:** the command runs and the audit shows one row. **FAIL:** `function_unavailable` on a healthy server. Send back: the run history entry and the Core log line "route is not owned".
2. Run the same command again with the same command id. **Expected:** refused as a duplicate, nothing sent. **FAIL:** sent twice. Send back: the endpoint's Tactical command history.
3. Run a different command id to the same endpoint. **Expected:** it runs. **FAIL:** refused as `duplicate_command` or `function_unavailable`. Send back: the run history and the Core log.

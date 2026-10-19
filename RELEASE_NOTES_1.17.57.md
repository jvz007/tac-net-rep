# Tec-Tac Framework 1.17.57

This is a decision record. Johan extended one existing rule, and this release records it. There is no code change, no contract change and no module change. There is no install step beyond the usual Core update.

## What was decided

Johan answered Q-APM4 and CQ163 in chat on 19 October 2026, option (d). It extends AD-40. It is not a new decision, so there is no AD-41.

- **What is allowed.** Advanced Patch Management (`patchmanagement`) is the honoured replacement of Windows Patching. An honoured replacement is the premium module Core lets stand in for a core module while that one is switched off (AD-20). It may now read the rows of two Tactical models: `WinUpdate` (AD-40 already allowed it) and `WinUpdatePolicy` (new).
- **The limits stay.** The reads are read-only. They are role-filtered through the visible ids the Agents contract gives the module. They live in one named accessor, the one file where the reads sit. They never write Tactical's tables and never use Tactical's Agent model. The module names the boundary in its release notes and in `reviews/questions/`.
- **What it gives.** Advanced Patch Management can serve all five `patching.resources` operations (`get_agent_patch_settings`, `get_policy_patch_settings`, `add_patch_policy`, `update_patch_policy`, `delete_patch_policy`) and the reset of patch policies for all endpoints, with full parity.
- **How long.** Until the owner's public read contract exists and can serve while the replacement is honoured. The request for it stays in `reviews/requests/core-modules.md` (patching).
- **Why, in Johan's words.** A premium module must not need core modules changed for it. If the replaced core module comes back, modules changed for the premium one would no longer work correctly. That rules out asking Agents and Automation to publish reads, and it rules out accepting the loss.
- **Other premium modules.** The clause does not widen the premium rule for any of them.

## Where it is recorded

These files sit at the project root, outside this package, so the signed Core zip does not contain them.

- `docs/tec-tac-module-standard.md`: the premium row of the design table and the AD-40 bullet. The bullet's end condition now points at `reviews/requests/core-modules.md`. It said `reviews/requests/core.md`, where the entry no longer lives.
- `docs/review-accepted-decisions.md`: row 40.
- `docs/review-checklist.md`: line A2 names the two models.
- `reviews/requests/core.md`: the request to record an option (a) amendment is removed, because (a) was not chosen. Nothing records a loss.
- `reviews/questions/premium-modules.md` (Q-APM4) and `reviews/questions/core.md` (CQ163): marked answered, with the line "Core builds nothing".

## Module-facing change

Nothing changes for any module. No contract, operation, route or capability moves. Patchmanagement's own next release is the one that uses the extension.

## What does not change

Everything under `framwork/`, the public contract export, Core UI, and every module.

## Tests

- New: `tests/decision-record-ad40-winupdatepolicy-1.17.57.py`. It checks the version, these notes, the 1.17.56 notes move and, when the project root is reachable, the decision documents. It needs no Django.
- `RELEASE_NOTES_1.17.56.md` moved to `docs/releases/`.

## Dev-server check (Johan)

Install the signed 1.17.57 build. Open Tec-Tac, the Core version shows 1.17.57. PASS if the version shows 1.17.57 and nothing else changed. FAIL if the version is lower, or any module, page or setting behaves differently; send back the version shown and what changed.

## Requests closed or answered

- Answered: Q-APM4 and CQ163, option (d).
- Removed: "record the AD-20 amendment for patchmanagement" (`reviews/requests/core.md`), because it asked for option (a).

## Not run on the build PC

Django is not installed on this PC. This release has no code that needs it.

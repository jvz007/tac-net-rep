# Tec-Tac Framework 1.17.69

Date: 21 October 2026. No migration. No new route, capability or contract row. `core.system_actions` stays 1.2.0.

This release closes the three Medium findings left open by the 1.17.68-2 review. It changes what a scoped engineer can do in three places, and it closes a gap that would have let one module pose as another. Nothing else moves.

What changes for a person:

- **A scoped engineer can now take over a delegated grant** when their own Tactical scope covers every endpoint it names. Before, Core asked the wrong module's resolver and always said no.
- **A scoped person can no longer save a schedule whose profile names no endpoint.** Core cannot check an empty list against a Tactical scope, so it asks for at least one endpoint. An unrestricted person and a scheduler manager are not affected.
- **A module can no longer pose as another module through the delegation functions.** Core reads the caller from the call stack inside those functions, so naming someone else's id does nothing.

## What changed and why

1. **Grant takeover is judged by the owner module's resolver (review finding Medium 1; AD-42, AD-44).** `delegation.register` checked a second person's scope with `scheduler._person_covers_targets`, which looks the resolver up under the provider module (patchmanagement). The target type `profile` belongs to the owner (maintenance), so no resolver was found and a scoped engineer was always refused with `takeover_out_of_scope`. A new one-line seam, `delegation._owner_scope_check(person, owner_module, targets)`, now asks the owner's resolver first, strict (no scheduler-manager shortcut). True or False is the answer; a fault is False; only when no resolver applies does the old `_person_covers` seam decide. `scheduler._person_covers_targets` and the three-argument `_person_covers` are unchanged. A refusal still changes nothing (owner, scope and stored targets stay as they were) and writes one deny row.
2. **A resolver that names no endpoint no longer passes the scope check (Medium 2; AD-42).** `scheduler._resolver_scope_check` answered True for an empty list. It now answers False when `strict` (a takeover, for everyone), and, with the new keyword `refuse_empty=True`, at creation for a person who is not a native scheduler manager and whose Tactical scope is not unrestricted. The two creation call sites set it: `_check_person_may_schedule` (a module-owned schedule saved with a person's request) and `start_one_off_run`. They refuse with a plain text of their own, `EMPTY_TARGET_LIST_REFUSED`: "This target list names no endpoints, so Core cannot check it against your Tactical scope. Add at least one endpoint and try again." The run-time owner check (`_runtime_authorization_error`) and every read, edit and view path keep today's answer, so an empty profile never fails a run that has nothing to do and never hides a schedule from a scoped person. `resolve_agent_pks` still returns an empty set. System actions already refuse an empty set. The takeover through `reconcile_schedule` or the browser PATCH keeps its existing plain text (`TAKEOVER_REFUSED`), because that text is part of the `TakeoverRefused` contract row; only the answer behind it changed.
3. **The delegation functions no longer trust a caller argument (Medium 3; AD-43, hardening H1 for this one finding).** `delegation.describe`, `register`, `remove`, `issue_ticket` and `start` took `caller` as their first argument, and only the wrappers in `system_actions.py` checked it, so a module that imported `tec_tac.delegation` could pass `'maintenance'`. The parameter is gone. Each function now calls a private `_verified_caller()` at the top, before any other check, and gets the caller from the call stack. The walk skips every frame of `delegation.py` and `system_actions.py`, so the capability route, the five wrappers and a direct import all give the same answer: the first frame outside both files must be an installed, enabled, non-legacy module, otherwise `caller_unverified`. Core is never a caller. To make that possible `caller_identity` takes `provider_file` as a string or, additively, as a non-empty tuple of file paths (`_checked_from`, `_core_provider_caller`, and the docstring of `calling_module_for_core_provider`). Every existing caller passes a string and sees no change; an empty tuple, a list, or a tuple holding anything that is not a path is unverifiable. The review's wording (walk with `provider_file=system_actions.__file__`) could not work as written, because the walker skips one file only and stops at the first `delegation.py` frame, which is Core code. The wrappers in `system_actions.py` no longer pass a verified id, and its private `_verified_caller` is removed (no test referenced it). The signatures of the five public functions in `system_actions.py`, the capability operations and every reason code are unchanged. Docs updated: `docs/system-actions.md` (Delegation) and `docs/caller-identity.md`.

Closes the three Medium findings of the 1.17.68-2 review (grant takeover resolver, empty resolver, delegation caller trust). Nothing in `reviews/requests/core.md` is closed by this release.

## Module-facing changes

None. Nothing a module can call changed shape, version or reason code.

What I checked in `modules/`: no module calls `describe_delegation`, `register_delegation_grant`, `remove_delegation_grant`, `issue_delegation_ticket`, `start_delegated_run` or `register_target_resolver`, and none touches the private helpers this release changes (`_resolver_scope_check`, `_check_person_may_schedule`, `delegation.*`, `caller_identity._checked_from`). `patchmanagement` only registers system actions and calls `run_system_action`, which is unchanged. `maintenance` registers no resolver yet. So the fixes are in effect before the first module wires up the delegated start.

One effect for the module that will register a profile resolver: a profile that names no endpoint cannot be saved with a schedule by a scoped, non-manager person until it names one. An unrestricted person or a scheduler manager is not affected.

## Tests

New: `tests/delegation-fixes-1.17.69.py` (all three fixes on the shared harness, with no stub on `delegation._person_covers`), `tests/caller-identity-1.17.69.py` (the tuple form), and `tests/delegation-fixes-runtime-1.17.69.py` (a small script for `manage.py shell`).

**One existing assertion was changed on purpose.** `tests/scheduler-target-resolver-1.17.68.py` line 274 said a resolver that names no endpoint is True in strict mode ("reaches nothing"). That is the behaviour this release fixes, so the expectation is now False. The 1.17.68 notes moved to `docs/releases/`, as every release does for the one before it, so `tests/contract-catalog-1.17.68.py` now reads them there and checks that `VERSION` and the package agree instead of pinning 1.17.68 (the same step 1.17.68 took for 1.17.67). Nothing else in that file or any other test was deleted, skipped or weakened.

The existing `delegation-*.py`, `caller-identity-*.py`, `event-jobs-caller-1.17.47.py`, `scheduler-target-resolver-1.17.68.py` and `scheduler-ownership-move-1.17.68.py` tests pass unchanged apart from the assertion above.

## Not in this release

- **CQ203** (a second kind of Tactical write for a premium replacement). Johan said not in this batch.
- **Hardening batches H1 to H3.** This release closes only the delegation-caller Medium, the part of H1 Johan named. The rest of H1, and H2 and H3, stay for separate small releases.
- The Low finding about lockdown settings decided once at start-up (`patch_lockdown.py`).
- The empty-resolver refusal is not applied to the run-time owner check or to the read, edit and view paths. That is deliberate (see item 2).

## What I could not do here

- **Django is not installed on this PC.** `manage.py makemigrations --check` (no migration in this release, it must say "No changes detected") and every ORM-touching test wait for the dev server. The unit tests use the stub harness.
- **`tests/delegation-fixes-runtime-1.17.69.py` did not run here.** It needs the dev server.
- **The workspace was not level with signed dev.** `tectac core sync core` refused (the workspace carries the five unsigned 1.17.68 to 1.17.68-2 commits, which differ from signed dev only in `VERSION`, `tec_tac_package.json`, the signed manifest and the release-notes file name). The run did not reset by hand. 1.17.69 is committed on top of them. `RELEASE_NOTES_1.17.68-2.md` moved to `docs/releases/RELEASE_NOTES_1.17.68.md` (the archive test forbids a rebuild suffix there, and signed dev uses that name) because `tests/release-integrity.sh` allows exactly one note at the root.
- `tec-tac-release.json` and its signature are made by the pipeline and were not touched.

## Dev-server checklist

Johan installs and tests, after the build is signed and dev is updated. Each step says what to do, what you should see, when it is a FAIL and what to send back.

1. **Update.** Update the dev server to Core 1.17.69. Restart Core and the Celery workers. Run `manage.py migrate tec_tac` (expect: nothing to apply) and `manage.py makemigrations --check --dry-run` (expect: "No changes detected"). FAIL: any migration is listed. Send back: the output.
2. **Runtime scripts.** Run `tests/delegation-fixes-runtime-1.17.69.py` through `manage.py shell` (the command is in its header), then the three 1.17.68 runtime tests (`tests/patch-lockdown-runtime-1.17.68.py`, `tests/scheduler-creation-scope-runtime-1.17.68.py`, `tests/delegation-runtime-1.17.68.py`). Expect: every file ends with a PASS line and no traceback. FAIL: any traceback or a line starting FAIL. Send back: the full output of the failing file.
3. **Scoped engineer, schedule save.** Sign in as an engineer limited to one client. Save a Maintenance schedule on a profile that names endpoints inside that client: expect it saves. Save one on a profile that names no endpoints: expect it is refused with "This target list names no endpoints, so Core cannot check it against your Tactical scope." FAIL: the empty profile saves, or the text says "outside your Tactical scope" instead. Then sign in as an unrestricted administrator and save the same empty-profile schedule: expect it saves as before. Send back: a screenshot of the message and the audit row.
4. **Nothing else moved.** Open Scheduler as an administrator: existing schedules list, edit and run as before. Run one existing Maintenance schedule (not a patch install): expect the run finishes. FAIL: any schedule disappears from the list for a scoped engineer, or a run ends with "no longer within the owner's Tactical scope". Send back: the schedule name and the run's message.
5. **Delegation caller.** The runtime test in step 2 covers the module impersonation case, because no installed module calls the delegation functions yet. Expect its output to say that a module naming another module as the owner is refused (wrong_module) and a call from Core code or from the shell is refused (caller_unverified). FAIL: either call is accepted. Send back: the output.
6. **Contract export.** Export a fresh public contract into `docs/contracts` and run `manage.py tec_tac_check_contract_export` on it. Expect: it passes, `core.system_actions` is still 1.2.0, no new capability. FAIL: any difference. Send back: the check output.

If steps 1 to 6 pass, the release is good. If one fails, send the step number and the text asked for under it.

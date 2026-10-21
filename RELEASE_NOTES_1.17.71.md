# Tec-Tac Framework 1.17.71

Date: 21 October 2026. No migration. No new route. `core.system_actions` stays at 1.3.0. One new capability, `core.module_dependants` 1.0.0 (additive).

Two changes. Both close something that was waiting.

- **A retry can no longer change what a run writes.** The 1.17.70 review held one Medium finding: a system write that failed at its audit row could be retried with the same updates and other decisions, and the retry would then write the new decisions. The audited decisions and the written decisions could differ. That cannot happen now.
- **A module can ask who depends on it.** Groups needs this before it can refuse to delete a group that is still in use (Johan, 21 October 2026: "if any group is used somewhere and not allow it to be delete"). Core now reports which installed modules name the caller in their signed dependencies.

What changes for a person today: nothing. No module uses either change yet. The Groups release that turns the in-use check on comes after this Core is signed.

## What changed and why

### 1. A write retry is bound to its decisions

Closes the held MEDIUM from the 1.17.70 review.

1. `_digest` and `_plan_digest` in `system_actions.py` take an optional `decisions` mapping. With `None` the formula is exactly the old one, so every task row keeps its digests. For a write, the sorted `update_id:action` pairs go into the group digests and the plan digest. The run key and every group mark now change when one action changes.
2. The stored plan of a write also keeps the ids-only digest (`ids_key`). On a retry, Core looks for a stored plan with the same updates and other decisions. Nothing is ever written for it:
   - If one of its groups was claimed, sent or left unknown, the run ends `OutcomeUnknown` with a plain sentence that the decisions changed and Core did not write again.
   - If every group mark was aborted (or none exists), the run ends `skipped` with the new refusal `decisions_changed` and one `deny` audit row.
3. A retry with the same updates and the same decisions finds the same plan and works as before. The retry after a failed audit row writes once. A second call of the same run with other update numbers still works.
4. A plan written by 1.17.70 has no `ids_key`. Core reads its `targets_digest` as the ids-only digest. So a run that was in flight across the upgrade and retries is refused (`decisions_changed`) or ends `OutcomeUnknown`. That is the safe side. Start a new run.

The refusal text: "This run already tried these updates with other decisions, so Core wrote nothing new. Start a new run if you want the new decisions."

### 2. Module dependants

1. `registry.PluginSpec` gets two trailing fields, `dependencies` and `optional_dependencies`: sorted `(module id, version constraint)` pairs, empty by default. They are left out of equality and repr, like `system_actions`, so every older `PluginSpec(...)` call and every test stub stays valid. The manifest reader is lenient and never raises: a missing key, a value that is not an object, or a blank id gives an empty tuple for that key. The module manager already refuses a malformed manifest at install, and the registry must never stop Tactical starting.
2. New `tec_tac/module_dependants.py` with `dependants(*, context=None)`. It returns `{module, dependants, complete}`. Each dependant row is exactly `{id, name, version, relation, constraint, enabled, capabilities}`. Nothing else leaves Core: no routes, permissions, settings, paths, audit events or data of the dependant.
3. New capability `core.module_dependants` 1.0.0 (operation `dependants`, needs framework >=1.17.71), registered in `apps.py` in its own `try` block. A fault is logged and never stops start-up.
4. One contract row (area `module-dependants`) and `docs/module-dependants.md`. One line in `docs/capabilities.md`.

## Module-facing

- **New: `core.module_dependants` 1.0.0.** A module calls `tec_tac.module_dependants.dependants()`, or gets the provider with `get_capability('core.module_dependants', version='>=1.0.0,<2.0.0')`. Needs framework `>=1.17.71`: the module declares the capability under its manifest `requires` and the framework bound. No module has to change for this release.
  - The caller is the verified, enabled, non-legacy module whose code made the call (rule 1.10, AD-26). Core itself, an unverified caller, a disabled module or a legacy module is refused with `DependantsRefused`. The text names no module.
  - The answer is about the calling module's own id only. A module cannot list the dependants of another. (Q-CORE-DEP1.)
  - A disabled dependant is listed with `enabled: false`, because its saved configuration still points at the caller. The caller decides what that means. (Q-CORE-DEP2.)
  - Rows are sorted by id, at most 200. `complete` is `False` when more exist. A caller that needs the whole answer treats `False` as "could not check".
  - An unreadable module list or module state raises `DependantsUnavailable`. It never answers an empty list. Groups treats it as "could not check, do not delete".
  - Core calls no provider on behalf of a module. A dependant that declares `<id>.groups_usage` is a provider Groups asks itself through `get_capability`. A dependant that declares none is "in use, not checked".
- **New: `PluginSpec.dependencies` and `PluginSpec.optional_dependencies`.** Additive, defaults `()`. Modules that read the registry (`reportmanager`, `serverhealth`) read existing fields only, so they are unaffected.
- **Changed: the write contract (`run_system_write`).** One added refusal reason, `decisions_changed`, listed under `write.refusal_reasons` and in `REASONS`. It is a permanent `SystemActionRefused`: the run ends `skipped` and the worker does not retry it. A module that retries a run with other decisions is now refused (nothing sent) or ends `OutcomeUnknown` (part sent). Same decisions: no change. `core.system_actions` stays at 1.3.0: this is a behaviour fix inside the existing write contract plus one added refusal reason, and five existing tests pin 1.3.0.
- No module in `modules/` calls `run_system_write` yet, so nothing there breaks. Advanced Patch Management is the first expected caller.

## Requests and questions

- **Closed:** the four entries under "From groups 0.3.0" in `reviews/requests/core.md` (the placeholder `groups.usage`, `core.groups_usage`, "show each enabled module's dependencies in the plugin registry", and "a usage contract Groups may call"). Shipped in 1.17.71 as `PluginSpec.dependencies`, `optional_dependencies`, `module_dependants.dependants()` and `core.module_dependants`. The Scheduler has no group reference, so no `core.groups_usage` is built.
- **Held MEDIUM about the retry digests:** closed by 1.17.71 (the release-manager records this in `reviews/core/BACKLOG-new-findings.md`).
- **Requests written for other lanes:** Groups 0.4.0 switches the in-use check on; Advanced Patch Management publishes `patchmanagement.groups_usage`. Both are in `reviews/requests/premium-modules.md`.
- **Questions for Johan (assumptions built, no wait):** Q-CORE-DEP1, Q-CORE-DEP2, Q-CORE-RETRY1 in `reviews/questions/core.md`.

## Not in this release

- Hardening batches H1 to H3 (Johan: one at a time, after this release).
- The signed public contract export for 1.17.68 to 1.17.71. It is made on a running server and signed by the release-manager (checklist step 8).
- The rest of `reviews/requests/core.md` (reboot with a result, software uninstall, checks, commands, tasks and reports, module-owned recurring targets) and the other held findings in the backlog.
- `core.groups_usage` and a Scheduler-side `groups.usage`. Nothing in the Scheduler names a Groups group, and a capability id must begin with its owner's id, so Core cannot publish `groups.usage`. The dependency list answers the need.

## What I could not do here

- **Django is not installed on this PC.** `manage.py makemigrations --check` (this release has no migration), `tec_tac_check_contract_export`, the real `capabilities.py` registration and `get_capability` lookup, and the two runtime scripts wait for the dev server.
- **`tests/module-dependants-runtime-1.17.71.py` did not run here.** It needs the dev server. The retry fix ships no runtime script: its logic is pure and is covered by `tests/system-writes-retry-1.17.71.py` on the harness. The existing `tests/system-writes-runtime-1.17.70.py` still applies (step 2).
- Three older tests fail on this PC with and without this release, because they scan `modules/` and Advanced Patch Management already uses the names they watch: `system-actions-compat-1.17.61.py`, `scheduler-compat-1.17.63.py` and `scheduler-compat-1.17.66.py`. They are not touched.

## Tests

- `tests/system-writes-retry-1.17.71.py`: other decisions on a retry after an aborted attempt refused as `decisions_changed` (fails on 1.17.70); same decisions written once; two groups with part sent ends `OutcomeUnknown`; digests unchanged for tasks and covering decisions for writes; a disjoint second call works; the reason is listed; a 1.17.70 plan is refused or ends outcome-unknown.
- `tests/module-dependants-1.17.71.py`: the registry fields, `dependants()` rows, refusals, fail-closed reads, sorting and the 200 cap, the capability, the contract row, `apps.py` and the docs.
- `tests/module-dependants-runtime-1.17.71.py`: for the dev server.
- `tests/audit-declared-browser-events-1.16.0.py` pinned the position of the last `PluginSpec` fields from the end of the list ("system_actions comes last"). It now says the two dependency fields come last. The check is as strict as before: new fields are only appended.

## Checklist for the dev server (Johan)

Update the dev server to Core 1.17.71 from the dev branch, restart Core and the Celery workers, then go in order. Core source is `/opt/tec-tac-src/framework/`. Every shell block starts with `sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py ...'`.

1. **Migrations.** `manage.py makemigrations tec_tac --check --dry-run`. Expected: "No changes detected". FAIL: any migration is listed. Send back: the output.
2. **Write path still works.** `manage.py shell < /opt/tec-tac-src/framework/tests/system-writes-runtime-1.17.70.py`. Expected: last line PASS, no FAIL line. FAIL: any FAIL line or a traceback. Send back: the full output. (This release ships no new write runtime script.)
3. **Dependants runtime script.** `manage.py shell < /opt/tec-tac-src/framework/tests/module-dependants-runtime-1.17.71.py`. Expected: last line PASS; one line says a shell is refused with a sentence that names no module. FAIL: any FAIL line or a traceback. Send back: the full output.
4. **Registry fields.** `manage.py shell -c "from tec_tac import registry as r; p=[x for x in r.get_plugins() if x.plugin_id=='patchmanagement']; print(p[0].dependencies if p else 'patchmanagement not installed'); print(p[0].optional_dependencies if p else '')"`. Expected: the declared pairs, or "patchmanagement not installed". FAIL: a traceback, or a module that declares dependencies showing an empty tuple. Send back: the printed lines and the module's `tec_tac.json` dependencies block.
5. **Capability row.** `manage.py shell -c "from tec_tac.capabilities import has_capability; print(has_capability('core.module_dependants', version='>=1.0.0,<2.0.0'))"`. Expected: `True`. FAIL: `False` or a traceback. Send back: the output and the Core log lines from the restart.
6. **A shell is not a module.** `manage.py shell -c "from tec_tac import module_dependants as m; print(m.dependants())"`. Expected: `DependantsRefused` with a plain sentence that names no module. FAIL: a list is returned or any module id is printed. Send back: the output.
7. **Existing behaviour.** Open the Modules page and the Scheduler page. Expected: every module shows as before and Advanced Patch Management's scan and install schedules are listed. FAIL: a module refused or disabled, or a schedule missing. Send back: a screenshot and the Core log lines around the restart.
8. **Contract export.** Export a fresh public contract into `docs/contracts` and run `manage.py tec_tac_check_contract_export <path of the new export>`. Expected: PASS, and the export lists the `core.module_dependants` row and the `decisions_changed` refusal. FAIL: any listed mismatch. Send back: the output and the file name.
9. **Groups check.** Waits for a signed Groups release that turns the check on. Then: create a group, link it from a rule or profile in Advanced Patch Management, and try to delete the group on the Groups page. Expected: the delete is refused with a plain sentence naming where it is used. FAIL: the group is deleted, or the page shows an error with no sentence. Send back: a screenshot and the Audit page rows for the attempt.

Ends when steps 1 to 8 pass. Step 9 waits for the Groups release.

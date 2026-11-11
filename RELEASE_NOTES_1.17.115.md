# Tec-Tac Framework 1.17.115

Date: 11 November 2026. Modules can now read when a scheduled action next runs, check for an active superuser through a public call, and rely on a stated answer about secrets at uninstall. One held Low from the 1.17.113 review is closed.

Closes: the requests from certificatemanagement 0.4.3 (next run of a schedule) and 0.5.0 (secrets at uninstall, public superuser check) in `reviews/requests/core.md`, and the held Low of the Core 1.17.113 review ("Early framework check lets a non-OSError from the VERSION read escape inspect_archive").

**Flagged for human review: security items.** The superuser check now fails closed (item 3). The secrets answer (item 2) is a statement, not a code change. See `reviews/questions/core.md`, Core 1.17.115.

## What changed and why

1. **New public read `tec_tac.scheduler.next_run_for_action(module_id, action_id)`.**
   * Why: certificatemanagement wants a "next scheduled scan" line on its status panel. It cannot see schedules a person made on the Scheduler page.
   * Now: it answers `{next_run_at: ISO-8601 UTC string | None, enabled_schedules: int}`. That is the earliest next time over every live schedule of the action, whoever made it. It gives a time and a count only. It never gives a schedule id, name, owner, target, parameter or run history.
   * A schedule counts only when it is enabled, not paused, its owner and action modules are installed and enabled, and it has a next time. An unreadable module state counts as none (fail closed). A finished one-time schedule is skipped.
   * A module may ask only about its own actions. `module_id` must be non-empty, at most 100 characters and equal to the module of the registered action. Anything else, and an unknown action, raises `SchedulerError`. This is the same caller-asserted trust as `get_owned_schedule`.
   * The read is bounded: at most 500 rows, and `.only()` loads just the fields the timing needs. A row that fails to compute is logged and skipped.
   * Code: `scheduler.py`, `contracts.py` (new `scheduler` row). Docs: `docs/module-scheduling.md`, `docs/scheduler.md`.
2. **Secrets at uninstall: stated, not changed.**
   * Why: certificatemanagement asked whether Core deletes a module's secrets when the module is uninstalled.
   * The answer: no. The remove job touches files and lifecycle state only, and nothing in Core removes `core_secret` rows. While the module is not installed and enabled, nobody can read them. A module with the same id installed later reads the old values again. A module deletes its own values with `delete(name)`, and Core has no route that deletes another module's secrets.
   * Advice for module authors: if your module keeps a login or key, offer a "remove connection" action and tell the person to use it before uninstall.
   * Why no purge: it needs a new hook in the root remove job or a sweep keyed on "module not installed". A registry read glitch or an upgrade could then wipe a stored login. That is not small and safe. The optional administrator purge of an orphaned module's secrets is recorded in `reviews/questions/core.md` as information.
   * Code: `contracts.py` (text of the `core.secrets` rows and the module-secrets guidance only). Docs: new section "When a module is uninstalled" in `docs/secret-store.md`. `secret_store.py` behaviour is unchanged.
3. **`tec_tac.rbac.is_effective_superuser(user)` is public and fails closed.**
   * Why: certificatemanagement and coreusersecurity each keep a local check that is weaker or different from Core's. coreusersecurity's checks Django's flag only, so a role marked superuser is refused.
   * Now: True only for an authenticated user who is not explicitly inactive and whose `is_superuser` is exactly True, or whose Tactical role has `is_superuser` exactly True (Tactical's own rule). An object with no `is_active` is judged by the rest. A user object without `get_and_set_role_cache` falls back to `user.role`. Any other failure of the role read gives False. It never raises.
   * Existing Core callers (runtime settings, module licensing views, session security, accounts, reporting, the Tactical websocket) keep working. For a real, active user the answer is unchanged. They are stricter only for an inactive user or a broken role read.
   * Code: `rbac.py`, `contracts.py` (new `rbac` row). Docs: `docs/core-functions.md`.
4. **A corrupt version file no longer escapes `inspect_archive` (held Low of 1.17.113).**
   * Why: `module_manager_v2._runtime_versions()` read the VERSION file and the UI version file with `read_text(encoding="utf-8")`. Bytes that are not UTF-8 raised `UnicodeDecodeError` out of `inspect_archive` as a 500.
   * Now: an unreadable or undecodable version file reads as None for that component, in `_runtime_versions`. `_refuse_unmet_framework` also catches `(OSError, ValueError)`. The later `_check_runtime_requirements` then answers "version unavailable", which fails closed with a reason. Start-up discovery is unchanged.
   * Code: `module_manager.py`, `module_manager_v2.py`.

## Module-facing changes

* **New public read** `tec_tac.scheduler.next_run_for_action(module_id, action_id)`. Additive. Requires framework >=1.17.115. No module uses it yet.
* **New public read** `tec_tac.rbac.is_effective_superuser(user)`. Additive. Requires framework >=1.17.115. The function already existed inside Core. It is now in the contract catalog and fails closed. No module in `modules/` calls it yet.
* **Stated behaviour** of `core.secrets`: Core keeps a module's secrets at uninstall (see item 2). No code and no signature changed. Users of `core.secrets` today: ai, certificatemanagement, licensing.
* The contract export for 1.17.115 is still to be made on the dev server. Claude cannot make it from this PC.

## Not done

* halopsa's `next_runs_for_action(action_id, *, module_id)` with schedule ids, names and last run status. It needs owner-scoped rows and is a bigger design than the time-only read. The request stays open. `next_run_for_action` gives HaloPSA a next-run time for its panel.
* A purge of a module's secrets at uninstall (item 2).
* The other open items in `reviews/requests/core.md` are untouched, to keep this release reviewable.

## Notes for the release manager

* Backlog: the Low "requires.framework >= 1.17.80 not enforced for scheduler_person_actions" (1.17.80 review) was already fixed in Core 1.17.81 (`registry.py`, `_PERSON_ACTIONS_MIN_FRAMEWORK`). Remove it from `reviews/core/BACKLOG-new-findings.md`. The 1.17.113 Low named above is closed here.
* On signing, close in `reviews/requests/core.md` the three certificatemanagement entries named above, naming 1.17.115.

## Tests

* New: `tests/scheduler-next-run-for-action-1.17.115.py`, `tests/rbac-effective-superuser-public-1.17.115.py`, `tests/secret-store-uninstall-state-1.17.115.py`, `tests/module-install-framework-first-1.17.115.py`.
* Changed: `tests/reporting-server-wide-scope-1.17.30.py` asserted that a failing role cache falls back to the role. Item 3 makes that case fail closed on purpose, so the assertion now expects no rows.
* Not run here: anything that needs Django, the ORM, a running Core or the dev server. The scheduler and rbac tests cut the real functions out of the source and run them against stubs.

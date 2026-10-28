# Tec-Tac Framework 1.17.86

Date: 28 October 2026. A disabled module's schedules now wait instead of firing. Does not close Johan's report from dev02 (Checks kept running `checks.provider-run` every minute while Network Probe was disabled): that schedule belongs to Checks, so Core does not pause it when Network Probe is off. Checks 0.17.2 handles it with a clean skip, and the request stays open in `reviews/requests/core-modules.md` (corrected in 1.17.87). Closes the held Low from the 1.17.85 review, and held Lows from the dev log. One migration (0040), no new route.

## What changed and why

1. **Disabled module, paused schedules.** The Scheduler tick never asked whether the owning module was enabled. Now it reads the module state once per tick. A schedule whose `module_id` or `owner_module` is disabled is not queued. Core sets `paused_reason = "paused: module disabled"` (new field), keeps `enabled` as it is, and writes one `disable` audit row (not one per tick). When the module is enabled again Core clears the reason, writes one `enable` row, and the schedule runs on its next occurrence under its missed policy. A schedule a person switched off is never paused or resumed by Core. If the module state cannot be read, the tick skips those schedules and writes nothing (fail closed). Core pauses only for the module that owns the schedule. A schedule of module A does not pause when module B, which A depends on, is disabled; A has to handle that itself.
2. **Run now, strict scope (held Low, 1.17.85 review).** For a declared person action Run now calls `_require_target_scope(..., strict=True)`. A manager outside the targets' scope is refused before queueing, with the plain message and one `deny` row.
3. **`_resolve_view` (held Low).** A view with no `__module__` is now refused (`function_unavailable`). Before, a missing module skipped the app check.
4. **Contract text (held Low).** `docs/system-actions.md` now documents `status`, `reason`, `error` and `tactical_detail` on a `failed` command reply.
5. **Manifest cache (Medium, scheduler.py).** Not changed. The cache is keyed on a stat fingerprint of every manifest; a safe change needs a locking or invalidation redesign that cannot be tested here without Django. Left for a release that can run the pipeline tests.

## Module-facing change

- Schedule API (`serialize_schedule`) and `get_owned_schedule` gain `paused` (bool) and `paused_reason` (string or null). Additive. `next_run_at` is null while paused. No module reads an exact key set of these, so none needs a change.
- Documented in `docs/module-scheduling.md`.

## Migration

`0040_schedule_paused_reason`: one blank-by-default `CharField` on `TecTacSchedule`. Written by hand (Django is not installed here). On the dev server check `manage.py makemigrations --check --dry-run`.

## Tests

`tests/scheduler-module-pause-1.17.86.py` (new); `tests/system-command-failed-reason-1.17.84.py` and `tests/scheduler-manual-run-person-1.17.85.py` adjusted (a view without `__module__` is refused now; the 1.17.85 notes moved to `docs/releases/`). The shared harness gains `paused_reason`.

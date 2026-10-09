# Tec-Tac Framework 1.17.6

This release adds a Tactical permission helper, makes the audit contract refuse forged provenance, and closes three small held findings.

Closes: the held 1.17.0 Low ("browser_provenance is still forgeable through backend record()"), the held 1.17.5 Low (`_take_bridge_back` never unregisters formerly forwarded models) and the 0.12.86 review's doc finding (runtime-settings 403 text).

## Not in this release

A first draft of 1.17.6 also shipped a server-side Tactical executor (`core.tactical_operations`, `POST /api/tfd/tactical-operations/<module_id>/<operation_id>/`) and deprecated the browser-declared audit path. Both are out. AD-6 says "no Core wrapper in between", and the decision that would narrow it (AD-19) does not exist. Johan has not answered CQ17 in `reviews/questions/core.md`, which also asks whether a failed audit write may be non-fatal. That is an audit-integrity decision and it is his.

What this means for modules:

- No new capability, route or contract row for Tactical operations. Agents, Report Manager and Licensing keep AD-17's interim backend relay.
- `POST /api/tfd/audit/record/` is not deprecated. It behaves exactly as in 1.17.5 and sends no `Deprecation` header.
- Mode (b), the Scheduler and background runs, stays in `reviews/requests/core.md` (AD-13).

If Johan picks option (a) in CQ17, Core rebuilds the executor and adds AD-19 in a later release.

## Tactical permission helper (new)

`rbac.has_tactical_permission(user, flag)` and `rbac.tactical_permission_flags(user, flags)`. They mirror Tactical's `_has_perm`: an authenticated user, a Django superuser or role superuser passes, no role is denied, otherwise the role's boolean. The flag must be a boolean `can_*` field on `accounts.models.Role`, or `ValueError`. A lookup failure fails closed. An installer user is denied. The helper adds no Tec-Tac permission, so it is not an AD-5 duplicate, and it does not change `has_extension_permission`.

## Audit contract hardening

- `tec_tac.audit.record()` now refuses `browser_provenance` in `operation_context`, as it already refused `core_refusal`. This closes the held 1.17.0 Low. A grep of `modules/` found no module that supplies either key. Every `operation_context` user builds it with `build_operation_context`.
- The browser-declared path calls a new Core-internal writer, `record_browser_declared`, instead of the public `record()`. Its answers and rows are unchanged.

## Smaller fixes

- **Take-back unregisters (held 1.17.5 Low).** `_take_bridge_back` takes the formerly forwarded registrations under the lock before clearing them. After the lock is released and before Core's bridge is installed, it makes a best-effort `unregister_model` call to Report Manager for each one, in id order, with the module's `source_module` context. It never raises: each failure is logged, including Report Manager's own `RegistryError` in mode `core-bridge-active`. With no provider it logs one warning. Report Manager 0.3.0 refuses every `register_model` today, so nothing is ever forwarded and its behaviour does not change.
- **Runtime-settings contract text.** The 403 text of `PATCH /api/tfd/system/runtime-settings/` was copied from the update-source entry. It now states the real rule: `core.runtime_settings.manage` or `core.privileged_operations`, checked before the body. Documentation only. A new test also checks that no 403 text names a permission its authorization line leaves out.

## Module-facing changes

- **New `rbac.has_tactical_permission` and `rbac.tactical_permission_flags`**, Python contract rows in the area `rbac`. A module that uses them needs `requires.framework` of `>=1.17.6`.
- **Two Core-owned `operation_context` keys:** `browser_provenance` and `core_refusal`. A backend `record()` call that supplies either raises `AuditContractError`. No module under `modules/` does.
- **`tec_tac.reporting`:** `_take_bridge_back` now calls Report Manager's `unregister_model` for formerly forwarded models. The seven callers of `register_reporting_model` see no change.

## Fixed after review (precheck, round 0)

- **Blocking: the in-process Tactical executor shipped on an unanswered design question (CQ17).** Removed `tactical_operations.py`, `tactical_operation_views.py`, the route, the capability registration, the throttles, the OpenAPI group, the install check, `objects_in_role_scope`, the executor's audit writer and internal authority, `docs/tactical-operations.md`, and the contract rows and route entry. Also removed the `Deprecation` header, the one-warning log and the contract text that pointed modules at an operation that no longer exists. Restored the AD-8 sentence in `docs/module-audit.md`. The earlier requests that asked three modules to declare operations and seven to switch `audit_events` are withdrawn in `reviews/requests/core-modules.md`.
- Test: `tests/audit-server-provenance-1.17.6.py` became `tests/audit-provenance-hardening-1.17.6.py`. It checks that the executor files, route, capability, writer and deprecation are absent, and that the audit path answers as in 1.17.5.

## Tests

- New `tests/tactical-permission-helper-1.17.6.py`, `tests/audit-provenance-hardening-1.17.6.py`, `tests/reporting-takeback-unregister-1.17.6.py` and `tests/runtime-settings-contract-1.17.6.py`.
- Amended `tests/audit-declared-browser-events-1.16.0.py`, `tests/audit-declared-browser-events-1.17.0.py` and `tests/audit-browser-provenance-hardening.py` (calls that wrote `browser_provenance` through the public `record()` now use the Core-internal writer) and `tests/reporting-installer-fix-1.17.5.py` (it counts the call made at take-back and none after it).

## What did not run here

Django is not installed on this PC. Every new test loads the real Core files against stubs. Tests that need `manage.py shell` (`tests/reporting-registration-runtime.py` and the other runtime tests) did not run.

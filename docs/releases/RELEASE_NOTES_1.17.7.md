# Tec-Tac Framework 1.17.7

This release brings back the server-side Tactical executor, now that Johan has accepted it (AD-19, 9 October 2026). Core runs a Tactical call for the signed-in person and writes the audit row from Tactical's real answer. A browser can no longer misreport it.

Closes: the open Core request "Replace the browser audit path with server-side audit (CQ6)" and the Core half of "Tactical permission flags and role scope" (the role scope descriptor is not in this release). Answers CQ17 (option a) and CQ18 (option a).

## What changed

- **Tactical operations (new).** `tec_tac.tactical_operations` and `POST /api/tfd/tactical-operations/<module_id>/<operation_id>/`. The owning core module declares each operation once. Core checks the Tactical flags, the optional Tec-Tac module permission and the role's client and site limits. It then calls Tactical's own view in-process with the person's own authenticated request. No HTTP call, no token read, no key. Tactical's own permission, scope and validation still run. Core writes the audit row after the call.
- **The registry starts empty.** Nothing changes for an installed module until a core module declares an operation.
- **Audit.** `server_provenance` is a third Core-owned `operation_context` key. `record()` refuses it, as it refuses `browser_provenance` and `core_refusal`. Core's own writer takes a private authority, so a person who acts only under a Tactical permission is not blocked by the module-permission check. The public `record()` never gets that authority.
- **Browser-declared audit path deprecated (CQ18, option a).** `POST /api/tfd/audit/record/` for declared events (`audit_events`) answers exactly as in 1.17.6 and keeps its `browser_provenance` marker. Each response on that path now carries `Deprecation: true`, and Core logs one warning per module per process. Nothing is removed and no manifest key is rejected. Core removes the path in the first release after every declaring module has switched, with no fixed date. The permissioned path (`can_record_from_browser`) is untouched.
- **`tactical_permissions` in the runtime context.** `GET /api/tfd/ui/context/` now carries every boolean `can_*` field on Tactical's Role, as true or false for the signed-in user, from one role lookup. A superuser and a role superuser have every flag. An installer user, a user with no role and any lookup failure have none. It adds no Tec-Tac permission (AD-5).

## AD-19 conditions

Each has a test.

1. Only an operation the owning core module declared runs. Core refuses module `core`, an unknown, legacy or disabled module, and routes under `accounts/`, `api/tfd/`, `api/v3/`, `api/v4/`, `_allauth/`, `logout*`, `v2/` and `agents/installer` at registration. One operation per method and route. Tactical flags must be boolean `can_*` fields on Role.
2. The dispatch uses the signed-in user's own identity through `django.urls.resolve`, on a request copy with forced authentication and with the `Authorization` header and cookies dropped. An installer user and a user with no role are denied. A route Tactical renamed gives 502 `tactical_route_changed` with no fallback.
3. A failed audit write is logged at error level and is never fatal. The response carries `X-Tec-Tac-Audit: not-recorded` (`recorded` otherwise, present when a row was due). Python callers read `TacticalOperationResult.audit`.
4. Outcome rows. 2xx writes the declared action. 401 or 403 writes a Core deny row (`core_refusal`, reason `tactical_denied`). A 5xx, or an error after dispatch, on a call that is not GET writes `custom:outcome-unknown`. Other 4xx write nothing. Core's own refusals write a deny row with fixed Core text.
5. Tec-Tac's own functions are audited by the same row schema. A module's backend action keeps `tec_tac.audit.record`. The executor refuses module `core` and any `api/tfd/` route. `docs/tactical-operations.md` and a test show both paths write rows an auditor reads the same way.

Also kept: a body whitelist and a 256 KiB cap, secret-looking audit field names refused, file relay up to 25 MiB with `Content-Type` and `Content-Disposition`, streaming refused, and an optional `module_permission` that is ANDed with the Tactical flags (Licensing: `licensing.manage` plus `can_code_sign`, AD-16). Rate limit: 120 a minute and 5 000 a day for each user and IP.

## Module-facing changes

- **New capability** `core.tactical_operations` 1.0.0 (operations `run`, `list_operations`, `get_operation`), owner `core`.
- **New route** `POST /api/tfd/tactical-operations/<module_id>/<operation_id>/` (OpenAPI group "Tec-Tac · Tactical Operations", route name `tec-tac-tactical-operations`).
- **New contract rows.** Python area `tactical-operations`: `register_tactical_operation`, `run_tactical_operation`, `list_operations`, `get_operation`. Python area `rbac`: `tactical_permission_catalog`. The HTTP route row with its error codes. A response entry `tactical_permissions` on `GET /api/tfd/ui/context/` and `tactical_permissions.<flag>` in the `ui.authenticated.runtime-context` operations.
- **Third Core-owned `operation_context` key**, `server_provenance`. A backend `record()` call that supplies it raises `AuditContractError`. A grep of `modules/` found no module that does.
- **Deprecation** of the browser-declared audit path: `Deprecation: true` header and one log warning per module per process. Behaviour and rows are unchanged.
- A module that uses any of this needs `requires.framework` of `>=1.17.7`.

Declaring operations is the owning core modules' work (Agents, Report Manager, Licensing). The eight modules that declare `audit_events` switch in their own releases. Both are filed in `reviews/requests/core-modules.md`. The UI helper is filed in `reviews/requests/ui.md`.

## Tests

- New `tests/tactical-operations-1.17.7.py`, `tests/audit-server-provenance-1.17.7.py`, `tests/audit-declared-browser-events-deprecation-1.17.7.py` and `tests/tactical-permission-context-1.17.7.py`.
- New `tests/tactical-operations-runtime-1.17.7.py`, a script for `manage.py shell` on the dev server. It prints PASS or FAIL per step and exits non-zero on failure.
- Amended `tests/audit-provenance-hardening-1.17.6.py`: 1.17.6 asserted the executor absent and two Core-owned keys. It now asserts three keys and no absence.

## What did not run here

Django is not installed on this PC. Every new test loads the real Core files against stubs. Core's real `django.urls.resolve`, Tactical's real views and DRF's forced authentication did not run. `tests/tactical-operations-runtime-1.17.7.py` did not run. Please update the dev server to Core 1.17.7 from `dev`, run it with `manage.py shell`, and export a fresh public contract into `docs/contracts`.

## Fixed after precheck (round 0)

- The in-process request copy now carries `_client_ip`. Tactical's `LogIPMiddleware` sets it on the outer request only, and several Tactical views read it (agents send-command, core, scripts, software). Without it a call that had already run answered 502 and wrote `custom:outcome-unknown`. Core copies the value from the incoming request, and otherwise works it out from `META` the way Tactical does. Regression test added to `tests/tactical-operations-1.17.7.py` with a fake Tactical view that reads `request._client_ip`.
- Not changed for modules: no contract, endpoint or capability differs.
- Not run here: `tests/tactical-operations-runtime-1.17.7.py` needs the dev server. Django is not installed on this PC.

## Fixed after review (round 1)

- **Operation registration now enforces the owning core module (AD-19 condition 1).** Review finding: `register_tactical_operation` only refused `core`, unknown, disabled and legacy modules, so a premium module could declare `agents/{agent_id}/cmd/` and take a route from its owner.
  - A module must have manifest `category: core`. A premium or server module is refused.
  - The route's first segment (its Tactical group) must be one the module owns in Core's owner map, `GROUP_OWNERS` in `tec_tac/tactical_operations.py`. It follows the function map and AD-18. A group missing from the map is refused.
  - One named exception: Licensing (server module) may declare `core/codesign/...` (AD-16).
  - `tec_tac.audit._resolve_module` now also returns `category` (additive).
  - Tests added to `tests/tactical-operations-1.17.7.py`: a premium stub (`category=""`) registering `agents/{agent_id}/reboot/` is refused, as is a premium stub taking `core/codesign/`; a core module outside its group is refused; Licensing's `core/codesign/` is accepted. `tests/tactical-operations-runtime-1.17.7.py` now declares its probe under a core module that owns `core/`.
  - `docs/tactical-operations.md` states the rule.
- **Module-facing:** a module that declares an operation must be a core module that owns the route's group. No installed module declares one yet, so none breaks. Agents, Report Manager and Licensing, the planned declarers, all fit.
- **Not done:** a premium module that replaces a core module 100% is not accepted yet. Core has no signal that says it is the one installed. Filed as CQ21 in `reviews/questions/core.md`.
- **Not run here:** Django is not installed on this PC. The new cases ran against the same stubs as before.

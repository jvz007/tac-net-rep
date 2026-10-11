# Tec-Tac Framework 1.17.19

This release gives core modules three things they asked for. A module can keep a Tactical operation off the browser. A Scheduler handler can confirm that its run and its owner are real. It also fixes a contract export cell that broke module builds.

Everything for modules is additive. A module that changes nothing keeps working.

Capabilities: `core.tactical_operations` goes from 1.4.0 to 1.5.0. It is still major 1.

## Closes

In `reviews/requests/core.md`:

- Declare an operation server-only (agents 0.5.0, reportmanager 0.5.2, patching 0.7.0), and the "priority for Core's next slice" entry for it.
- A Scheduler run context a handler can verify, with the schedule owner (globalsettings 0.3.1, scriptmanager 0.4.1 and 0.4.2, alerts 0.8.0, CQ64 a).
- Browser contract docs cells must be a plain path (checks 0.13.0, and the "from the 1.17.18 contract export" entry).
- Name the missing Tactical flag in the 403 (software 0.1.0 fix round 1).
- The two checks 0.13.0 documentation entries: `caller_scope` with a call that names no agent, and a `body_selector` field that must also be in `body_fields`. No code change.

Still open: the AD-13 system-action contract. The run context is not that contract.

## Module-facing changes

Modules that use `server_only` or `verify_run_context` need `requires.framework >=1.17.19`. No module under `modules/` declares `server_only` or calls `verify_run_context` yet. Every module that declares operations still registers exactly as before: 105 declarations of 13 modules in `tests/tactical-operations-modules-compat-1.17.18.py`.

| What | Where | Needs a module change? |
|---|---|---|
| `register_tactical_operation(..., server_only=False)`. A strict true or false. A server-only operation is refused on Core's browser route with 403 `operation_server_only` and one Core deny row (reason `server_only`). It is refused before the body is parsed or a file is read, and Tactical is never called. A module backend that calls `run_tactical_operation` runs it as before. | `docs/tactical-operations.md` | No. Each module opts in when it wants to. |
| `server_only` stops the browser path only. It is not a verified caller identity. Module code must never pass the private `_via_http_route` keyword. A call that carries it only makes Core stricter. | `docs/tactical-operations.md` | No. |
| `list_operations` and `get_operation` carry a `server_only` key. | `docs/tactical-operations.md` | No. |
| The 403 `tactical_permission_denied` detail names the missing flag: "It needs the Tactical permission can_x." (or "permissions a, b"). The code and the deny row text are unchanged. | `docs/tactical-operations.md` | No. A module that shows its own text ignores it. |
| `tec_tac.scheduler.verify_run_context(context, require_owner=True)` returns a frozen `VerifiedSchedulerRun` (`run_id`, `schedule_id`, `module_id`, `action_id`, `owner_module`, `owner_key`, `one_off`, `user`, `owner_user_id`, `owner_username`, `has_tactical_permission(flag)`, `resource_context()`) or raises `SchedulerRunContextInvalid`. Also exported: `SchedulerRunContext`, `VerifiedSchedulerRun`, `is_core_issued_run_context`. | `docs/scheduler.md` | No. Handlers that ignore it are unchanged. |
| The handler context is now a `SchedulerRunContext`, a `dict` subclass with every key it had. It is JSON-serialisable. A copy, a pickled or Celery-carried context and a context a module builds do not verify, so pass the object itself. | `docs/scheduler.md` | No. 23 modules read it only as a dict. |
| The `ui.authenticated.tactical-scope` row of the contract export has a plain path in its docs cell. The section name moved to the first line of `details`. | `docs/contracts/` after the next export | No. This fixes `reference.ui-doc-missing` in the module validator. |

## What changed and why

**Server-only operations.** Some changes should never come from a browser, such as a bulk action a module runs after its own checks. Until now a declared operation was open to the browser route. `server_only` closes that route for one operation. It does not tell Core which module called, because modules run in the same Python process as Core.

**The run context.** Core keeps a private list of the exact context objects it issued, with the run id of each. `verify_run_context` reads the run row again, so the run must still be running. It takes the owner from the database, never from the dict, and checks that the owner is active and still holds the action and the target scope. A retry attempt issues a new context for the same run. The owner is checked again on every attempt. It fails closed on any lookup error.

This stops a module from naming a run or an owner Core did not issue. It cannot stop deliberately hostile signed module code, so the review of signed modules stays the defence. There is no per-run signed token (Johan, CQ64 a). It is not the AD-13 system-action contract.

**Docs fixes (no code change).** `caller_scope="unrestricted"` applies to every call of the operation, including a call whose body names no agent. The "no agent" rule of CQ57 belongs to a `row_lookup` scope entry. A `body_selector` field must also be in `body_fields`. A selector that says `present: false` still lists the field.

## Tests

New: `tests/tactical-operations-server-only-1.17.19.py` (also covers the missing flag, the 403 errors entry and the docs statements), `tests/scheduler-run-context-1.17.19.py`, `tests/contract-browser-doc-cells-1.17.19.py`. Updated for 1.5.0: the 1.17.7, 1.17.14, 1.17.16 and 1.17.18 tests named in the commit.

These tests stub Django. Django, Celery and a database are not installed on the development PC, so nothing ran against a real Django, a real database or a worker. `tests/scheduler-run-context-1.17.19.py` replaces Core's lookups with stubs. A runtime check on the dev server is still due after install.

## Not in this release

- A failed-attempt audit row for a 4xx that Tactical answers on a change (reportmanager 0.5.2 fix round 1, CQ63). AD-19 condition 4 says other 4xx write nothing, and no signed amendment exists, so the request stays open and the question is in `reviews/questions/core.md`.
- Hand registrations that survive uninstall with a deleted executable (held Medium from 1.17.18): a root-helper change for the server phase.
- Recording a test run's outcome on its audit row, and a view audit row for a GET that declares none.
- The AD-13 system-action contract, and enforcing module categories (AD-21 condition 6).
- The next public contract export: it is generated on the dev server after 1.17.19 is installed.

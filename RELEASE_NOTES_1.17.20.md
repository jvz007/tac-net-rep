# Tec-Tac Framework 1.17.20

This release does three things. Core now writes an audit row when Tactical refuses a change. A Scheduler handler can only verify a run that belongs to it. A module can record a refusal or an outcome for a person who holds none of its own permissions, when the module owns the Tactical operation.

Capabilities: `core.tactical_operations` goes from 1.5.0 to 1.6.0. It is still major 1.

## Closes

In `reviews/requests/core.md`:

- The failed-attempt audit row for a Tactical 4xx (reportmanager 0.5.2 fix round 1, remote-background, globalsettings, patching). Johan answered CQ63 (b) on 11 October 2026, and AD-19 condition 4 carries the amendment. Core 1.17.19 first built this row and the precheck held it back. This release restores it.
- "Core 1.17.20: module deny and outcome rows for a person who holds none of the module's own permissions" (globalsettings 0.3.0 fix rounds 2 and 3, scriptmanager 0.4.2).

Also closes the held Medium from the 1.17.19 review: a Scheduler run context issued for one module's action verified inside another module's handler (a confused deputy).

## Module-facing changes

Each change below needs `requires.framework >=1.17.20` in a module that relies on it. Everything except the `verify_run_context` signature is additive. No module under `modules/` calls `verify_run_context`, uses the action `custom:operation-failed`, or declares anything that the new rules refuse.

| What | Where | Needs a module change? |
|---|---|---|
| **A failed row.** When Tactical answers a call that is not `GET` with a 4xx other than 401 and 403 (400, 404, 409, 422, 429 ...), Core writes exactly one row. The action is `custom:operation-failed`. Metadata carries `declared_action` (the operation's own audit action), `result: failed`, `failure: tactical_refused`, `tactical_status`, `operation`, `method` and `route`. The row has the declared object type, the object id and the correlation id, a fixed Core text ("Tactical refused this change (HTTP 404); nothing was changed."), no before or after value, and none of Tactical's own text. A filter on the declared action never matches it. | `docs/tactical-operations.md` | A module that writes its own failed row for a Tactical 4xx should stop, so one refused attempt gives one row. reportmanager (`_audit_failed`), remote-background, globalsettings and patching are queued in `reviews/requests/core-modules.md`. |
| A 4xx on a `GET` still writes nothing. 401 and 403 still write a `deny` row. A 5xx, or an error after dispatch, on a call that is not `GET` still writes `custom:outcome-unknown`. | `docs/tactical-operations.md` | No. |
| `TacticalOperationResult.audit` and the `X-Tec-Tac-Audit` header are now a verdict for these 4xx answers. Before they were `{}` and absent. | `docs/tactical-operations.md` | A module that read `result.audit == {}` as "no 4xx row" must read `recorded` instead. |
| `register_tactical_operation` refuses `custom:operation-failed` as a declared audit action. `tec_tac.audit.record` and the browser writer refuse it with `AuditContractError`, so a module cannot forge Core's failed row. `custom:outcome-unknown` stays open to `record()` (scriptexecution writes it itself). | `docs/tactical-operations.md`, `docs/module-audit.md` | No. |
| Capability `core.tactical_operations` is 1.6.0. The metadata lists `declaration_keys_added_in_1_6_0` (none), `behaviour_added_in_1_6_0` and `audit_actions_core_only`, so a module can feature-detect the failed row. | `docs/tactical-operations.md` | No. |
| **`verify_run_context(context, *, expected_module_id, expected_action_id, require_owner=True)`.** The two ids are required keywords. Core compares them, exactly, with the module and action of the run it loaded. A mismatch gives `SchedulerRunContextInvalid` ("This run belongs to another module or action."), with no ids in the message. An id that is missing, empty or not a string is refused too. The 1.17.19 call form, without the ids, raises `TypeError`. | `docs/scheduler.md` | Only a handler that already calls it. None exists under `modules/`. |
| **Audit rows without a module grant.** A signed-in person with none of the module's permissions is accepted as the actor of a backend `record()` row when the module is the declaring owner of the action. That means the module registered at least one Tactical operation. `deny` is accepted for such a module. Any other action is accepted only when it is the audit action of one of the module's operations that has no `module_permission`, and the person holds every Tactical flag of that operation. Core marks the row `debug_info.actor_authority = "declared-operation-owner"`. A module cannot supply it. | `docs/module-audit.md` | A module opts in by writing the row. It no longer needs its own warning path for "row could not be added". |
| The new rule refuses nothing that was accepted before. An installer user, an unauthenticated actor, module `core`, a legacy or disabled module, a module with no operation, an action no operation declares, and an operation that needs a module permission stay refused. | `docs/module-audit.md` | No. |

## What changed and why

**The failed row.** An auditor wants to see who tried what, even when Tactical said no. Until now a refused change left no row. The row has its own action, so it never looks like a change that happened. It carries no before or after value and none of Tactical's wording, because nothing changed and Tactical's text can name hosts and settings. If the audit write fails, Core logs it and reports `recorded: false`. It never raises.

**The run context.** A run context that Core issued is real. Without the ids, module A could pass it to module B's handler. B would then act for A's schedule owner. The handler now names its own module and action. The run row decides, not the dict, so a dict that claims other ids moves nothing. This needed a required signature because an optional one leaves the hole open for any handler that forgets it. Johan chose required keywords in chat.

**Rows without a grant.** Some modules are gated by Tactical's own role flags, not by a Tec-Tac permission. Their refusals and outcomes were lost for people who held only the Tactical flag. Core now trusts the registry of declared operations and the Tactical flag check it makes anyway (AD-5, AD-12). It does not trust a module's word. Johan chose this reading in chat: only registered Tactical operations, `deny` for any module that owns one, outcome rows only for that operation's own audit action and only for a person holding its flags.

What this does not cover. The browser audit path (`POST /api/tfd/audit/record/`) is unchanged, because Core cannot prove that the module's code sent a browser event. So scriptmanager's unsaved-draft download row, which is a browser row of a permissioned module, is not covered. Script Manager's CSV-export deny row, its test-outcome row and globalsettings' parent and deny rows are.

## Tests

New: `tests/tactical-operations-failed-rows-1.17.20.py` (the 1.17.19 file restored from commit 0169d6a, retitled and extended: 400, 404, 409, 422 and 429 on POST, PUT, PATCH and DELETE, a GET 4xx, 401 and 403, 5xx and a transport error, a failed audit write, the Core-only action at registration and in `record()`, capability 1.6.0, docs and contract text), `tests/scheduler-run-context-bind-1.17.20.py`, `tests/audit-declared-owner-rows-1.17.20.py`.

Updated: `tests/tactical-operations-1.17.7.py`, `tests/tactical-operations-audit-params-1.17.18.py`, `tests/tactical-operations-before-scope-1.17.14.py`, `tests/tactical-operations-server-only-1.17.19.py`, `tests/audit-correlation-1.17.16.py` and `tests/contract-export-1.17.16.py` (capability 1.6.0, and "other 4xx writes nothing" now reads "writes one failed row"), and `tests/scheduler-run-context-1.17.19.py` (its calls pass the ids).

These tests stub Django. Django, Celery and a database are not installed on the development PC, so nothing ran against a real Django, a real database or a worker. A runtime check on the dev server is still due for 1.17.19 and 1.17.20.

## Not in this release

- Browser-declared audit events for a permissioned module (scriptmanager's unsaved-draft download row). Widening that path is a design question for Johan.
- The held Medium from the 1.17.16 review (a one-off schedule re-run by another user under the original user's identity, in the scheduler views).
- The held Mediums from the 1.17.17 and 1.17.18 reviews (hand registrations and protected actions in the server-maintenance helper): a root-helper change for the server phase.
- The AD-13 system-action contract, general secret storage, an object id for a create row, secret body fields recorded as changed, a runtime setting for a private mail relay, a completion path for finished server jobs, and enforcing module categories (AD-21 condition 6).
- The next public contract export: it is generated on the dev server after 1.17.20 is installed.

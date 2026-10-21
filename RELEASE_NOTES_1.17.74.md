# Tec-Tac Framework 1.17.74

Date: 21 October 2026. No migration. No new route. No new setting. `core.system_actions` goes from 1.3.0 to 1.4.0 (additive).

A module that starts an unattended install for Maintenance can now ask Core which endpoints a delegation ticket covers, before it starts anything. The module sees only what the ticket covers.

- **A provider can ask which endpoints a ticket covers.** The new `resolve_delegated_targets` returns only what the ticket covers (Q-APM21 b, answered by Johan on 21 October 2026).
- **We answered the open question about resuming after a reboot.** Core publishes no "agent is back" event. Polling is the supported path.

What changes for a person today: nothing you can see. Nothing uses the new operation until Advanced Patch Management and Maintenance switch to it.

## What changed and why

### 1. `resolve_delegated_targets` (Q-APM21 option b)

`resolve_delegated_targets(ticket, *, action_id, endpoint_ids)` is called by the provider the grant names, before it starts anything.

- `endpoint_ids` is a list of 1 to 40 000 whole numbers or agent id texts.
- It applies exactly the checks `start_delegated_run` applies before it makes a run. They share one helper, `_checked_ticket`. Then it reads the grant's targets (through the owner module's resolver) and the person's stored scope.
- It returns `{"agents": [{"agent_id", "pk"}], "covered", "not_covered"}`. It never names an id it refuses. It creates no run and no schedule, and it does not use up the ticket.
- Any ticket problem is one generic refusal, `ticket_invalid`, with one `deny` audit row. The audit row keeps the real cause (`cause`). The caller sees none, so a module cannot probe the grant.
- The caller is read from the call stack, as for the other delegation functions.
- A grant still names a task row only (an install, AD-43). Nothing about which rows may be delegated changed.

### 2. Durable runs with a reboot (documentation only)

`docs/system-actions.md` has a new section, "Durable runs with a reboot". It lists what exists (the Scheduler's `start_one_off_run`, delegation tickets, `register_target_resolver` and `resolve_delegated_targets`). It says plainly what is missing: Core publishes no "agent is back" event, and polling Agents' `get_reboot_status` (`agents.resources` 1.13.0) is the supported path. An "accepted" answer is not a restart. No code and no new promise.

## Module-facing change

- `core.system_actions` 1.3.0 to 1.4.0, additive. `requires_framework` for the new part is `>=1.17.74`.
- New operation `resolve_delegated_targets`, appended after the first ten. New public function `tec_tac.system_actions.resolve_delegated_targets(ticket, *, action_id, endpoint_ids)`.
- Every earlier row, digest, result shape, refusal code and delegation behaviour is unchanged. A search of `modules/` finds no use of the new name. Advanced Patch Management and Maintenance are the modules to build next.

## Held: the reboot row and the delegated reboot

An earlier draft of this release built an `agents.reboot` command row (Core sending Tactical's `agent.nats_cmd` itself) and let a delegation grant name it. The precheck blocked both, and we agree: rule 1.7 and checklist A2 name Tactical's own task functions as the only path for AD-13 work, AD-43 names the install only, and a reboot of up to 40 000 endpoints is a safety decision that is Johan's. Both are removed. CQ213, CQ214 and CQ215 in `reviews/questions/core.md` wait for his answer. When he signs them and the release-manager records the clauses, Core builds the row in a later release.

## Fixed after precheck

- The command kind (`KIND_COMMAND`), `system_commands.py`, the `agents.reboot` row, the command branch of `run_system_action`, the command text of the confirmation and the `for_storage` hook of `tasks.py` are removed.
- The kind check in `delegation._provider_action` is back to `entry.kind != _sa.KIND_TASK`. The command lines in `delegation._text` are removed.
- The contract text, the capability metadata (no `kinds`, `command` or `delegable_kinds`) and `docs/system-actions.md` no longer describe a reboot row. The `wrong_kind` text is the one of 1.17.70.
- The requests to Agents (register the row) and Maintenance (use the reboot grant) are withdrawn. The release-manager request in `reviews/requests/core.md` now records what Johan must sign first.

## Tests

New, named after this version (stub harness `tests/delegated-targets-harness-1.17.74.py`, built on `scheduler-completion-harness-1.17.61.py`; no network, no Django):

- `tests/delegated-targets-resolve-1.17.74.py`: exact coverage, a generic refusal for every ticket problem with one deny row and the cause kept in the row only, the caller from the stack, shape refusals, no run or schedule created, the ticket not used up, `start_delegated_run` unchanged.
- `tests/delegated-targets-task-only-1.17.74.py`: the table has the four rows and no command row, `agents.reboot` cannot be registered, the framework has no `nats_cmd` call or command kind, the kind check names the task kind only, a write row is not delegable, an install still is.
- `tests/delegated-targets-compat-1.17.74.py`: signatures, the same table fields, the same digests and result shapes for scan and install, `modules/` does not use the new name.
- `tests/delegated-targets-contract-1.17.74.py`: metadata, version, `contracts.py` text, the docs, and the contract-export gate.

Existing tests changed in place: version pins use `>=` so a `-N` rebuild passes, and the operations lists check the first ten and allow one appended. The table pins keep the four rows. The release notes of 1.17.73 moved to `docs/releases/`, as earlier releases did.

## Checks run on this PC

Django is not installed here, and this is Windows (no `fcntl`). The tests that import `accounts`, need the dev server or `fcntl` did not run, and they fail the same way before this change (see the 1.17.73 tree). The runtime test for the reboot row is removed with the row.

## Not in this release

- The reboot row and the delegated reboot (CQ213, CQ214, CQ215): held for Johan.
- `commands.run` (CQ194), software package uninstall, checks, tasks and reports rows (CQ193): no owning module has asked, and Tactical already schedules checks, tasks and reports natively.
- The Scheduler progress call, the schedule list filter and paging, the per-call conditional scope, the extension-permission snapshot on unattended runs, the scope check for a group's members and the `core.module_dependants` text fix: next releases.
- Exporting the public contract and signing: a running server generates the export and the pipeline signs.

## Requests closed and opened

- Closed (removed from `reviews/requests/core.md`): "an operation that tells a module which endpoint ids a delegation ticket covers" (patchmanagement 0.13.0 and 0.14.0, Q-APM21 b) and the polling answer for "Maintenance multi-step runs with reboot and resume".
- Still open: "unattended reboot of an endpoint" (agents 0.15.0), held for CQ213 and CQ215. The release-manager records the clauses first.
- Opened for other areas: Maintenance and Advanced Patch Management use `resolve_delegated_targets` (`reviews/requests/premium-modules.md`).

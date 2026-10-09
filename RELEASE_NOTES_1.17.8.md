# Tec-Tac Framework 1.17.8

Core now decides who may declare a Tactical operation route by route, not group by group. It also makes the Tactical operation audit writer private, so only Core's executor can write a server-provenance row.

Closes: the two held findings from the 1.17.7 review (one Medium, one Low). No entry in `reviews/requests/core.md` closes with this release.

## What changed

- **Route-level ownership (held Medium).** The group map `GROUP_OWNERS` is gone. Core holds an ordered table of route prefixes, each with the module ids that may declare there. Core finds the longest prefix a route starts with and applies only that rule, so a reserved sub-route cannot be claimed through its group. An empty owner set means the prefix is Core's own, or no core module owns it yet, and every module is refused. The table follows the function map, AD-11, AD-16 and AD-18.
- **Refused at registration.** A non-owner is refused when it registers, so a module outside its home can no longer register a route first and block the real owner on the one-caller rule. The error names the route and the rule's owners. Dispatch still re-checks the stored operation, as before.
- **Audit writer private (held Low).** `audit.record_tactical_operation` is now `audit._record_tactical_operation`. Core's executor passes its own authority and nothing else calls it. There is no public alias. `record_browser_declared`, `record_core_refusal` and `_record_tactical_operation` are Core-internal: a module that needs a Tactical call audited declares a Tactical operation.
- `docs/tactical-operations.md` has a new "Who may declare where" table. `docs/module-audit.md` and the contract catalog say the audit writers are Core-internal.

## Module-facing changes

Only registration-time refusals change, and no module in `modules/` declares a Tactical operation yet. A grep of `modules/` for `register_tactical_operation`, `tactical_operations`, `tactical-operations` and `record_tactical_operation` finds mentions in text only (Licensing's `codesign.py`, the Alerts `tactical_actions.py` docstring and Licensing's release-notes test). So no compatibility path is needed. Licensing's declaration of `core/codesign/` stays valid.

Who may declare where (a `{}` is a parameter segment):

| Route prefix | Owner |
| --- | --- |
| `clients/`, `clients/sites/`, `clients/{}/` | nobody (Core's, AD-11) |
| `clients/deployments/`, `clients/{}/deploy/` | agent-management |
| `core/codesign/` | licensing only (AD-16). Global Settings, Report Manager and Script Manager lose it |
| `core/settings`, `customfields`, `keystore`, `urlaction`, `emailtest`, `smstest`, `clearcache`, `servermaintenance`, `version`, `webtermperms` | globalsettings |
| `core/schedules/` | reportmanager |
| `core/serverscript/` | scriptmanager |
| `core/openai/`, `core/dashinfo/`, any other `core/` route | nobody |
| `agents/` (the rest) | agents |
| `agents/{}/cmd/` | remote-background (AD-18) |
| `agents/{}/{}/webvnc/` | take-control (AD-18) |
| `agents/{}/runscript/` | scriptexecution |
| `agents/{}/meshcentral/` (with `recover/`) | take-control |
| `agents/{}/processes/`, `registry/`, `eventlog/`, `terminal-defaults/` | remote-background |
| `agents/update/`, `versions/`, `bulkrecovery/`, `agents/{}/recover/` | agent-management |
| `logs/pendingactions/` | agents (AD-18) |
| `logs/audit/`, `logs/debug/` | audit, debug |
| any other `logs/` route | nobody |
| `automation/patchpolicy/`, then the rest of `automation/` | patching, automation |
| `reporting/` | reportmanager |
| `alerts/`, `scripts/`, `checks/`, `software/`, `tasks/` | alerts, scriptmanager, checks, software, tasks |
| `services/`, `winupdate/` | remote-background, patching |

- **Endpoints owns no route.** It composes what other modules publish, so it loses its declare rights in `agents/` and `logs/`.
- **Clients.** `clients/` is Core's (AD-11). Agent Management keeps the deployment routes.
- **Premium replacement modules** are still refused (CQ21 is open). Core has no signal that one is the installed replacement.
- **Removed:** `tec_tac.audit.record_tactical_operation`. No module used it. It was never a contract row.
- `tec_tac.tactical_operations.GROUP_OWNERS` is gone. It was not a contract either. The table `ROUTE_OWNERS` is Core-internal and not a module contract.

## Tests

- New `tests/tactical-operation-route-owners-1.17.8.py` and `tests/audit-private-operation-writer-1.17.8.py`.
- Updated `tests/tactical-operations-1.17.7.py` (refusal text), `tests/audit-server-provenance-1.17.7.py` (private name) and `tests/tactical-operations-runtime-1.17.7.py` (reads the new table; its second probe route is now `core/version/does-not-exist/`).
- The runtime script needs Django and Tactical, so it was not run here. Run it on the dev server.

## Precheck fix (held Medium from 1.17.7, still open)

- A parameter segment is now a wildcard in the route owner check. Before, `agents/{x}/` or `agents/{agent_id}/{op}/` matched only the `agents` group rule, so Agents could register a route that reaches `agents/<id>/cmd/`, `.../webvnc/`, `.../runscript/`, `agents/update/`, `agents/versions/` or `agents/bulkrecovery/`. Core now expands each parameter to every route word a rule names at that position (and to an ordinary value), finds the longest rule for each expansion, and refuses the route unless the module owns all of them. An expansion that runs on past a rule after an id value (`agents/update/reboot/`) is treated as an id, so `agents/{agent_id}/reboot/` still belongs to Agents.
- Test: `tests/tactical-operation-route-owners-1.17.8.py` gains the wildcard cases. `tests/tactical-operations-1.17.7.py` now declares `agents/{name}/notes/` instead of the bare `agents/{name}/`, which the new check refuses by design.
- Module-facing: none today (no module declares operations). A module declaring a bare `<group>/{param}/` route may now be refused if a reserved route of another owner sits there.

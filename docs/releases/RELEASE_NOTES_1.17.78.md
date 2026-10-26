# Tec-Tac Framework 1.17.78

Date: 26 October 2026. Two safety checks on the background send-command path (`agent.command`). No migration, no new route, no new setting, no contract change. `core.system_actions` stays at 1.5.0.

An earlier session left this change uncommitted. 1.17.77 left it out on purpose. I reviewed it and ship it. It only adds refusals, so it cannot widen trust.

## What changed

1. **Route-owner check before the send.** `_send` now runs the same two guards every Tactical operation passes: the path is not a route Core owns, and `OWNER_MODULE` (`remote-background`, a constant) is listed for the rule `agents/{}/cmd` in Core's static owner table. This does not read whether that module is installed or enabled (see 1.17.79). A failed guard raises `function_unavailable`. Nothing is resolved or sent.
2. **Claim released when the audit lookup fails.** If the durable audit lookup fails after the claim is made, Core now releases the claim and refuses the call. Before, the claim stayed for 24 hours and a retry read as a duplicate, though nothing was sent. Still fail closed: no send on a failed lookup.
3. **One request builder.** The request for Tactical's view is now built by `tactical_operations._build_request`, the builder every Tactical operation uses (no credentials copied, forced authentication as the service user, loopback address). Same body, same path. This also removes the unused `BytesIO` import.

## Module-facing change

None. I grepped `modules/` for `system_commands` and `_build_view_request`: only Communicator's own tests mention `system_commands`, and none call a changed function. The contract, routes and refusal reasons are the same.

## Assumption (recorded in reviews/questions/core.md)

`OWNER_MODULE = "remote-background"` is a fixed id. Core's owner table gives `agents/{}/cmd` to that module. A replacement of that module still passes. Nothing is read from the caller.

## Tests

`tests/system-command-1.17.78.py` (new, no Django): owner table gives the route to `OWNER_MODULE`; a non-owner and a Core-owned path are refused and `_send` dispatches nothing; a failed lookup releases the claim, a retry succeeds, a second claim is still a duplicate, an earlier audit row still refuses.
`tests/system-command-1.17.76.py` now loads `system_commands.py` with `tactical_operations.py` as one package, because the code imports it.

Not run here: Django, Tactical's real view dispatch, `tests/system-command-*` that need Django. `system-writes-compat-1.17.70.py` and `system-writes-table-1.17.70.py` were failing before this change (they expect no `agent.command` row and no patchmanagement use). This release's diff does edit both, so they are not unrelated; the 1.17.79 notes record what was done. `system-writes-runtime-1.17.70.py` needs Django.

## Test checklist (dev02)

1. Run a Communicator background schedule for one endpoint (Run now). **Expected:** the command runs and the audit shows one row. **FAIL:** `function_unavailable` on a healthy server. Send back: the run history entry and the Core log line "route is not owned".
2. Run the same command again with the same command id. **Expected:** refused as a duplicate, nothing sent. **FAIL:** sent twice. Send back: the endpoint's Tactical command history.
3. (Withdrawn in 1.17.79: the check reads Core's static table, so disabling Remote Background does not refuse the run.)

# Tec-Tac Framework 1.17.76

Date: 23 October 2026. One migration (0038, the Communicator service user, AD-50). No new route. No new setting. `core.system_actions` stays at 1.5.0.

Communicator's background command (`agent.command`) now stands on Tactical's own "send command" route, and it stays switched off until one decision is signed. Nothing you can see changes today.

- **The copy is gone.** 1.17.75 copied the steps of Tactical's send command (a history row, then the agent call) inside Core. That code is deleted. The send is Tactical's own view, `POST agents/{agent_id}/cmd/`, whose answer is the output text.
- **It runs as the Communicator module (Johan, 23 October 2026, signed in chat).** The person's Communicator rights (`communicator.send`, `communicator.reboot` for a restart) are checked when the schedule is made. The command then runs as a dedicated Tactical service user, `tectac-communicator`, so the person need not hold Tactical's `can_send_cmd`. Johan's words: APM via Communicator can use the cmd endpoint to send the commands for Communicator even when the user does not have the send command permission; it can only send the Communicator commands and nothing else. Core runs Tactical's own `send_raw_cmd` view in process (`_dispatch`) with that user and the body `{shell, cmd, timeout, custom_shell: null, run_as_user: false}`. HTTP 2xx gives the output text; HTTP 400 `Unable to contact the agent` reads `unreachable`; any other status is `failed` and the claim stays.
- **The service user is least privilege and checked on every call.** Role `Tec-Tac Communicator (send commands only)` holds `can_send_cmd` and no other boolean flag. The user is not superuser, staff or installer, has an unusable password and `block_dashboard_login`. Any deviation refuses `function_unavailable`. Only the `agent.command` row can use it (`run_one` refuses any other row), and only after every check of `run_system_command`.
- **Open Tactical scope for that user.** Its role has no client or site limits, so Tactical's own scope check passes for every endpoint. The endpoint was validated against the OWNER's creation-time scope by Core; the string agent id is resolved from that one validated number.
- **Tactical's own audit holds the command text.** Tactical records the rendered template text as the command in its history and audit log, as it does for any command. Core's own rows never hold command text or output.
- **Per-run cap.** One run sends at most 2000 commands (`too_many_commands` above, nothing claimed or sent). The number of each send is in the audit row as `run_send_number`. One Scheduler run still sends only what fits in the drain budget of Communicator (240 s, 10 s per command); the rest stays queued there.
- **Tactical's string agent id.** The route takes the string agent id, not the number. Core resolves it from the number and refuses the call (`bad_agents`) when it cannot.
- **Same replies.** The bare `timeout` or `natsdown` answer reads `unreachable` (as Remote Background maps it). The output is cut at 1 MiB.
- **Once, even after a cache flush.** After the 24-hour cache claim, Core checks for an earlier strict audit row of the same endpoint and `command_id`. A flushed cache cannot let the same id run again. A failed lookup refuses the call. (Closes the held Medium of 1.17.75.)
- **`declaring_module`** widens the unattended exemption only for the registered `agent.command` row, no longer for any id that starts with the owner's name. (Closes the held Low of 1.17.75.)
- **No Tactical minimum flag (Johan, 23 October 2026).** The person's Communicator rights are checked when the schedule is made; the command runs as the Communicator module. The row no longer requires `can_send_cmd`, and the forced run-time re-check is gone. Flags the registering module lists are still held to what was stored.
- **Known issue (Johan, fix next week).** A person with Communicator rights but without Tactical's Send commands permission can cause fixed-template commands (AD-49 templates only, never free text) to run on endpoints in their scope through a scheduled APM profile. Proposed fix: re-add `can_send_cmd` as an owner requirement, or a dedicated Communicator permission for unattended sends.

## Module-facing changes

- `run_system_command` and the call shape `{agent_id, command_id, template_id, params}` are unchanged. `agent_id` stays the endpoint number. New refusal `too_many_commands` (above 2000 per run). The call now works (it was refused `function_unavailable` in the first build of this version).
- Remote Background: its `send_command_background` is redundant. Request in `reviews/requests/core-modules.md`.
- Communicator must check `communicator.send` / `communicator.reboot` itself at schedule creation and at each run, and handle `too_many_commands` per endpoint. The person-driven operation `send-command` (Remote Background) is unchanged and keeps Tactical's own `can_send_cmd` and scope.

## Tests

`tests/system-command-1.17.76.py` (new); `system-command-1.17.75.py` and `system-command-integration-1.17.75.py` updated for the seams. Django is not installed here: the cache, the audit, Tactical's models and the Scheduler are small fakes; the dispatch of Tactical's view could not be run.

## Fixed after review (second stop, 1.17.76-1 promotion)

The AI review passed 1.17.76-1, but signing stopped at promotion: the rebuild version appeared outside `VERSION`, the package manifests and the release notes. It sat in code comments, contract text and tests. This rebuild (1.17.76) removes it: those places now say "1.17.76" or no version, and the rebuild number is only in `VERSION`, `tec_tac_package.json` and this file's name. The held review findings are fixed too.

- **[Medium] `declaring_module` no longer depends on registration order.** It matches the exact id `<owner>.command` (`remote-background.command`) for a caller on the row's list, reads no registry, and its docstring says so. A look-alike id or a non-caller is never widened.
- **[Medium] The duplicate lookup is one query per run, not one per send.** `_already_recorded` reads the last 7 days of Core's strict command `run` rows once for the run (kept for the last 8 runs, this run's own sends added), so a 2000-command run no longer does up to 2000 audit scans. It is bounded (100 000 rows); more rows than that refuses the call (`function_unavailable`, fail closed), and any failed lookup still refuses. Limit: a `command_id` older than 7 days is outside the lookup (the 24-hour cache claim covers the normal case; the audit row covers a cache flush within 7 days). Stated in `docs/system-actions.md`.
- **[Low] The contract text** no longer says "fail closed until the view dispatch is signed". It now says Core runs Tactical's `send_raw_cmd` view in process as its service user after every check of `run_system_command`.
- **[Low] Migration 0038** logs the exception type when it cannot make the service user (still never aborting the migration). A regression test runs it on a fake `apps` registry: creation, existing rows untouched, a Tactical without the flag, and a failure.

Module-facing: none. Tests: `tests/system-command-1.17.76.py` extended; `system-command-1.17.75.py` and the integration test unchanged apart from comments. Not run here: Django, the real dispatch, the migration on a real database, the real audit query (dev02).

## Fixed after review (first stop, 1.17.76-1: the blocked review)

The blocked review (High) said Johan's service-user decision was not in the accepted decisions. It is now: **AD-50** (23 October 2026, Johan, chat) in `docs/review-accepted-decisions.md`, with its conditions. This rebuild meets them.

- **Service user made at install or upgrade, never on the first send.** New migration `0038_communicator_service_user` makes role `Tec-Tac Communicator (send commands only)` (`can_send_cmd`, every other boolean flag off) and user `tectac-communicator` (unusable password, no dashboard sign-in, not superuser, staff or installer). It never changes an existing row and never fails the migration (a fault is logged). Choice: a Core migration, because Core already makes its fixed rows that way and a migration runs on install and on every upgrade. `_service_user()` only reads and re-validates (active, not superuser, staff or installer, unusable password, no dashboard login, the one role, exactly `can_send_cmd`). Missing or deviant: `function_unavailable` with a plain reason. It is now checked before the claim and the audit row, so a refusal sends and claims nothing.
- **A Communicator-specific flag for `agent.command` (AD-50).** Core cannot read a module permission (`held_at_creation` reads Tactical role flags only), so the confirmed parameters carry `rights`: `communicator.send` always, `communicator.reboot` too when an allowed template was registered with the new `right='communicator.reboot'`. Core refuses a schedule without them, and a run refuses `permission_lost` when a template's right is not in them. The run also re-checks that the owner still exists and is active. Tactical's `can_send_cmd` stays NOT required (AD-50; known issue, fix next week).
- **Backlog.** The durable duplicate lookup reads only the last 7 days of Core's strict `run` rows (a time window, still fail closed). The `contracts.py` text now says what the code does (the Communicator rights and owner-active check, not `can_send_cmd`).

### Module-facing change: Communicator must pass `rights`

`run_system_command` is unchanged. The command parameters gain a required key `rights` and `register_command_template` gains `right=` (default `communicator.send`). Communicator (in `modules/communicator`) must send `rights` in `system_action_parameters` and register its restart template with `right='communicator.reboot'`; until it does, creating the schedule is refused (fail closed). Request in `reviews/requests/core-modules.md`.

### Not tested here

Django is not installed. The regression tests fake Tactical's accounts models, the view dispatch, the cache and the audit log. The real dispatch (Tactical's `send_raw_cmd` in process as the service user), the migration on a real database and the audit lookup are untested here: dev02 must test them.

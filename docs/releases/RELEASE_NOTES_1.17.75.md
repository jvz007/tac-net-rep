# Tec-Tac Framework 1.17.75 (rebuild of 1.17.75 after review)

Date: 23 October 2026. No migration. No new route. No new setting. `core.system_actions` goes from 1.4.0 to 1.5.0 (additive).

Communicator can now send a command to an endpoint from a background run, once Remote Background registers the new `agent.command` action. Core sets the limits and keeps the record.

- **A third kind of system action: one command on one endpoint.** Core runs the steps of Tactical's own "send command" and returns the output text (up to 1 MiB).
- **Strict by design.** Only a verified Communicator run may call it. The person confirms the shells and the longest timeout when they make the schedule. A repeated `command_id` never runs twice.
- **The record never holds the command or its output.**

What changes for a person today: nothing you can see. Nothing uses the action until Remote Background registers it and Communicator switches on its background send.

## What changed and why

Closes the request "core: system actions: a typed `agent.command` action" (communicator 0.5.0, 0.6.0; Remote Background 0.11.0).

- `system_commands.py` (new) and `run_system_command` in `system_actions.py`. Row `agent.command`, kind `command`, owner `remote-background`, caller allow-list `communicator`, minimum flag `can_send_cmd`, parameters `allowed_templates`, `template_hashes` and `max_timeout` (changed after review, see below).
- Checks in order: a context Core issued, the caller is on the allow-list and owns the run, action declared in the signed manifest now, module enabled now, parameters from the confirmed record only, exact call shape (template id and params, never a command text), the template hash against the confirmed one, `can_send_cmd` as held at creation, the endpoint inside the run's snapshotted targets, the owner's stored scope (also for an unattended run), then the claim, the strict "before" row, the send, the closing row.
- A refusal of this call does not end the run (new `keep_run` in the refusal helper): the call is one endpoint of a batch. Earlier kinds are unchanged.
- New refusal reasons `bad_command` and `duplicate_command`.
- Registration refuses a command row that is not `dangerous=True` or that has `delegable_to`.

## Module-facing change

- `core.system_actions` 1.4.0 to 1.5.0, additive. New operation `run_command` appended after `resolve_delegated_targets`. New public function `tec_tac.system_actions.run_system_command(context, *, action_id, command)`. `requires_framework` for the new part is `>=1.17.75`. New contract row `run_system_command`. New metadata block `command`.
- `SystemFunction` gains the defaulted field `callers`. Every earlier row, digest, result shape and reason code is unchanged. A search of `modules/` finds no use of the new names.
- Remote Background: register `register_system_action("remote-background.command", "remote-background", <label>, "agent.command", ["can_send_cmd"], dangerous=True)` and list the id under `system_actions` in its signed manifest.
- Communicator: make the schedule with the confirmation for `remote-background.command` (parameters `allowed_templates`, `template_hashes`, `max_timeout`), then call `run_system_command` from its own verified Scheduler handler for one endpoint at a time.

## Decisions and assumptions (recorded as information)

- **Idempotency store: the Django cache** (`cache.add`, 24 hours), not a new table. It is atomic, shared by the workers on Tactical's Redis, and needs no migration. A cache that raises refuses the call. Limit: the claim lapses after 24 hours or on a flush.
- **The command text is Core's own**, rendered from a fixed template the module hardcoded (AD-49). See "Fixed after review".
- **Tactical's own audit log** (`AuditLog.audit_raw_command`) is not written, because it would store the command text. Core's rows are the record. Tactical's command history row is written, as for a person's command.
- `run_as_user` is always false.

## What could not run here

Django is not installed on this PC. `tests/system-command-1.17.75.py` runs without it (fake cache, audit and send). The real send (`Agent.nats_cmd`) and the full run path (`_run` with a real Scheduler run) were not run; they need the dev server.

## Fixed after review

The review of 1.17.75 blocked one High finding: the `agent.command` row let the caller choose the command text at run time, so a module on the allow-list had an unattended remote-command primitive that the person had not confirmed (checklist A2, rule 1.7, AD-40). Johan decided on 23 October 2026 (recorded as AD-49): "yes that's narrow enough to not cause issues. fixed command templates should do it. and I would hardcode those templates so that it can only change with a module update." He added: "or if its a file the hash should be recorded."

What changed from d853ff6 (1.17.75):

- **No command text from a caller, ever.** The call is now exactly `{agent_id, command_id, template_id, params}`. A `command` or `shell` field is refused (`bad_command`). The shell, the fixed text and the timeout come from the template. Core renders the final command itself.
- **Template registry.** New `register_command_template(module_id, template_id, *, shell, text=None, file=None, slots=None, timeout=30)`, also exposed as `tec_tac.system_actions.register_command_template`. A module calls it from `AppConfig.ready()`. Only module ids on the row's allow-list (`communicator`) are accepted, and the module must be an installed extension. `template_id` is `<module_id>.<name>`. A template is immutable: the same content again is accepted; different content under the same id is refused (`CommandTemplateError`) and logged.
- **Typed slots.** `{type: "int", min, max}`, `{type: "text", max, chars}` (printable ASCII; quotes and shell metacharacters can never be in `chars`) and `{type: "enum", values}`. Every `{slot}` in the text needs a spec and every spec must be used. A param that does not fit is `bad_command`.
- **Hashes.** Core hashes each template at registration: shell, fixed text (or the SHA-256 of the file content), slot schema and timeout. A file template (an absolute path to a file in the module) is read and hashed again at every run. `tec_tac.system_actions.command_template_hashes(ids)` returns the current hashes.
- **The confirmation replaces `allowed_shells`.** The person confirms `allowed_templates`, their `template_hashes` and `max_timeout`. At run time a template whose current hash differs from the confirmed or the registered hash (a module update, or a changed file) is refused with the new reason `template_changed`: the person must confirm again. A template not in the confirmed list is `action_not_allowed`. An unreadable file fails closed (`function_unavailable`).
- **Audit.** The strict rows now carry the template id and hash, and the confirmed ids and hashes. They still never hold the command text or the output.
- **Unchanged:** the caller allow-list, the owner's stored scope and `can_send_cmd`, the timeout of 1 to 60 seconds, the 1 MiB output cap, the durable `command_id` claim, `dangerous=True`, no delegation, fail closed.

Module-facing (additive on top of 1.17.75, which was never signed): the `run_command` call shape and the row parameters change as above; new `register_command_template` and `command_template_hashes`; new reason `template_changed`. `modules/` had no user of 1.17.75's shape. Remote Background and Communicator must follow (see `reviews/requests/`).

Not run here: Django is not installed, so `_run` with a real Scheduler run, `_registered_plugin` against real modules and the real send were not run. `tests/system-command-1.17.75.py` runs without Django.

## Fixed after review (1.17.75-1 passed review but stopped at promotion)

Changes since the blocked build, all on top of AD-49:

- **M1 (Medium, security): the registering module is verified.** `register_command_template` and `command_template_hashes` no longer trust the `module_id` argument. Core reads the calling module from the stack (`calling_module_for_core_provider`, AD-31). It must equal `module_id` and be on the allow-list (`communicator`). An unverified or different caller is refused. This also closes the open path gap: a template `file` must lie inside that module's install directory, with symlinks resolved, and no part of its path may be a symlink.
- **M2 (Medium, security): a text slot is one token.** A space in a slot's `chars` is refused unless the slot spec says `spaces: true`. A text value may not start with `-`, `/` or a space, so a slot cannot add a flag or a switch. Enum values must start with a letter or digit. Core's module-facing slot rule: slots are single tokens unless declared otherwise.
- **Version text.** The build version no longer appears in source files; it is in `VERSION`, the package manifests and this file's name only. The test file is `tests/system-command-1.17.75.py`.

Module-facing: Communicator must register from its own code (from `AppConfig.ready()` of its own module) and keep template files inside its install directory. A `text` slot whose `chars` include a space needs `"spaces": True`.

## Fixed after review (1.17.75-2)

- **High: `agent.command` could never run.** Creation required the schedule's module to be the registering module (`remote-background`); the run required the caller to be on `callers` (`communicator`). Core now decides the owner of the scheduled action in one place: the schedule's module must be on the row's `callers` list (Communicator). The registering module (Remote Background) must still declare the action in its signed manifest and be enabled, and it never schedules the row itself. `is_registered_system_action(module, action)` answers this for the creation check (`_controls`), the unattended-run decision and the manifest check in `scheduler.py` (new `declaring_module`). At run time `_run` already required the run's module to be the verified caller on `callers`. A schedule is `module_id = communicator`, `action_id = remote-background.command`; Communicator registers that scheduled action with its own handler and does not list the id in its own manifest.
- **Medium: confused deputy.** For a command row `_run` now requires that the `action_id` passed is the very action the run is scheduled for, and that it is registered for the caller. Otherwise `wrong_module`, before `resolve` and before the claim.
- **Low: a missing stored creation scope** now raises `SystemActionRefused('creation_scope_unavailable')` with one deny row, and the run is not ended (it is one endpoint of a batch).
- **Tests.** New `tests/system-command-integration-1.17.75.py` drives the real `describe_confirmation`, `reconcile_schedule`, `_controls`, the worker and `_run` on the stub harness. What stays faked: the Django models, the audit sink, the cache claim and the send to the agent (`run_one` itself is real), Tactical's roles and scope, the module registry. The real `Agent.nats_cmd`, the database and the Celery worker are not exercised.
- **Module-facing.** Communicator: register the scheduled action `remote-background.command` under `module_id="communicator"` with an unattended handler. Remote Background: keep listing the id under `system_actions` in its manifest and registering the row; it does not register a scheduled action for it.

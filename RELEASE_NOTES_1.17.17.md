# Tec-Tac Framework 1.17.17

This release gives modules three things they have been waiting on, and fixes the two findings held from 1.17.16. A Scheduler action can now name a Tactical role flag. Client and site records carry the alert template id, and modules can ask Core about a person's client and site scope without reading Tactical's Role. A signed server module can register its own server-maintenance actions when it is installed, each behind its own permission. Everything for modules is additive: a module that changes nothing keeps working.

Closes, in `reviews/requests/core.md`: the Scheduler entry of patching 0.5.0; the `alert_template_id` entry (alerts 0.6.0); the whole-client check (scoutdns 0.2.0); the Core halves of "Tactical permission flags and role scope for the signed-in user" and "Scope descriptor" (audit 1.4.0, debug 1.3.0, automation 0.5.0, patching 0.2.0, governance 0.3.0, notifications 0.2.0, huntress 0.2.0) and the role scope parts of the agents and alerts entries; "Server-maintenance action registration on install" (tacticalupdater 0.2.0); and "Module server-maintenance actions" (certificatemanagement 0.2.0, securityWAF 0.2.7). Also closes the held Medium and the held Low from the 1.17.16 review.

Capabilities: `core.resources` goes from 1.3.0 to 1.4.0 and `core.server_maintenance` from 1.0.0 to 1.1.0. Both are still major 1.

## Module-facing changes

Modules that use any of these need `requires.framework >=1.17.17`.

| What | Where | Needs a module change? |
|---|---|---|
| `register_scheduled_action(permission=...)` takes `"tactical:<flag>"`, or a list or tuple (any-of). New `ScheduledAction.permission_any` and `permission_any` on the action rows. | `docs/scheduler.md`, `docs/module-scheduling.md` | No. A text permission works as before. |
| Run now refuses a one-off schedule (403) for every caller. `reconcile_schedule` refuses an `owner_key` that starts with `one-off:`. | `docs/scheduler.md` | Only a module that used `one-off:` as its own key prefix. |
| `alert_template_id` on client and site records, appended last. `update_client(client_id, *, name=None, alert_template_id=UNSET, context)` and `update_site(..., alert_template_id=UNSET, ...)`. PATCH accepts it too. | `docs/resource-directory.md` | No. Every new keyword is optional. `name` is optional on `update_client` now. |
| `core.resources`: `scope_descriptor`, `scope_unrestricted`, `has_whole_client_access`, `ResourceAccessContext.scope`. | `docs/resource-directory.md` | No. |
| `GET /api/tfd/ui/context/` carries `tactical_scope` (mode and counts only). | `docs/resource-directory.md`, `docs/tactical-operations.md` | No. Older UI builds ignore it. |
| `core.server_maintenance` 1.1.0: an action may declare `permission` and `owner_module`. `start(..., user=)` and `cancel(..., user=)`. `ServerMaintenancePermissionDenied`. `holds_action_permission`. New keys on action and job rows. | `docs/server-maintenance-capability.md` | No. An action with no permission, and a caller that passes no user, behave as before. |
| `start(parameters=None)` now means no parameters. | `docs/server-maintenance-capability.md` | No. Before, it was refused. |
| Manifest key `server_maintenance_actions`. | `docs/server-maintenance-capability.md`, `docs/module-routes.md` | Yes, for a module that wants to register actions (see below). |

## What changed

### A Scheduler action can name a Tactical flag (patching 0.5.0)

`register_scheduled_action(permission=...)` accepts these forms:

- `"patching.run"`, a Tec-Tac permission. This is the form that existed before.
- `"tactical:can_manage_winupdates"`, a Tactical role flag.
- `["patching.run", "tactical:can_manage_winupdates"]` (or a tuple). This is any-of: one entry is enough. Tec-Tac codes and flags may be mixed. One to 8 entries, no repeats, each a non-empty string.
- `None`, which still means native scheduler managers only.

Registration checks the shape only and raises `SchedulerError` for a bad shape. An unknown flag or code is caught when the action is used. It fails closed, and Core logs it. An error on one entry never blocks the next.

The browser lists follow the same rule (AD-12): the action list, the schedule list and the run history. Because `start_one_off_run` and the AD-13 re-check just before the handler both use the same check, the Tactical flag is read again at run time. A run whose owner lost the flag ends `skipped`, with the audit row, and the handler never runs.

`ScheduledAction` gains one trailing field, `permission_any`, so positional construction and equality of every older action stay as they were. `permission` keeps its text form: the single entry, or the entries joined with ` | ` for display. No new Tec-Tac permission was added, so AD-5 stays true.

### Fixed: a second user could run another user's one-off schedule again (held Medium, 1.17.16 review)

`POST /api/tfd/scheduler/schedules/<id>/run/` used to let any user with the action permission and scope queue a run on someone else's one-off schedule. The run then executed as the first user. Now run-now refuses every one-off schedule with 403, for every caller, before any other check. A single run can no longer be repeated from the browser either.

We listed every place that queues a run. Run-now is the only route that takes an existing schedule id. The self-test makes its own user-owned schedule and needs no change. `reconcile_schedule` also refuses an `owner_key` that starts with `one-off:`, so only `start_one_off_run` can make one. A test now fails if a new route that queues a run is added without a decision.

### Fixed: a name ending in a newline was accepted (held Low, 1.17.16 review)

`audit_before` field names, declared field names (`body_fields`, `query_params`, `audit_fields`, `audit.before` fields) and the upload field name now use `fullmatch`. A trailing newline is refused. This is stricter only for names no module can have meant.

### Alert template on clients and sites (alerts 0.6.0, Johan's answer (a) of 9 October)

Core holds only the field. Client and site records gain `alert_template_id`, an integer or `null`, after the existing keys. Anyone who can list clients or sites sees it. It is an id only: Alerts owns the template list and the picker.

`update_client` and `update_site` set it with a positive whole number and clear it with `None`. Leaving the keyword out leaves the template alone. A boolean, zero, a negative number and text that is not a whole number are refused. An id that names no template is refused too: Tactical's own foreign key decides, so Core imports no Alerts model. The write rule is the same as a rename (Tactical `can_manage_clients` or `can_manage_sites`, the Core resources permission, and the same scope: a whole-client grant for a client, a site grant or a grant of its client for a site). We did not ask for `can_manage_alerts`, because Tactical's own client and site PUT check only the manage-clients and manage-sites flags. The write goes through Tactical's model save, so its own refresh of the agents' cached alert template still runs. The audit row carries before and after records and the flag `alert_template_changed`.

### One description of a person's client and site scope (scoutdns, huntress, notifications, automation, governance, others)

Modules no longer need to read Tactical's Role. `core.resources` 1.4.0 adds:

- `scope_descriptor(context=)`: `{mode, unrestricted, whole_client_ids, site_ids, whole_client_count, site_count}`. `mode` is `unrestricted`, `clients`, `sites`, `mixed` or `none`.
- `scope_unrestricted(context)`.
- `has_whole_client_access(client_id, context=)`: true only for an unrestricted caller or a role that lists the client in `can_view_clients`, and only when the client exists. A site-only role never holds the whole client, not even the client that owns its site.
- `ResourceAccessContext.scope`: the same descriptor, read when asked and never cached.

Core works it out once, in the adapter, from the rule Scheduler targets, report row scope and client writes already use. A test checks that the four agree on one fixture. No role, a Tactical installer user and any lookup failure give mode `none`: Core fails closed. A trusted global service context is unrestricted. A service context that is not global is refused. None of this asks for `can_list_clients`: it is a scope question only.

`GET /api/tfd/ui/context/` gets `tactical_scope` next to `tactical_permissions`: `mode`, `unrestricted`, `whole_client_count` and `site_count`. It carries counts only, so the start-up payload stays small. The ids stay in the Python contract. The UI half is a request in `ui.md`.

### Server-maintenance actions with their own permission (certificatemanagement, tacticalupdater)

An action manifest may carry `permission` (a Tec-Tac permission code) and `owner_module`. Core now enforces the permission itself:

- `start(..., user=user)` needs a user who holds it. A superuser passes. No user, a failed lookup or a missing grant raises `ServerMaintenancePermissionDenied`, writes a best-effort audit row (never the parameters) and creates no job file.
- `cancel(..., user=user)` applies the same check to the job's action.
- A permissioned action whose owner module is not enabled is refused.
- The HTTP routes need `core.privileged_operations` and the action's permission. They answer 403 with the permission to ask for. The action list and the job list and detail routes hide permissioned actions from a caller who lacks it.

This closes the direct route that every holder of `core.privileged_operations` had to the Tactical Updater's protected actions. Actions with no permission are unchanged. It reads as an amendment to AD-10, so it waits for Johan's sign-off (CQ52).

While adding `user=`, we found that `start(action=..., context=...)` with the default `parameters=None` was refused as "parameters must be an object". `None` now means no parameters.

### A signed module registers its own server-maintenance actions on install (tacticalupdater, certificatemanagement, securityWAF)

A module adds `server_maintenance_actions` to `tec_tac.json`, plus `publisher_permissions` `server_maintenance.register`. Core registers the actions when the module is installed and removes them when it is uninstalled. Nobody runs a root script by hand.

- The rules are checked when the manifest is read, and again by the root helper from the root-owned installed manifest. They are never read from job metadata. An id starts with `<module_id>.`. The permission is one the same module declares. The executable is a file below `server_maintenance/actions/` in the module folder: no absolute path, no `..`, no symlink. `argv` and `parameters` are typed, with no shell text. At most 16 entries.
- The root helper gains `--register-module <module-id>` and `--unregister-module <module-id>`. Registering copies each executable into the Core action root as a root-owned 0755 file, records its SHA-256, owner module and permission, writes the registry file atomically, and removes the module's actions that the new manifest no longer declares. An action never runs from the module folder. Dispatch and run check the hash again, so a changed executable stops the action.
- The v2 job helper (install, upgrade, bundle and batch install) registers after the files are installed and the runtime is synced. The legacy helper does the same for an install and unregisters on uninstall. A failed install restores the earlier module code and then re-registers the restored version, or removes the actions when there was none. A registration failure fails the job with a plain message.
- A module that declares nothing is not affected. The job helper only asks the root helper to drop that module's earlier actions, and does nothing when the root helper is not installed.
- Disabling a module does not unregister its actions. A hotfix that changes an action's executable does not re-register, so the hash check stops the action until the module is installed again.
- `protected: true` keeps an action out of automatic registration (CQ54). The Tactical Updater keeps its manual opt-in for its protected actions.
- The sudoers rule for the Tactical account is unchanged. It reaches `--dispatch` and `--cancel` only. A test asserts this from `install.sh`.
- `install-extension.sh` now removes group and world write from an installed module folder. The root helper refuses to register from a folder that is writable by anyone else.

This is root code arriving in a signed package, so please read CQ53.

## Notes for Johan

- Please update the dev server to Core 1.17.16 (still pending from the 1.17.15 and 1.17.16 notes), and then to 1.17.17 once it is signed. Then export a fresh public contract into `docs/contracts`, so module work builds against `core.resources` 1.4.0 and `core.server_maintenance` 1.1.0. Claude cannot export it: it is generated on a running server.
- The module validator under `pipeline/` may refuse the new manifest key `server_maintenance_actions` (and, from 1.17.16, `routes` and `description`) until its allowed-key list learns them. Core does not touch `pipeline/`.
- Four decisions are yours, with the assumption taken in `reviews/questions/core.md`: CQ52 (Core enforces a per-action permission, an amendment to AD-10), CQ53 (a signed package installs an executable that Core's root helper runs), CQ54 (protected actions are never registered automatically), CQ55 (the browser context carries counts only). CQ50 is still unanswered. The Tactical flag re-check here builds on its assumed answer (a). The fix for the one-off run-now hole holds under either answer.

## Checks that ran here

- `bash tests/release-integrity.sh`.
- The new tests: `tests/tactical-operations-audit-before-fullmatch-1.17.17.py`, `tests/scheduler-tactical-permission-1.17.17.py`, `tests/scheduler-one-off-run-now-1.17.17.py`, `tests/resource-alert-template-1.17.17.py`, `tests/resource-scope-descriptor-1.17.17.py`, `tests/ui-context-tactical-scope-1.17.17.py`, `tests/server-maintenance-permission-1.17.17.py` and `tests/server-maintenance-module-actions-1.17.17.py`.
- The earlier tests for the same code, run after the change, with `tests/resource-directory-foundation.py` (version 1.4.0) and a few stubs that pin the new key (`tests/audit-declared-browser-events-1.16.0.py`, `tests/resource-scheduler-audit-scope.py`, `tests/tracker-http-feature-boundary-1.15.172.py`, `tests/scheduler-run-now-*.py`) updated. Every test that passed before the change still passes.
- `python -m py_compile` on every changed file, and `ruff check` on the changed files with no new findings.

## What could not run here

Django, Celery, Tactical and Linux are not installed on the development PC. The stub tests run. These need the dev server (each script says how to run it):

- `tests/resource-alert-template-runtime-1.17.17.py`: the real foreign key, Tactical's save hook, the real roles and `filter_by_role`.
- `tests/server-maintenance-module-actions-runtime-1.17.17.py`: a signed test module, the root helpers as root, systemd dispatch and the sudoers file. It needs a small signed module (`smprobe`) that Core cannot make.

The root helper tests run against a fake owner, mode and symlink layer, because this PC has no root account. `tests/server-maintenance-privilege-boundary.py`, `tests/server-maintenance-root-layout.py` and `tests/server-maintenance-foundation.sh` need Linux and root and were not run. The foundation script now expects capability version 1.1.0.

## Not in this release

- Naming the missing Tactical flag in the 403 of a Tactical operation: it changes pinned wording and needs a decision on an added field or changed text.
- The AD-13 system-action contract (registered Tactical actions run in-process as the owner). This release prepares only the permission side.
- Secret storage, the streamed file answer, a larger body cap for template import, the nested scope source, conditional scope and a per-call audit action, a scope check on the agent of a loaded row, two audit actions on one route, `audit.count_fields` and `permissions_any` for Tactical operations.
- A verified caller identity, the permission alias hook, the reporting replay path, notice fan-out, module user preferences, universal filters, API keys and SSO admin, the Tactical WebSocket ticket and `conflicts_with`.
- The production gate (AD-21 condition 6): Johan names the release first.
- Automatic registration of protected actions. Those stay a manual administrator step.

## Fixed after review

Round 1 blocked 1.17.17 with one high finding.

- **The root trust gate accepted an unsigned package that declares `server_maintenance.register`.** `privileged-trust.py verify-package` derived the permissions from the archive but never refused an unsigned package that asked for more than `module.install`. With the policy floor at "unsigned" or the development override on, that package installed and its executables were registered to run as root. `verify_package` now refuses it with `signature_required`, as `verify_hotfix` already did. It also checks every required permission against the publisher's approved permissions (`publisher_permission_denied`). Both job helpers verify before they install and register, so nothing reaches `actions.d` in either case. Bundles are covered: the permissions of every child package are included.
- Regression test: `tests/privileged-trust-register-permission-1.17.17.py`.

Module-facing: none. A signed package from a publisher that holds `server_maintenance.register` installs as before. An unsigned package with no extra permission is unchanged.

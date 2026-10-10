# Core Server Maintenance Capability

`core.server_maintenance` is the framework-owned durable privileged job contract for generic server maintenance.

## Public capability

Capability ID: `core.server_maintenance`

Version: `1.1.0` (1.0.0 until Core 1.17.16; still major 1 and additive; ask for `>=1.1,<2` and framework `>=1.17.17`)

Operations:

- `start(action, parameters=None, context, user=None)`
- `get_job(job_id, context=None)`
- `cancel(job_id, context, user=None)`
- `list_jobs(status=None, action=None, limit=100, include_output=False, context=None)`
- `list_actions(context=None)`

Since 1.17.17, `parameters=None` means no parameters. Before, `start` refused it with "parameters must be an object". `user` is new in 1.1.0 and is the person a permissioned action runs for (see below).

Jobs are file-backed under `/var/lib/tec-tac/server-maintenance` and privileged execution runs in a detached systemd transient unit. The job therefore does not belong to Django, Celery, NATS, nginx, or the requesting HTTP connection.

## Security boundary

Modules never submit shell text, an executable path, environment variables, or a working directory. They may only start an action that an administrator has already registered.

Registered action manifests live under `/etc/tec-tac/server-maintenance/actions.d`. An administrator can register one by hand (below). Since 1.17.17 a signed module can also register its own actions when it is installed, with no manual root step (see "Registering from a module manifest"). Executables must live under `/usr/local/lib/tec-tac/server-maintenance/actions`, be root-owned, executable, and not group/world writable. The root helper re-validates the manifest and typed parameters immediately before execution.

The Tactical service account receives sudo permission only for:

- `tec-tac-server-maintenance --dispatch <job-id>`
- `tec-tac-server-maintenance --cancel <job-id>`

It does **not** receive sudo permission for action registration, unregistration, arbitrary commands, or a root shell.

Administrators register an action as root:

```bash
sudo tec-tac-server-maintenance --register /root/my-action.json
```

Action registration is itself audited. The root helper has two more modes, `--register-module <module-id>` and `--unregister-module <module-id>`. Only Core's root module job helpers call them. The Tactical account's sudo rule does not reach them.

A registration manifest has this shape:

```json
{
  "id": "vendor.rotate-certificate",
  "revision": "1",
  "description": "Rotate a registered certificate",
  "executable": "/usr/local/lib/tec-tac/server-maintenance/actions/vendor-rotate-certificate",
  "argv": ["--certificate", {"param": "certificate_id"}],
  "parameters": {
    "certificate_id": {
      "type": "string",
      "required": true,
      "pattern": "^[A-Za-z0-9_.-]{1,128}$",
      "max_length": 128
    }
  },
  "timeout_seconds": 900,
  "success_exit_codes": [0],
  "enabled": true,
  "permission": "vendor.rotate",
  "owner_module": "vendor"
}
```

`permission` and `owner_module` are optional (since 1.17.17). An action with neither behaves exactly as before.

Supported parameter types are `string`, `integer`, `boolean`, and `enum`. Unknown parameters are rejected. Sensitive parameters may set `"sensitive": true`; their public job representation is redacted.

## Global maintenance lock

All jobs share one exclusive Core lock:

`/var/lib/tec-tac/server-maintenance/server-maintenance.lock`

A dispatched job may remain in `waiting_for_lock` while another maintenance job is running. Once acquired, the lock remains held for the complete privileged action and is released on success, failure, timeout, or cancellation.

## Operation context and RBAC

Capability callers must provide the standard Core operation context fields:

- `source_module`
- `source_action`
- `requested_by`
- optional `source_run_id`

Use `build_operation_context()` when calling from another module. For automation without a human operator, use a stable value such as `requested_by="system"`.

Core REST endpoints use `SessionAuthenticated` and require the Tec-Tac permission `core.privileged_operations` (a superuser passes). Earlier versions of this page said Tactical `can_do_server_maint`; the code has always checked `core.privileged_operations`:

- `GET /api/tfd/system/maintenance/actions/`
- `GET|POST /api/tfd/system/maintenance/jobs/`
- `GET /api/tfd/system/maintenance/jobs/<job-id>/`
- `POST /api/tfd/system/maintenance/jobs/<job-id>/cancel/`

## Actions with their own permission (since 1.17.17)

An action manifest may carry `permission`, a Tec-Tac extension permission code, and `owner_module`, the id of the module that owns the action.

Core enforces the permission itself, in `start()` and `cancel()`:

- `start(..., user=user)` needs a user who holds the permission. A superuser passes. No user, a failed lookup, an unknown permission code and a missing grant all refuse.
- A refusal raises `ServerMaintenancePermissionDenied` (a `ServerMaintenanceError`, classification `permission_denied`, with a `permission` attribute that names the code to ask for). It writes a best-effort Core audit row (action `deny`, object type `server_maintenance_action`, never the parameters) and creates no job file.
- `cancel(..., user=user)` applies the same check against the permission the job's action had when it started. A job file written before 1.17.17 uses the permission the registry declares now.
- A permissioned action whose `owner_module` is not enabled is refused with classification `action_disabled`. A superuser does not bypass this.
- An action with no permission, and a caller that passes no `user`, behave as in 1.0.0. `tacticalupdater` 0.2.0's hand-registered actions keep working.

The HTTP routes are stricter in the same way. `POST /api/tfd/system/maintenance/jobs/` and `POST .../<job-id>/cancel/` still need `core.privileged_operations`, and for a permissioned action they also need its permission. Without it the answer is 403 with a text that names the permission to ask for. This closes the direct route that anyone holding `core.privileged_operations` had to a permissioned action.

Denied means hidden (AD-12). `GET /api/tfd/system/maintenance/actions/` leaves out a permissioned action the caller does not hold, the job list leaves out its jobs, and the job detail answers 404 as for a job that does not exist.

`list_actions` rows add `permission` and `owner_module` (null when the manifest has none). Job rows add `permission` (null when the action needed none). The existing filtering of sensitive parameter defaults stays.

### AD-10 note

AD-10 says Core adds no separate actor check on privileged capabilities and leaves the permission to the module. This release makes Core check the permission itself for any action that declares one. It reads as an amendment to AD-10 and is recorded as CQ52 in `reviews/questions/core.md`, assumed answer (a), until Johan signs it off. Actions without a permission are unchanged.

## Registering from a module manifest (since 1.17.17)

A signed module declares its actions in `tec_tac.json`. No root script is run by hand.

```json
{
  "id": "vendor",
  "category": "server",
  "publisher_permissions": ["server_maintenance.register"],
  "permission_groups": {"Vendor": ["vendor.rotate"]},
  "server_maintenance_actions": [
    {
      "id": "vendor.rotate",
      "description": "Rotate a certificate",
      "permission": "vendor.rotate",
      "executable": "server_maintenance/actions/rotate.sh",
      "argv": ["--id", {"param": "certificate_id"}],
      "parameters": {"certificate_id": {"type": "string", "required": true, "pattern": "^[A-Za-z0-9_.-]{1,64}$", "max_length": 64}},
      "timeout_seconds": 300,
      "success_exit_codes": [0],
      "revision": "1"
    }
  ]
}
```

Rules, checked when the manifest is read (Python) and again by the root helper from the root-owned installed manifest. They are never read from job metadata:

- Extensions only, at most 16 entries.
- `id` begins with `<module_id>.` and is unique.
- `permission` is required and is one the same module declares in `permission_groups`.
- `executable` is a path relative to the module folder, below `server_maintenance/actions/`. No absolute path, no `..`, no symlink, and the file must exist.
- `argv` entries are literal strings or `{"param": "<name>"}`. `parameters` are typed (`string`, `integer`, `boolean` or `enum`). There is no shell text.
- The module declares `publisher_permissions` `server_maintenance.register`. The publisher that signs the package must hold it (AD-10). The existing trust gate already refuses an unsigned or wrongly signed package.
- `protected: true` keeps an action out of automatic registration (see below).

What happens on install:

1. The module job helper installs the files and syncs the runtime. Then it calls the root server-maintenance helper with `--register-module <module-id>`. This runs in the v2 helper (install, upgrade, bundle and batch install) and in the legacy helper (install), so both paths behave the same.
2. The helper reads `<extensions root>/<module-id>/tec_tac.json`. The module folder, the manifest and each executable on the way must be root-owned and not writable by a group or anyone else, and none may be a symlink. The installer removes group and world write from an installed module for this reason.
3. Each executable is copied into the Core action root under `<module-id>/` as a root-owned 0755 file. An action never runs from the module folder.
4. The registry file records `owner_module`, `owner_version`, `permission`, `executable_sha256` and `registered_by: module-manifest`. It is written atomically as root.
5. The module's registry files that the new manifest no longer declares are removed, with their executables, so an upgrade drops stale actions.
6. Every step is audited in the helper's JSONL log: `action.registered`, `action.unregistered`, `action.skipped_protected`, `module.actions_registered`.

Dispatch and run read the registry file back and compare the executable's SHA-256 with the recorded one. An executable that changed since registration fails closed.

A hotfix that changes an action executable does not re-register. The stale hash fails closed and the action stops until the module is installed again.

If registration fails, the install job fails with a plain message ("server-maintenance action registration failed for module X ... See the job log for the reason"). A failed install restores the earlier module code and then re-registers the restored version, or removes the module's actions when there was none. Uninstalling a module runs `--unregister-module`, which removes every action and executable the module owns and nothing of any other module's.

Disabling a module does not unregister its actions. `start()` refuses a permissioned action whose owner module is not enabled.

A module that declares no `server_maintenance_actions` is not affected: the job helper only asks the root helper to drop that module's earlier actions, and does nothing when the root helper is not installed.

### Protected actions

An action marked `protected: true` is never registered automatically. An administrator keeps the manual opt-in (`--with-protected` in the Tactical Updater's own script) for these. An administrator's hand registration of a protected action stays in place on upgrade. An action that an earlier version registered from the manifest and a later version marks protected is dropped. This is assumption (a) of CQ54 in `reviews/questions/core.md`.

### Sudo

The sudoers rule for the Tactical account is unchanged. It allows `--dispatch` and `--cancel` and nothing else. `--register-module` and `--unregister-module` are reachable only from the root job helpers.

## Durable job state

Public job state includes:

- job/action/status/stage and timestamps
- operation context
- redacted parameters
- global-lock state
- `exit_result` with success, exit code, signal, and timeout state
- structured `failure` classification and message
- bounded stdout, stderr, and lifecycle log output with byte counts/truncation markers

Failure classifications include `dispatch_failed`, `validation_failed`, `lock_failed`, `execution_failed`, `timeout`, `cancelled`, `cancel_failed`, and `worker_error`. Refusals before a job exists add `permission_denied`, `action_disabled` and `action_invalid`.

The helper also appends durable JSONL audit events to `/var/lib/tec-tac/server-maintenance/audit.jsonl`.

## Scope

This capability is generic Core infrastructure. It contains no Tactical update logic and does not prescribe what registered maintenance actions do.

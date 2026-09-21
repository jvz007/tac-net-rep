# Core Server Maintenance Capability

`core.server_maintenance` is the framework-owned durable privileged job contract for generic server maintenance.

## Public capability

Capability ID: `core.server_maintenance`

Version: `1.0.0`

Operations:

- `start(action, parameters, context)`
- `get_job(job_id, context=None)`
- `cancel(job_id, context)`
- `list_jobs(status=None, action=None, limit=100, include_output=False, context=None)`
- `list_actions(context=None)`

Jobs are file-backed under `/var/lib/tec-tac/server-maintenance` and privileged execution runs in a detached systemd transient unit. The job therefore does not belong to Django, Celery, NATS, nginx, or the requesting HTTP connection.

## Security boundary

Modules never submit shell text, an executable path, environment variables, or a working directory. They may only start an action that an administrator has already registered.

Registered action manifests live under `/etc/tec-tac/server-maintenance/actions.d`. Executables must live under `/usr/local/lib/tec-tac/server-maintenance/actions`, be root-owned, executable, and not group/world writable. The root helper re-validates the manifest and typed parameters immediately before execution.

The Tactical service account receives sudo permission only for:

- `tec-tac-server-maintenance --dispatch <job-id>`
- `tec-tac-server-maintenance --cancel <job-id>`

It does **not** receive sudo permission for action registration, unregistration, arbitrary commands, or a root shell.

Administrators register an action as root:

```bash
sudo tec-tac-server-maintenance --register /root/my-action.json
```

Action registration is itself audited. A registration manifest has this shape:

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
  "enabled": true
}
```

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

Core REST endpoints use `SessionAuthenticated` and require Tactical `can_do_server_maint` (or a superuser role):

- `GET /api/tfd/system/maintenance/actions/`
- `GET|POST /api/tfd/system/maintenance/jobs/`
- `GET /api/tfd/system/maintenance/jobs/<job-id>/`
- `POST /api/tfd/system/maintenance/jobs/<job-id>/cancel/`

## Durable job state

Public job state includes:

- job/action/status/stage and timestamps
- operation context
- redacted parameters
- global-lock state
- `exit_result` with success, exit code, signal, and timeout state
- structured `failure` classification and message
- bounded stdout, stderr, and lifecycle log output with byte counts/truncation markers

Failure classifications include `dispatch_failed`, `validation_failed`, `lock_failed`, `execution_failed`, `timeout`, `cancelled`, `cancel_failed`, and `worker_error`.

The helper also appends durable JSONL audit events to `/var/lib/tec-tac/server-maintenance/audit.jsonl`.

## Scope

This capability is generic Core infrastructure. It contains no Tactical update logic and does not prescribe what registered maintenance actions do.

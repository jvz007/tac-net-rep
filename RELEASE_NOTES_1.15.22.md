# Tec-Tac Framework 1.15.22

Adds the public Core `core.server_maintenance` capability for durable privileged server-maintenance orchestration.

- durable file-backed jobs survive Tactical Django, Celery, NATS and nginx restarts/stops
- detached root execution uses transient systemd units rather than Tactical workers
- global server-maintenance locking serializes privileged maintenance jobs
- public provider operations: `start`, `get_job`, `cancel`, `list_jobs`, and `list_actions`
- privileged work is limited to administrator-registered action manifests; modules cannot submit arbitrary root-shell commands
- action manifests and typed parameters are revalidated by the root helper immediately before execution
- Core session/RBAC-protected REST endpoints expose action discovery and job start/read/cancel/list operations
- jobs expose structured status, lock state, stdout, stderr, lifecycle logs, exit result and failure classification
- durable JSONL audit records cover registration, dispatch, lock, start, cancellation and completion events
- release-integrity behavior from 1.15.21 is retained: current + immediately previous root release notes are allowed

The capability is generic Core infrastructure and contains no Tactical-update-specific actions or logic.

# Tec-Tac Framework 1.15.11

- Bumps `core.server_backup` to 1.5.0.
- Adds read-only `get_job_status()` lookup by Core `job_id` and module `source_run_id`.
- Returns sanitized stage/progress/error/log-tail data without exposing `/var/lib/tec-tac/server-backup` to modules.
- Adds persisted backup creation stages and labels, including Tactical privileged-collection sub-stages.
- Adds an explicit recovery-bundle validation stage before destination transfer.
- Preserves all existing native Tactical archive validation, privilege bridge, restore override, and artifact-integrity trust boundaries.

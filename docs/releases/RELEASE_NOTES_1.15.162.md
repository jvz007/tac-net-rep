# Tec-Tac Core 1.15.162

## Review rebuild: Backup & Restore public contract

- Publishes `/api/tfd/system/backups/restore/` GET/POST in the live HTTP contract catalogue.
- Publishes `/api/tfd/system/backups/restore/jobs/<uuid:job_id>/` GET in the live HTTP contract catalogue.
- Documents the effective-superuser plus Tec-Tac session-security boundary, registered-destination constraint, asynchronous job shapes, validation binding, and restore confirmation requirements.
- Adds executable contract-catalog coverage for the native Backup & Restore routes.

No Backup/Restore runtime behavior changed from Core 1.15.162.

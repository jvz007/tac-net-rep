# FIXING.md — Core 1.15.103

## Review scope

This release is intentionally scoped to **M5** from Claude's Tec-Tac Medium/Low tracker.

### M5 — Tec-Tac-only rollback host coverage

Review that a Tec-Tac-only pre-restore transaction snapshots and can restore:

- Tactical `local_settings.py` at `<TACTICAL_ROOT>/api/tacticalrmm/tacticalrmm/local_settings.py`.
- `/etc/systemd/system/rmm.service.d`.
- Persistent `tec-tac-*` systemd units, including known installer units even when absent before restore so a failed restore cannot leave newly introduced units behind.
- Any additional existing `tec-tac-*` unit files/symlinks discovered at transaction start.

The behavioral regression is `tests/server-backup-host-rollback.py`, section `M5 Tec-Tac host integration rollback surface`. It mutates/deletes/adds those surfaces and verifies exact pre-restore state is recovered.

## Out of scope

No M6+ Mediums or unrelated Low items are intentionally addressed in this release.

# Tec-Tac Framework 1.15.7

## Core housekeeping
- Adds `/api/tfd/system/storage/` storage inspection and retention configuration.
- Adds dry-run and purge operations using Core-owned category IDs only; callers cannot submit filesystem paths.
- Covers old local_settings backups, module staging/history, system-update staging/rollback/history, and server-backup staging/history/pre-restore snapshots.
- Protects persistent module state, repository metadata, secrets, deployed UI, source/runtime trees, and configured backup destinations.

## Tactical restore OS override execution
- A valid persisted `target.os` override is now honoured by the actual Tactical restore execution path.
- Core prepares a staged restore.sh only when the override is authorized, verifies Tactical restore.sh v67 and the exact inspected OS-support gate, then removes only that rejection block.
- Real lsb_release-derived OS identity and codename remain untouched.
- Any baseline/version drift fails closed before services are stopped or `/rmm` is moved.
- Without an OS override, restore.sh is copied byte-for-byte unchanged.

# Tec-Tac Core 1.15.103

## M5 — complete Tec-Tac-only rollback host snapshot

- Added Tactical `local_settings.py` to the Tec-Tac-only pre-restore host snapshot.
- Added `rmm.service.d` to the same transaction snapshot.
- Added persistent Core-owned `tec-tac-*` systemd units to rollback coverage.
- Known installer units are recorded even when absent before restore, so rollback removes units introduced by a failed restore.
- Additional existing `tec-tac-*` unit files/symlinks are discovered automatically at transaction start.
- Added a behavioral rollback regression covering modified, deleted, and newly-created host integration files.

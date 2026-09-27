# Tec-Tac Framework 1.15.104

## M6 — safe System Update rollback publication

- System Update rollback archives are now fully validated and extracted to a sibling staging directory before the installed component tree is touched.
- Missing, malformed, truncated or corrupt rollback archives therefore leave the live installation unchanged.
- The live component tree is quarantined with a same-filesystem rename until the staged rollback tree has been published successfully.
- Existing `.git` checkout metadata is preserved across rollback because release backups intentionally exclude Git metadata.
- Failed final publication restores the quarantined live tree instead of leaving the component missing.
- Added `tests/system-update-rollback-backup-safety.py` covering missing, malformed, corrupt and successful rollback cases.

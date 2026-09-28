# Tec-Tac Core 1.15.152

## Summary

Hardens unprivileged Core state publication against concurrent web workers and predictable temporary-file collisions.

## Changes

- Added `framwork/tec_tac/safe_files.py` with a shared `atomic_json()` writer based on a unique sibling `mkstemp` file, `fchmod`, `fsync`, and atomic `os.replace`.
- Migrated Module Manager, System Update, Server Backup, Module Repository, and Server Maintenance state writers away from the shared predictable `<target>.tmp` filename.
- Preserved the existing per-call file modes and JSON serialization behaviour, including `default=str` where required.

## Regression coverage

- `tests/safe-files-atomic-json.py` plants a predictable `.tmp` symlink and verifies it is never followed.
- The same test runs eight concurrent writers repeatedly against one state file and verifies that readers never observe malformed JSON and no unique temp files leak.
- The regression also asserts that all five production writers use the shared safe helper.

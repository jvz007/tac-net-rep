# Tec-Tac Core 1.15.156

## Summary

Hardens the shared unprivileged atomic JSON publisher so successfully replaced state is durably committed at the directory-entry level as well as the file-content level.

## Changes

- `framwork/tec_tac/safe_files.py` now fsyncs the containing directory after `os.replace()`.
- This applies to the Core state writers that already use the shared `atomic_json()` helper, including module state, module repositories, system-update state, server-backup state and server-maintenance state.
- A host crash immediately after rename can therefore no longer leave the caller believing the JSON was flushed while the directory entry itself was not durably committed.
- Added `tests/safe-files-durability-1.15.156.py` to verify `atomic_json()` invokes the directory durability boundary after publication and that the helper fsyncs and closes its directory descriptor.

## Compatibility

No public API or capability contract changes.

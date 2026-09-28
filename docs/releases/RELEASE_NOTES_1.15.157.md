# Tec-Tac Core 1.15.157

## Summary

Hardens recovery public-key imports so the root console command cannot follow a final symlink or read an unbounded input file, and makes imported trust-key publication durable at the directory-entry level.

## Changes

- `tec-tac-recovery-key import` now opens the supplied import file through a no-follow, nonblocking descriptor instead of resolving and reading the path with `Path.read_text()`.
- Import sources must be regular files and are bounded to 256 KiB before JSON parsing, preventing symlink substitution and unbounded root-process reads.
- Newly imported recovery trust keys now fsync the trust directory after the key file is created and fsynced.
- Added `tests/recovery-key-import-1.15.157.py` covering symlink rejection, oversized-input rejection, successful import and directory durability.

## Compatibility

No public API or capability contract changes.

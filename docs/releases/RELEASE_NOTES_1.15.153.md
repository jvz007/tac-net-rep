# Tec-Tac Core 1.15.153

## State publication hardening

- Module state now uses Core's shared unique atomic JSON writer instead of a PID-derived sibling temporary path.
- The root privileged trust-policy writer now publishes through a unique `mkstemp` sibling with root ownership, explicit mode, file fsync, and atomic replace.
- This removes avoidable same-process/concurrent writer collisions and eliminates reliance on predictable policy temporary names.

## Regression coverage

- Added `tests/state-atomic-hardening-1.15.153.py`.
- The test verifies module-state publication ignores the old predictable temp-name pattern and that concurrent root trust-policy writers always leave valid JSON without leaked unique temp files.

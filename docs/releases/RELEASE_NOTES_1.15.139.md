# Tec-Tac Core 1.15.139

## Core leftovers and staged-input hardening

- **L01:** Standalone Module Management v2 batch package identity/version now comes from the root verifier's authenticated `artifact_modules` result. Mutable job-supplied package ids are ignored for identity decisions.
- **L02:** Added behavioral coverage proving the uninstaller parses Tec-Tac config as data through `scripts/tec-tac-config.sh`; shell-looking values are never executed.
- **L03:** Added executable coverage preventing install/recovery scripts from regressing to bare `python3` lookup through `PATH`.
- **L04:** The v1 module worker now reads staged package metadata through the bounded `O_NOFOLLOW|O_NONBLOCK` JSON reader instead of `Path.read_text()`, rejecting symlink/FIFO substitutions.

## Regression coverage

- Added `tests/test_core_leftovers_1_15_139.py` with behavioral coverage for L01–L04.
- Wired the new regression into `tests/module-management-foundation.sh`.
- Existing Module Management and recovery foundations remain green.

No unrelated tracker findings are included in this release.

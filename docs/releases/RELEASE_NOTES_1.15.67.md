# Tec-Tac Framework 1.15.67

## Core server-backup durable-state validator regression

- Fixed `validate_tec_tac_component()` rejecting the same durable Module Manager state files that `create_tec_tac_component()` intentionally packages.
- `/var/lib/tec-tac` remains default-deny. Only `module-manager/module-state.json` and `module-manager/repositories/repositories.json` are accepted as durable state beneath the protected state root.
- The canonical `/var/lib/tec-tac` boundary is always enforced even when recovery-manifest metadata declares a different source state root.
- `state_policy.included_paths` remains descriptive and is not used to expand the validator security allow-list.
- Added regression coverage proving generated Tec-Tac components validate, the two approved state files pass, arbitrary directories/cache/history/staging/server-backup data fail, forged `included_paths` cannot authorize extra state, and full recovery-bundle validation succeeds with the durable files present.
- Updated server-backup documentation to describe the durable-state allow-list rather than the superseded full-state exclusion model.

No `core.server_backup` public contract or capability-version change is required.

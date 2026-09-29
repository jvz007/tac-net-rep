# Tec-Tac Core 1.15.165

## Tracker closure: L10, L24 and L25

- **L10:** recovery-bundle final names are immutable across local, FTP, rclone and SCP publication. FTP no longer deletes final objects before rename; all remote transports check for an existing final archive or sidecar before any publish step and fail closed without replacing recovery evidence.
- **L24:** migration 0015 and repair migration 0020 now reject unsupported target keys instead of silently dropping them into a valid broader schedule. Documented legacy aliases are still canonicalized, invalid rows are quarantined, and run history remains immutable.
- **L25:** persisted endpoint PK aliases are canonicalized to Tactical `agent_id` immediately before scheduled execution as well as at create/edit/migration time. Ambiguous numeric PK/`agent_id` collisions fail closed; module-declared native target types remain unchanged.

Regression: `tests/tracker-closure-1.15.165.py`.

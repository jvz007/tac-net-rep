# Tec-Tac Framework 1.15.40

## Core Notice Center

- Added bounded, per-user persistent notice history for authenticated Tec-Tac UI notifications.
- Added authenticated notice APIs for list/create, mark-read, mark-all-read, and clear-read operations.
- Notice history is retained for 30 days and capped at the latest 500 records per user.
- Persistent actions accept internal Tec-Tac routes only; external/protocol-relative/script URLs are rejected.
- Runtime notification metadata is deliberately not persisted by Core.
- UI context now includes only the current user's unread notice count; history rows remain lazy-loaded by the UI.

## Performance optimisation pass

- The UI context startup path now discovers installed module manifests once and reuses the immutable snapshot for permission discovery, the extension catalogue, and runtime module status.
- The current user's Tactical role is resolved once during UI context construction and reused for user, capability, and permission calculations.
- Existing authorization, publisher trust, signed-tree verification, session-security, and fail-closed update boundaries are unchanged.

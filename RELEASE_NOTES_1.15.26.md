# Tec-Tac Framework 1.15.26

## 24-hour stable release discovery cache

- Persists the last successful stable GitHub release lookup for Framework and UI under `/var/lib/tec-tac/system-updates/cache/release-cache.json`.
- Reuses a successful lookup for 24 hours instead of repeatedly querying GitHub.
- `GET /api/tfd/system/updates/` now includes the read-only `release_cache` snapshot so the UI can immediately display the last known available release.
- `GET /api/tfd/system/updates/online/?component=...` refreshes only when the cache is stale; `force=1` explicitly bypasses the cache.
- Repository lookup failures preserve and return the last known release as stale telemetry rather than erasing it.

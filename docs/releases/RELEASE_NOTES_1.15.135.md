# Tec-Tac Core 1.15.135

## Scheduler history scope and health closure

- **M14:** closes the retained-history scope-query review item with behavioral coverage proving scoped history resolves Tactical scope once per request. PostgreSQL paging remains set-based through the JSONB SQL scope prefilter; the bounded compatibility fallback reuses the same snapshot rather than resolving Tactical scope for each row.
- **L79:** Scheduler `AuthorizationRevoked` health now reports the immutable `schedule_snapshot_id` and saved `schedule_name` when the live schedule has been deleted, with `Deleted schedule` as the final name fallback. Health output no longer reports schedule id `None` or a blank deleted-schedule name.

## Regression coverage

- Added `tests/scheduler-history-health-1.15.135.py` and wired it into `tests/scheduler-foundation.sh`.
- The regression exercises both PostgreSQL set-based paging and the bounded alternate-backend path, and verifies deleted-schedule health uses run snapshots.

No unrelated Scheduler or tracker findings are included in this release.

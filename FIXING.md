# FIXING.md — Core 1.15.102

## Review scope

This release is intentionally scoped to **M4 only** from the Claude/Sol medium tracker.

### M4 — database rollback must not depend on a preserved Tactical tree

**Problem**
`rollback_failed_restore()` restored the Tactical tree first inside the same exception boundary as host/database rollback. If the pre-restore Tactical tree was unavailable, the function raised before replaying the pre-restore PostgreSQL dumps.

**Expected behaviour**
- Tactical tree rollback may fail independently.
- A Tactical tree failure must be retained and reported.
- Host rollback and valid pre-restore database dumps must still be processed.
- Overall rollback remains incomplete/failed when the Tactical tree could not be restored.
- Runtime verification must not claim success after an incomplete tree rollback.

**Implementation areas**
- `scripts/server-backup-helper.py`
- `tests/server-backup-host-rollback.py`

**Behavioural regression**
The M4 regression invokes the real rollback coordinator with:
- a failed live Tactical tree;
- no preserved pre-restore Tactical tree;
- one valid pre-restore PostgreSQL dump.

It verifies that `dropdb`, `createdb`, and `pg_restore` still execute, the database is reported in `rollback_databases`, the tree failure is retained in `rollback_error`, and the overall rollback is not marked successful.

## Explicitly out of scope

No M5+ work, UI changes, scheduler changes, trust-policy changes, or unrelated Low items are part of this release.

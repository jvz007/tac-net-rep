# Tec-Tac Core 1.15.102

## Fixed

- **M4:** restore rollback now treats Tactical tree restoration and database restoration as independent recovery phases. If the original Tactical tree is unavailable, Core records that failure but still restores host paths and replays valid pre-restore PostgreSQL dumps before reporting the rollback as incomplete.
- Added behavioural coverage proving database rollback still runs when no preserved Tactical tree exists.

## Review scope

See `FIXING.md`. This release is intentionally limited to M4.

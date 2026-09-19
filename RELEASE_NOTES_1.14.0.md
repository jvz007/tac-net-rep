# Tec-Tac Framework 1.14.0

## Dashboards

- Adds persistent Core-owned dashboard records.
- Dashboards are owned by a Tactical user and may be `private` or `shared`.
- Private dashboards are visible only to their owner.
- Shared dashboards are visible to every authenticated Tec-Tac user.
- Owners may change visibility after creation.
- Shared dashboards may also be managed by Tec-Tac administrators/server-maintenance roles; private dashboards remain invisible to other users.
- Dashboard layout payloads are validated and bounded before storage.
- Adds authenticated dashboard list/create/detail/update/delete APIs under `/api/tfd/dashboards/`.
- Adds `0005_dashboards` database migration.

## User preferences

- Adds `dashboard.last_dashboard_id` so the existing `restore_last_dashboard` preference can restore the most recently selected dashboard.

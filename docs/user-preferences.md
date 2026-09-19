# User preferences

Framework 1.13.9 adds a Core-owned per-user preference profile backed by Tactical's authenticated user model.

## HTTP contract

`GET /api/tfd/ui/preferences/` returns the current user's normalized preferences.

`PUT /api/tfd/ui/preferences/` replaces the current user's preference document after validation.

`DELETE /api/tfd/ui/preferences/` deletes the stored profile and returns Core defaults.

All methods use `permission_classes = [IsAuthenticated]` and operate only on `request.user`.

`GET /api/tfd/ui/context/` also includes `preferences`, `preferences_initialized`, and `preferences_updated_at` so the UI can hydrate preferences during its existing startup context request.

## Schema

The Core schema currently reserves these sections:

- `appearance`
- `navigation`
- `dashboard`
- `extensions`

The `extensions` object is reserved for future module-specific user settings. Modules should not create separate browser-token or localStorage-based durable preference stores when Core preference storage is available.

Preference payloads are normalized and limited to 128 KiB per user.

Dashboard preferences include `default_dashboard_id`, `last_dashboard_id`, and `restore_last_dashboard`. Dashboard visibility itself is enforced by the dashboard API and is not a preference-layer authorization decision.

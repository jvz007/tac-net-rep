# Tec-Tac Framework 1.13.9

## User preferences

- Adds `TecTacUserPreferences`, a one-to-one server-side preference profile for the authenticated Tactical user.
- Adds authenticated `GET`, `PUT`, and `DELETE /api/tfd/ui/preferences/` operations.
- Adds normalized preferences and initialization metadata to `/api/tfd/ui/context/`.
- Adds Core sections for appearance, navigation, dashboard defaults, and a reserved extension preference namespace.
- Validates preference structure and limits each preference document to 128 KiB.
- Adds migration `0004_user_preferences` and foundation regression coverage.

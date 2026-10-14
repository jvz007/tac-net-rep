# User preferences

Framework 1.13.9 adds a Core-owned per-user preference profile backed by Tactical's authenticated user model.

## HTTP contract

`GET /api/tfd/ui/preferences/` returns the current user's normalized preferences.

`PUT /api/tfd/ui/preferences/` replaces the current user's preference document after validation.

`DELETE /api/tfd/ui/preferences/` deletes the stored profile and returns Core defaults.

All methods use `permission_classes = [SessionAuthenticated]` and operate only on `request.user`, so a valid Tactical credential must also pass Core session trust.

`GET /api/tfd/ui/context/` also includes `preferences`, `preferences_initialized`, and `preferences_updated_at` so the UI can hydrate preferences during its existing startup context request.

## Session theme (1.17.24)

A theme chosen in the dropdown is held for the signed-in session only. It is not written to the saved preference, and it dies with the session, so the next person on the same browser starts clean. Saving the preference stays a separate, explicit action.

- `GET /api/tfd/session/theme/` returns `{ "theme": null }` or `{ "theme": "dark" | "light" | "high-contrast" }`.
- `PUT /api/tfd/session/theme/` with `{ "theme": "light" }` holds the theme for the caller's own current session. Only the three preference themes are accepted. A boolean, `null`, other text or any other body key gives 400 and saves nothing.
- `DELETE /api/tfd/session/theme/` clears it.
- `GET /api/tfd/ui/context/` carries `session_theme` (`null` or the theme) next to `preferences`, so the UI applies it at startup with no extra call. It is additive: older UI builds ignore it.

All three need a signed-in session and touch only the caller's own session row. Another user's session, and another session of the same user, are never changed. Nothing here is audited: it is a display choice, not a security event. `PUT /api/tfd/ui/preferences/` is unchanged, and the UI decides when to call which. A new sign-in creates a new session row, so a second user never sees the earlier user's choice. A revoked row keeps its value only as a tombstone that is never read. Migration `0028_session_theme` adds the one column (`session_theme`, text, empty by default).

## Two stores (1.17.35)

A person's preferences live in two places, and a UI picks the right one for each choice:

- **Tec-Tac's own preferences** (`appearance`, `navigation`, `dashboard`, `extensions`) are the document above. `GET`, `PUT` and `DELETE /api/tfd/ui/preferences/` keep them per person, across browsers.
- **Tactical's UI preferences** (dark mode, the agent table tab, the client tree, the dashboard colours, the date format and the rest) are Tactical's own user columns. `GET` and `PUT /api/tfd/account/tactical-ui/` read and write them, so Tactical's own UI shows the same choice. Their rules and fields are in `my-account.md`. They do not go into the document above.

Core keeps the two apart on purpose. `dark_mode` (Tactical's dark mode switch) and `appearance.theme` (Tec-Tac's three themes) are independent: saving one does not change the other.

A module's own per-person choice is a third, separate store: see `module-preferences.md`. It is not the `extensions` object above, because a saved `extensions` document replaces the whole object and would overwrite a module's choice from another tab.

## Schema

The Core schema currently reserves these sections:

- `appearance`
- `navigation`
- `dashboard`
- `extensions`

The `extensions` object is reserved for future module-specific user settings. Modules should not create separate browser-token or localStorage-based durable preference stores when Core preference storage is available.

Preference payloads are normalized and limited to 128 KiB per user.

Dashboard preferences include `default_dashboard_id`, `last_dashboard_id`, and `restore_last_dashboard`. Dashboard visibility itself is enforced by the dashboard API and is not a preference-layer authorization decision.

## Navigation section ordering (1.15.28)

The server-backed navigation preference document supports `navigation.section_order`, an ordered de-duplicated list of category names. Core validates and persists this value alongside per-category route order, Favorites, collapsed categories, and rail state. No schema migration is required because `TecTacUserPreferences.preferences` remains JSON-backed.

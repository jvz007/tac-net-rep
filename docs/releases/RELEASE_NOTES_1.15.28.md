# Tec-Tac Framework 1.15.28

## Per-user navigation section order

- Extends the existing server-backed user preference contract with `navigation.section_order`.
- Validates section order as an ordered, de-duplicated string list.
- Preserves the existing per-section item order, Favorites, collapsed sections, and rail state contracts.
- No database migration is required because the preference document remains JSON-backed.

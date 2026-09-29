# Tec-Tac Core 1.15.184

## Tracker closure

- F11: strengthened Swagger/OpenAPI acceptance so every currently mounted Core `/api/tfd/` class-based route must have an explicit owner group, module callback ownership wins over Core-looking prefixes, `category=core` produces `Core module · <name>`, and no generic `Tec-Tac · Framework` group may exist.
- Review hygiene now executes the final F11 contract directly and points legacy historical regressions at their actual `tests/legacy/` paths.

## Tests

- Added `tests/f11-tracker-closure-1.15.184.py`.
- `tests/review-hygiene-foundation.sh` now runs the current F11 closure test directly.

Unsigned build.

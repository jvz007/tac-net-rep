# Core 1.15.98

## D5 completion

- Unrestricted Tactical roles can now save and execute `dynamic_unscoped` Scheduler targets.
- Restricted roles still require explicit client, site, or endpoint scope.
- Scheduler health `AuthorizationRevoked` fields now have behavioral regression coverage.
- Save-time and runtime Scheduler scope checks continue to share the Resource Directory scope decision.

## Tests

- `tests/d5-completion.py` executes the real Scheduler scope functions and health-field builder.
- Existing unrestricted-resource and Scheduler scope foundations remain green.

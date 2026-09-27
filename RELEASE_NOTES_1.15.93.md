# Tec-Tac Core 1.15.93

## D1 account-security policy hardening

- L81: strict Core audit contract failures now trigger policy rollback just like audit persistence failures. A requested D1 policy change is not retained without its required Core audit record.
- L82: legitimate Tactical usernames containing `+` or Unicode characters can now be recorded as the policy actor; the privileged helper is invoked with an argv list, not a shell command.
- L84: an effective superuser can repair a corrupt root-owned account-security policy through the normal policy API. The Core audit marks the previous state as unreadable and identifies the repair. If that audit fails, Core fails closed to superuser protection ON instead of retaining the requested unaudited state.

## Regression coverage

- Added `tests/account-security-policy-edge-cases.py` with behavioural coverage for AuditContractError rollback, Unicode/plus actor names, corrupt-policy repair, and fail-closed repair rollback.

## Compatibility

- No database migration is required.
- UI 0.12.41 is paired with this release for the Account Protection failed-save workflow fix.

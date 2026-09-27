# Tec-Tac Core 1.15.107

## M9 — fail-closed corrupt pending trust-policy reverts

- `tec-tac-trust-policy check-revert` no longer treats an unreadable or structurally invalid pending-revert file as if no revert existed.
- Corrupt pending state now restores at least the environment trust floor: `signed_production` in production or `signed_development` in development.
- If the current valid policy is already stronger than the environment default, the stronger current floor is preserved; automatic recovery never lowers trust.
- Pending files with malformed JSON, invalid schema, missing change id, invalid trust levels, or invalid expiry timestamps all take the same fail-closed recovery path.
- Recovery writes a root audit event and clears the corrupt pending state only after the safe floor is enforced.
- Console `set` validates/repairs pending state before classifying the requested target as a lowering operation, preventing corrupt-state recovery from bypassing interactive lowering confirmation.
- Added `tests/trust-policy-corrupt-pending.py` with behavioral coverage for production/development defaults, stronger-current preservation, semantic corruption, and console-set ordering.

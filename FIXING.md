# FIXING.md — Core 1.15.107

## Review scope

This release is intentionally scoped to **M9** from the 27 September 2026 Claude tracker.

### M9 — corrupt pending trust-policy auto-revert fails open

Core 1.15.106 treats an unreadable pending revert file as `None`, so `check-revert` reports `no_pending_revert`. If the trust floor was temporarily lowered, corruption of that state can therefore leave the weaker floor in place indefinitely.

Review that this release:

1. Treats malformed JSON, Unicode/read errors, invalid schema, missing change id, invalid previous/temporary levels, and invalid expiry timestamps as corrupt pending state.
2. Recovers to at least the environment default floor (`signed_production` for production, `signed_development` for development).
3. Never lowers a current valid floor that is already stronger than the environment default.
4. Writes the safe floor before clearing the corrupt pending file.
5. Writes root audit event `policy_pending_revert_corrupt_recovered` with current/default/restored levels and a bounded error description.
6. Validates/repairs pending state before `set_level()` decides whether interactive lowering confirmation is required.
7. Includes executable behavioral regression `tests/trust-policy-corrupt-pending.py`.

## Primary files changed

- `scripts/trust-policy-cli.py`
- `tests/trust-policy-corrupt-pending.py`
- `docs/trusted-publisher-verification.md`

## Explicitly out of scope

No other Medium or Low tracker item is intended to be closed by this release.

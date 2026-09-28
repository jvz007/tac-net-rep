# Tec-Tac Core 1.15.132

## Session and MFA hardening

- **M2:** Knox invalidation now lives at the common Tec-Tac session revocation boundary, covering automatic as well as explicit revocation. Legacy unbound trust rows fail closed by invalidating that username's Knox tokens.
- **L80:** retention keeps legacy revoked rows with an empty Knox digest while the recorded username still has a live Tactical Knox token.
- **L88:** backup-code verification now atomically reserves one of five per-username verification slots before code verification, so concurrent wrong-code requests cannot all pass a check-then-record race.
- **L89:** wrong-password recovery attempts use a separate, looser 20-attempt / 15-minute username budget; only password-valid backup-code verification uses the five-attempt budget.

## Compatibility

No database migration or public capability version change is required.

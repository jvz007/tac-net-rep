# Tec-Tac Core 1.15.133

## Trust-policy hardening

- **M9 / L28:** serializes trust-policy mutation, pending-revert checks, automatic reverts and corrupt-pending recovery behind one root-owned advisory lock. Corrupt pending state continues to fail closed to `secure_signed` before it is cleared.
- **L26:** the authenticated trust-policy PUT uses dedicated Tec-Tac authenticated-operation throttles (`10/min`, `100/day`) instead of Tactical anonymous login throttles.
- **L27:** the install-time immediate `check-revert` is best-effort; an unexpected one-shot failure is logged and the persistent systemd timer remains the durable retry path.
- **L29:** equal-strength upgrade ties prefer the current root-owned policy, preserving administrator metadata and avoiding a rewrite on every upgrade.
- **L30:** trust-policy responses again expose `help_url` alongside the built-in `help_article`, including the existing configurable URL override.

## Regression coverage

- Added `tests/trust-policy-batch-1.15.133.py` and wired it into the System Update foundation.
- Extended migration and policy tests for equal-strength preservation and dual help fields.

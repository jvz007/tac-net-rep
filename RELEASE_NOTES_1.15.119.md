# Tec-Tac Core 1.15.119

## Scope

This release continues from the review-passed 1.15.118 baseline and respects the agreed maximum of **1 Medium + 5 Low** findings per pass. This pass closes **M9** from the supplied open-review list. No UI or Decision items are included.

## Fixed

### M9 - corrupt pending trust-policy revert now fails fully closed

A corrupt `pending-trust-policy-revert.json` destroys the only trustworthy record of the trust floor that existed before a temporary lowering. The previous recovery path restored only to the environment default (`signed_production` in production or `signed_development` in development). That was safer than leaving a temporarily lowered policy in place, but it could still be weaker than the unknown pre-change policy when the server had originally required `secure_signed`.

Core now treats a corrupt pending revert as an indeterminate security state and restores the update/module trust floor to the strongest supported level, **`secure_signed`**. The corrupt pending file is cleared only after that stronger policy is written, and the root-owned trust audit records `recovery_mode=fail_closed_strongest`.

This applies consistently to the periodic `check-revert` path, the root-console `get` path, and a subsequent `set` operation that first discovers corrupt pending state.

## Regression coverage

- `tests/trust-policy-corrupt-pending.py` proves corrupt syntactic and semantic pending records recover to `secure_signed` in both production and development environments.
- The regression also proves a later lowering request starts from the recovered `secure_signed` floor, preserving the fail-closed boundary.
- `tests/open-list-closure-1.15.119.py` statically guards the strongest-floor recovery and audit marker against regression.

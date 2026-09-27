# FIXING.md — Core 1.15.119

This build continues from the review-passed 1.15.118 baseline and respects the agreed maximum of **1 Medium + 5 Low** findings per pass.

## M9 — trust-policy corrupt pending revert fails fully closed

- A corrupt `pending-trust-policy-revert.json` no longer restores only to the environment default.
- Because corruption removes the trustworthy record of the previous trust floor, Core now raises the policy to the strongest supported level, `secure_signed`.
- The pending file is cleared after the stronger policy is written.
- Root audit output records `recovery_mode=fail_closed_strongest` so operators can distinguish emergency fail-closed recovery from a normal timed revert.
- A subsequent trust-policy operation observes the recovered `secure_signed` floor before applying any requested change.

## Regression coverage

- `tests/trust-policy-corrupt-pending.py`
- `tests/open-list-closure-1.15.119.py`

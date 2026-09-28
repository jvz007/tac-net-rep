# Tec-Tac Core 1.15.147

## MFA administrative and backup-code closure

This release closes the remaining behavioral-evidence gaps for L47, L48, L49, L88 and L89 without changing already-correct production MFA logic.

- L47: executable coverage proves a non-authorized administrator receives 403 before protected-account MFA status is read.
- L48: executable service coverage proves status reads do not delete stale recovery codes or emit mutation audits.
- L49: executable service coverage proves automatic TOTP-change invalidation uses `mfa_backup_codes_invalidated_totp_change`, while explicit administrator invalidation uses `mfa_backup_codes_invalidated` with the explicit marker.
- L88: executable view coverage proves the tight recovery-code admission slot is claimed before code verification and a rate-limited attempt never reaches `consume_backup_code`.
- L89: executable view coverage proves wrong-password failures consume only the looser password-failure budget, while correct-password/wrong-code attempts use the separate tight recovery-code budget.

Added `tests/mfa-closure-1.15.147.py` and wired it into the normal Access/MFA foundation.

No production Core code was changed in this release.

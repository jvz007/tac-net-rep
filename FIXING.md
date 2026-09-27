# FIXING.md — Core 1.15.132

## Review scope

This release is intentionally limited to the session/MFA tracker batch: **M2, L80, L88 and L89**.

Review that:

1. Every Tec-Tac trust-row revocation path invalidates Tactical Knox at the common `_revoke_locked` boundary.
2. A legacy revoked row without `knox_digest` fails closed rather than leaving an identifiable user's Tactical tokens live.
3. Retention preserves an old empty-digest tombstone while that username still has a live Knox credential.
4. Backup-code verification reserves the tight five-attempt budget before `consume_backup_code` executes.
5. Wrong-password failures use a separate, looser per-username budget and do not consume the five backup-code verification slots.
6. Existing session/MFA, System Update, Module Management and release-integrity regressions remain green.

## Explicitly out of scope

No unrelated tracker findings are included in this release.

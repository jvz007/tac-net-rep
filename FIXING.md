# FIXING - Core 1.15.105

## Review scope

This release addresses **M7 only** from Claude's Tec-Tac Medium/Low tracker.

### M7 - legacy backup retention compatibility

Older saved retention policies may not contain `keep_unclassified`. Core must not reject those policies or interpret omission as deletion.

Expected behavior:

- Provider-side normalization accepts a legacy policy with `keep_daily`, `keep_weekly`, and `keep_monthly` but no `keep_unclassified`.
- Omitted `keep_unclassified` normalizes to `10000`, the existing supported maximum, so legacy/no-sidecar backups are retained rather than deleted after upgrade.
- The privileged helper independently applies the same safe legacy default if it receives an older request shape.
- New/updated callers should continue to send `keep_unclassified` explicitly.
- An explicit `keep_unclassified` value is still honored exactly; the compatibility default does not override explicit policy.

## Behavioral regression

`tests/server-backup-retention-compat.py` verifies:

1. provider normalization of a legacy policy to `keep_unclassified=10000`;
2. helper execution does not delete unclassified backups for the legacy shape;
3. explicit `keep_unclassified=1` still deletes older unclassified backups according to policy.

The older grep assertion requiring the previous error string was removed from `server-backup-review-hardening.sh` and replaced with this behavioral test.

## Not in scope

No other Medium or Low tracker items are intentionally addressed by this release.

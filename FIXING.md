# FIXING.md — Core 1.15.122

This build continues from the review-passed 1.15.121 baseline.

## D2 — older Core restore is now an enforced version transition

- Recovery bundles may intentionally restore an older Core version.
- After the restored framework installer completes, Core now verifies that the effective installed Core version exactly matches the backup manifest `framework_version`.
- A restore that claims to downgrade but leaves a different Core version installed is treated as a failed restore and enters the existing transactional rollback path.
- Successful restore results now expose the verified `version_transition`, including `effective_core_version` and `version_verified`.

## Regression coverage

- `tests/server-backup-d2-version-transition.py`
- existing `tests/server-backup-d2-d3.py`

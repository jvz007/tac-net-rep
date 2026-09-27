# Tec-Tac Core 1.15.122

## Scope

This release continues from the review-passed 1.15.121 baseline and closes **D2** from the supplied open-review list. No UI findings or other Decision items are included.

## Fixed

### D2 — restoring to an older Core version is verified, not merely reported

Core already allowed a recovery bundle to declare an older `framework_version` and reported the downgrade in restore validation. The remaining gap was that the destructive restore did not prove that the final installed Core actually matched that declared version.

Core now treats the backup-declared framework version as a post-restore invariant:

- the version transition still reports the current and restored Core versions before mutation;
- after the restored Core installer and runtime verification complete, Core reads the effective installed framework version;
- the effective version must exactly match the recovery manifest `framework_version`;
- a mismatch fails the restore and enters the existing pre-restore rollback path;
- successful restore results include `version_transition.effective_core_version` and `version_transition.version_verified=true`.

This means an intentional downgrade such as `1.15.121 -> 1.15.108` is now complete only when the server is genuinely running Core 1.15.108 afterward.

## Regression coverage

- `tests/server-backup-d2-version-transition.py` verifies downgrade detection, exact-version success, and mismatch rejection.
- `tests/server-backup-d2-d3.py` continues to cover recovery continuity and security-state preservation.

# Tec-Tac Core 1.15.173

Final tracker-acceptance consolidation for D2, D3, L10, F1, F2, F4, F5, F6, F7 and F11. Companion UI release: 0.12.67.

## D2 / D3 — destructive restore orchestration
- Adds an executable regression through the real `operation_restore_backup()` control flow.
- Proves an older backup-declared Core version is accepted, propagated into reintegration, installed and then verified as the effective Core version.
- Proves the pre-restore Tactical service activity snapshot flows through the destructive restore and is restored before runtime verification.
- Preserves source server, installation ID and recovery signer identity at the verified bundle boundary.

## L10 — final publication atomicity
- Adds one explicit local/FTP/rclone/SCP acceptance test.
- Every transport proves sidecar-first publication, forced final-archive failure, sidecar rollback and absence of a published final archive.
- Backup implementation behavior is unchanged.

## F1/F2/F4/F5/F6/F7/F11 — consolidated Core acceptance
- One Core acceptance runner executes the existing real DRF/runtime/OpenAPI regressions together with the new D2/D3/L10 tests.
- `docs/tracker-acceptance-1.15.173.md` maps each tracker row to its production boundary and executable regression.

## Regression coverage
- `tests/tracker-acceptance-1.15.173.py`
- `tests/d2-d3-restore-orchestration-1.15.173.py`
- `tests/l10-publication-final-1.15.173.py`
- inherited `tests/tracker-http-feature-boundary-1.15.172.py`
- inherited `tests/f11-openapi-ownership-1.15.172.py`

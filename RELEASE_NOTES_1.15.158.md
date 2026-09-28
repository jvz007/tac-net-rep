# Tec-Tac Core 1.15.158

## Summary

Tracker-closure release for the remaining Core items in `CORE-UI-REVIEW-1.15.84-0.12.37`. This release intentionally prioritises closure evidence over unrelated hardening.

## Tracker closure work

- **M18**: repaired both historical 1.15.52 regression harnesses so they execute against the current package-relative Core imports instead of failing before their assertions. `review-regressions-1.15.52.py` now imports `tec_tac.module_state` as a package, and `review-1.15.52-rebuild.sh` provides the `tec_tac.safe_files` dependency required by the current repository module.
- **D2 / D3**: retains and explicitly regression-gates older-Core restore transitions, recovery-signer continuity, trust merge, exact restored-Core version handling, and preservation of pre-restore Tactical service state.
- **L04 / L07**: regression-gates no-follow staged metadata reads and portable trusted Bash resolution.
- **L10 / L15 / L76**: regression-gates sidecar publication rollback, host-snapshot preflight accounting, and recovery-key trust/ownership/symlink boundaries.
- **L24 / L25**: regression-gates immutable scheduler run history, migration/runtime target compatibility, and endpoint PK/agent-id canonicalisation.
- **L26 / L27**: regression-gates authenticated Trust Policy throttles and a bounded, non-fatal immediate revert check with the persistent timer already active.
- **L61**: the three formerly root-only regressions are executed as an unprivileged user in the closure suite.
- **L63**: release-archive continuity and canonical clean-version filenames remain release-gated.
- Added `tests/tracker-open-closure-1.15.158.py` as an explicit tracker-ID closure manifest/test runner.

## Compatibility

No public API or capability contract changes.

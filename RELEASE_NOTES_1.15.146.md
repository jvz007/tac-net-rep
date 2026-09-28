# Tec-Tac Core 1.15.146

## Restore continuity and review-hygiene closure

This release closes the remaining evidence/runner gaps for D2, D3, M18, L61 and L62 without changing already-correct production restore behavior.

- D2: `server-backup-d2-d3.py` and `server-backup-d2-version-transition.py` are now wired into the normal server-backup foundation, so older-Core restore/version-transition behavior is exercised by the standard backup suite.
- D3: `server-backup-d3-service-state.py` is now wired into the same foundation, preserving executable coverage for signer identity, restore continuity and pre-operation Tactical service state.
- M18: `system-update-claim-security.py` and `module-v2-verified-bytes-boundary.py` were removed from ordinary foundations and moved to `tests/root-required-foundation.sh`, which explicitly skips outside root and executes both tests when root.
- L61: the portable privileged-helper, immutable-artifact and recovery-trust tests remain wired into `review-hygiene-foundation.sh` and continue to exercise production helpers with only narrow ownership fixtures.
- L62: `tests/tracker-closure-1.15.146.py` guards the corrected 1.15.83 wording so grep/structural assertions cannot again be described as a full behavioral regression harness.

No production Core code was changed in this release.

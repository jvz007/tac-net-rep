# Tec-Tac Core 1.15.129

## Review/test hygiene batch

This release closes tracker items **M18, L50, L51, L54, L61 and L62** without changing operator-facing Core behavior.

### M18 — stale regressions now execute against current contracts
- Updated the historical 1.15.52 housekeeping assertions to the current fail-closed zero-retention contract.
- Updated the old repository SSRF assertion to the current per-hop `_resolve_remote_url()` plus pinned-connection implementation.
- Updated the old GitHub-token and session-security assertions to the current hardened contracts.
- `review-regressions-1.15.52.py`, `review-1.15.52-rebuild.sh`, and `system-update-claim-security.py` now pass against this tree.

### L50 / L51 / L54 — durable closure guards
- Added an executable guard for the documented administrator MFA recovery endpoint.
- Added an AST guard preventing the removed `timedelta` import from returning to `views.py`.
- Added a guard requiring stable `Invalid pagination parameters.` responses instead of raw integer-conversion errors.

### L61 — security regressions no longer require root
- `privileged-helper-environment.py`, `module-artifact-immutable-claim.py`, and `server-backup-recovery-trust.py` now model only root ownership in non-root fixtures while retaining their real mode, symlink, path and immutable-copy checks.
- Added `tests/review-hygiene-foundation.sh`, which runs these tests as `nobody` when the suite itself is executed as root.

### L62 — release-note claim corrected
- Archived `docs/releases/RELEASE_NOTES_1.15.83.md` with corrected wording: the original login-session test was structural contract coverage, not a full behavioral regression harness.

## Compatibility

No database migration or public API behavior change is introduced by this release.

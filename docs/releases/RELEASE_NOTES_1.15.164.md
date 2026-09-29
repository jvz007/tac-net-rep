# Tec-Tac Core 1.15.164

## Final tracker review closure: D2, D3, L10, L15, L24, L25

- Recovery bundles are now created only inside Core-private staging. `/rmmbackups` and configured local destinations receive a bundle only through the sidecar-first local publisher, so a final archive is never used as the build workspace.
- Local recovery archive names are immutable. A sidecar publication failure cannot expose the archive, and an archive publication failure rolls the newly published sidecar back.
- Full/Tactical restore disk preflight now includes conservative PostgreSQL rollback-snapshot bytes (`tacticalrmm` and `meshcentral`) in addition to host-path snapshot bytes.
- Scheduler target normalization now writes singular canonical Tactical target types (`client`, `site`, `endpoint`). Migration 0015 enforces current dynamic-filter scope rules and never rewrites run history.
- Added migration 0020 to repair schedules on installations where 0015/0019 had already run before the final target-parity rules shipped.
- Scheduler run-history scope snapshots now expose legacy Agent PK aliases only when the token resolves unambiguously; numeric PK/`agent_id` collisions fail closed.
- The D2/D3 recovery-continuity regression is now runnable as an ordinary unprivileged CI user while preserving real cryptographic, symlink and permission-mode behavior.

## Verification

- `tests/tracker-final-review-1.15.164.py`
- `tests/server-backup-d2-d3.py` as an unprivileged user
- inherited backup, Scheduler, contract and release-integrity suites

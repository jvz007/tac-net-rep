# Tec-Tac Core 1.15.137

## Server-maintenance and housekeeping hardening

- **L35:** Server-maintenance jobs created before the root-private claim model remain cancellable. Legacy cancellation stops only the UUID-derived systemd unit and does not trust mutable unit names from the public job record.
- **L36:** Server-maintenance no-follow JSON reads add non-blocking open semantics so FIFO/device substitutions are rejected by `fstat()` without hanging the privileged helper.
- **L37:** The root-owned Tec-Tac config is opened once with `O_NOFOLLOW`, ownership/mode checked with `fstat()`, and read through that same descriptor, removing the check/read race.
- **L38:** Housekeeping claim publication is atomic and no-clobber. Concurrent runs using the same request UUID can no longer replace the first root-owned claimed copy.
- **L39:** Housekeeping `results/` is installed root-published and Tactical-read-only (`2750`). The helper rejects group/world-writable result directories and prunes stale root-owned result files itself.

## Regression coverage

- Added `tests/maintenance-housekeeping-hardening-1.15.137.py` and wired it into the housekeeping foundation.
- Updated the server-maintenance root-layout regression for the descriptor-based config trust boundary.
- Existing server-maintenance privileged-boundary and housekeeping claim/config/legacy-policy regressions remain green.

No unrelated tracker findings are included in this release.

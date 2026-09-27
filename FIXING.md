# FIXING.md — Core 1.15.137

## Review scope

This release is intentionally limited to **L35–L39** from the current Core tracker.

### L35 — legacy server-maintenance cancellation
Public-only jobs created by pre-claim releases can be cancelled after upgrade. Core derives the systemd unit strictly from the validated UUID and never trusts a legacy job's stored unit name.

### L36 — FIFO-safe no-follow reads
Privileged server-maintenance state reads use `O_NOFOLLOW|O_NONBLOCK` and reject non-regular descriptors with `fstat()` before parsing.

### L37 — config ownership/read race
The fixed Tec-Tac config path is opened once, verified on the open descriptor, and read from that same descriptor.

### L38 — housekeeping claim collision
Claim publication uses atomic no-clobber linking. A second run with the same request UUID fails instead of replacing the first root-owned claim.

### L39 — root-published housekeeping results
`results/` is root:Tactical mode 2750. The root helper rejects writable result directories and owns stale-result pruning; Django retains read access without directory mutation rights.

No other tracker findings are intentionally changed.

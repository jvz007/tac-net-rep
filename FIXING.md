# FIXING.md — Core 1.15.133

## Review scope

This release is intentionally limited to the tracker trust-policy batch: **M9, L26, L27, L28, L29 and L30**.

Review that:

1. `set`, `check-revert`, explicit revert and corrupt-pending recovery cannot race each other.
2. Corrupt pending state still moves the active policy to `secure_signed` before clearing the pending file.
3. Trust-policy PUT is protected by authenticated Tec-Tac throttles rather than Tactical login throttles.
4. A failed immediate installer `check-revert` cannot abort installation; the timer remains enabled for retry.
5. Equal-strength migration ties preserve the current root-owned policy bytes and administrator metadata.
6. Both `help_article` and `help_url` are present in trust-policy/help responses.

## Explicitly out of scope

- Scheduler findings M13/M14 and scheduler Low findings.
- Backup, maintenance, housekeeping and module-install findings.
- UI findings.

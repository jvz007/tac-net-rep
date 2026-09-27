# Tec-Tac Core 1.15.91

## M1 - MFA backup-code throttling

- Backup-code generation proof failures are now keyed to the account only, not account plus source IP.
- Five failed proof attempts are allowed per 15-minute window; subsequent attempts return HTTP 429 with `Retry-After`.
- A successful proof clears the proof-failure bucket.
- Successful backup-code rotations use a separate account-only 20/day budget so failed proofs do not consume the success allowance.
- Backup-code recovery login now has an additional Tec-Tac failure budget keyed to normalized username: five failed recovery attempts per 15 minutes, reset after a successful recovery login.
- Tactical's existing generic login minute/day throttles remain in force for recovery login.

## Low - MFA recovery endpoint documentation

- Expanded the Session Security documentation for backup-code status, rotation, administrative invalidation, recovery login and rate-limit behavior.

## Compatibility

- No database migration is required.
- UI 0.12.40 remains compatible; no UI release is required.

# Tec-Tac Core 1.15.87-2

## Restore continuity and recovery trust

- Older signed Core recovery bundles may be restored without a downgrade block. Restore validation and execution expose the current/restored Core versions and a clear downgrade notice when the bundle rolls Core back.
- Downgrade restores are durably recorded in the root recovery audit log.
- Restore now preserves target-side security state: current trusted-publisher state takes precedence for publishers already known on the target, so later revocations remain revoked, and the update trust floor keeps the stricter of the current and restored values.
- Recovery signing/trust directories remain target-local and are never restored from a backup.
- Recovery bundle manifest/sidecar inventory now includes source installation ID, server name, signer key ID and signer fingerprint.
- Non-destructive restore validation can inspect a cryptographically valid unknown signer without trusting it. Destructive restore remains fail-closed until the signer is trusted.
- Added a superuser-only Core trust endpoint for one-confirmation signer trust after validation.
- Added `tec-tac-recovery-key status|export|import` for optional root-console public-key trust preparation. The private signing key is never exported.
- `core.server_backup` is now capability version 1.7.0 and documents the new signer/version-transition fields and recovery trust endpoint.

## Low-risk cleanup

- Privileged Python helpers no longer hard-code `/usr/bin/bash`; each resolves Bash from `/bin/bash` or `/usr/bin/bash` and requires the executable to be root-owned, regular and not group/world writable.
- The live HTTP contract catalogue now publishes pagination query/response metadata for module-job history, session audit, active login sessions and scheduler run history, plus the recovery trust route contract.

## Verification

- Added D2/D3 recovery-continuity regression coverage for unknown-signer inspection, explicit trust, revoked-publisher preservation, stricter trust-floor merge and Core downgrade notice behavior.
- Added privileged Bash path-boundary regression coverage.

## Rebuild 1

- Recovery signer trust now uses the Core `SessionAuthenticated` permission boundary instead of Tactical-only `IsAuthenticated`.
- Pre-TOTP Knox setup credentials and revoked Tec-Tac sessions therefore cannot call recovery trust GET or POST.
- Added a regression that binds `RecoveryTrustView` to `SessionAuthenticated` and the shared MFA/session revocation enforcement path.

## Rebuild 2

- Removed recovery identity and signer-trust methods from the public `core.server_backup` capability provider.
- Recovery trust now remains Core-internal behind the `SessionAuthenticated` + effective-superuser HTTP boundary.
- Added regression coverage proving modules cannot obtain or invoke a recovery-trust primitive through `get_capability("core.server_backup")`.

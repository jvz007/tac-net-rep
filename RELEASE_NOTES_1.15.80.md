# Tec-Tac Core 1.15.80

## Security: N1 recovery-bundle trust boundary

- Added mandatory Ed25519 authentication for Tec-Tac version-2 recovery bundles. The exact `manifest.json` and `checksums.sha256` bytes are signed into `recovery-signature.json`.
- Added a persistent server recovery identity under `/etc/tec-tac/recovery-signing/`; upgrades preserve an existing key instead of rotating it.
- Added root-owned `/etc/tec-tac/recovery-trust/` public-key trust anchors. A bundle-carried candidate public key never self-authorizes a restore.
- Excluded recovery private keys and recovery trust anchors from backup payloads so restore cannot overwrite its own trust boundary.
- Added a fixed Tec-Tac restore destination allow-list. Signed payloads cannot write arbitrary host paths such as `/etc/cron.d`, `/root/.ssh`, unrelated systemd units, or other non-Tec-Tac locations.
- Post-restore framework/UI installer paths now come only from the target server's root-owned local configuration; recovery-manifest path fields are descriptive only.
- Added regression coverage for valid signatures, tampered manifests, untrusted signers, signed path escapes, and attempted recovery-trust replacement.

## Compatibility

Older unsigned version-2 Tec-Tac recovery bundles are rejected by the new authenticity boundary. Legacy native Tactical archives remain available for Tactical-only recovery.

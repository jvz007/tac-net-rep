# Tec-Tac Core 1.15.121

## Scope

This release continues from the review-passed 1.15.120 baseline and respects the agreed maximum of **1 Medium + 5 Low** findings per pass. This pass closes **M20** from the supplied open-review list. No UI or Decision items are included.

## Fixed

### M20 - stored backup credentials are bound to their destination endpoint

Core no longer permits a browser-supplied destination to reuse an existing stored backup credential against another remote endpoint. `core.server_backup` 1.8.0 binds each newly stored remote secret to a canonical destination identity before the credential can be used.

- SFTP/SCP/FTP credentials bind to transport, host, port and username.
- WebDAV credentials bind to scheme, host, port and base path.
- S3 credentials bind to provider, endpoint, region and bucket.
- Destination ids and remote object paths are not treated as security boundaries.
- Legacy unbound secret files are rejected for remote use and must be re-saved once.
- Binding is checked before any network operation opens a connection or sends credentials.

The recovery-signer trust path still resolves only a previously validated server-side `destination_id`; this change closes the earlier credential-exfiltration window during destination validation itself.

## Regression coverage

- `tests/server-backup-credential-binding.py` verifies same-endpoint reuse, different-host rejection and legacy-unbound rejection.
- Existing server-backup, recovery-trust and destination-validation foundations continue to guard the privileged helper boundary.

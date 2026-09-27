# FIXING.md — Core 1.15.121

This build continues from the review-passed 1.15.120 baseline and respects the agreed maximum of **1 Medium + 5 Low** findings per pass.

## M20 — backup credentials are endpoint-bound

- `core.server_backup` is now capability version 1.8.0.
- `store_secret(...)` accepts the intended destination (without `secret_ref`) and stores a root-owned credential envelope containing the canonical endpoint binding.
- Remote credential loading verifies that binding before any transport connection is created.
- Reusing a credential against another host/URL/S3 endpoint or bucket is rejected.
- Existing legacy raw secret files are treated as unbound and are rejected for remote use until re-saved.
- Recovery signer trust continues to use only server-registered destination ids.

## Regression coverage

- `tests/server-backup-credential-binding.py`
- existing server-backup foundation and recovery trust regressions

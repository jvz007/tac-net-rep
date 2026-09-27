# FIXING.md — Core 1.15.128

## Review scope

This release is intentionally limited to the tracker batch:

- M19 — native Tactical archive cleanup and raw repository sync error disclosure.
- L09 — local staging deletion after size-only remote verification.
- L10 — archive publication before sidecar publication.
- L11 — `filter="data"` cancelling `numeric_owner` restore semantics.
- L12 — FTP destinations missing `tls_mode` silently switching transport.
- L13 — malformed root-owned config crashing privileged helpers at import time.

## Expected outcome

Backup staging, destination publication and restore metadata handling remain fail-safe, and non-manager repository status no longer exposes raw synchronization errors.

## Explicitly out of scope

All other Medium, Low, UI and Decision tracker items.

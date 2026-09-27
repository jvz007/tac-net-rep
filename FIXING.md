# FIXING.md — Core 1.15.114

Reviewer scope for this release: **M16 + L42 + L43 + L44 + L45 + L08 remainder** only.

## M16 — Client/site invariants and creator scope
- Creating a client now atomically creates a `Default Site`.
- A restricted creator is added to the new client's Tactical `can_view_clients` scope inside the same transaction.
- Moving the final remaining site out of a client is rejected; every client must retain at least one site.

## L42 — Bounded pagination
- `core.resources` rejects page numbers above 10000 and page sizes above 500.
- Session Security paged login-session and audit-history helpers reject page numbers above 10000; their existing 100-row page-size cap remains.

## L43 — Audit global trusted service contexts
- `trusted_service_context(..., global_access=True)` writes a strict Core/Tactical audit event before returning global authority.
- If that audit cannot be persisted, the global service context is denied.

## L44 — Preserve Tactical audit fields
- Client/site updates include Tactical `BaseAuditModel.modified_by` and `modified_time` in `update_fields`, allowing Tactical's own save/audit hooks to persist them.

## L45 — Stable Tactical validation errors
- Django `ValidationError` from Tactical Client/Site model validation is converted to `TacticalResourceValidationError`, then to the stable `ResourceValidationError`/HTTP 400 boundary.

## L08 remainder — Publish Clients/Sites paging contract
- `core.resources` is now contract version 1.2.0.
- Clients/Sites list query and response paging fields are explicitly published in contract metadata, Markdown export and text export.
- Behavioral regression verifies the published rows.

## Behavioral coverage
- `tests/resource-directory-foundation.py`
- `tests/resource-directory-write-hardening.py`
- `tests/resource-directory-site-move-postgres.py` (real Django/PostgreSQL HTTP regression)
- `tests/pagination-upper-bounds.py`
- `tests/resource-contract-paging.py`
- existing Session Security and contract foundation suites

## Explicitly out of scope
- M17 and later Mediums.
- M31 stale Resource Directory shell greps are intentionally not changed in this release.
- No UI changes.

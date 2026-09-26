# Tec-Tac Core 1.15.82

## History pagination hardening

- Added bounded `page/page_size` pagination to Module Management v2 lifecycle history.
- Added optional status, action and text filters to the Core module-history reader without changing lifecycle records.
- Preserved the legacy `list_jobs(limit=...)` Python contract and HTTP `limit=` compatibility path.
- Added paged session-security audit reads with total/page metadata and a new additive `page_audit_events(...)` public contract.
- Preserved the existing `list_audit_events(...)` provider contract for compatibility.
- Session audit queries now transfer only the requested page while obtaining total count from the database.
- Updated Core documentation and regression coverage for both paged history surfaces.

## Compatibility

No database migration or breaking public-contract change is required. Existing bounded-list and `limit=` consumers continue to work.

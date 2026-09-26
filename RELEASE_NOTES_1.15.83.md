# Tec-Tac Core 1.15.83

## Active Tactical login-session pagination

- Added bounded `page/page_size` pagination to `GET /api/tfd/access/sessions/`, with a maximum page size of 100.
- Added optional server-side `search` across Tactical usernames and Core-observed last IP addresses.
- Protected root/native-superuser/role-superuser accounts are excluded from non-superuser administrators before count and pagination, so page metadata never leaks protected-session counts.
- Active Knox token rows are serialized only for the requested page; Core no longer materializes up to 2,000 tokens before applying the administration boundary on the paged path.
- Preserved the no-query legacy response path for existing consumers.
- Added regression coverage for pagination, search, protected-account filtering and legacy compatibility.

## Compatibility

No database migration is required. Existing unpaged callers remain supported; the new UI opts into the additive paged contract.

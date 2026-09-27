# FIXING.md — Core 1.15.127

This is a blocking rebuild of 1.15.127 only. No unrelated review items are included.

## HIGH — browser audit writer reopened C8

1.15.127 incorrectly allowed authenticated browser callers to submit audit rows for permissionless extensions and legacy plugins. Because those modules have no permission surface, Core could not prove that module code rather than an arbitrary authenticated user originated the browser event.

### Fix

- `can_record_from_browser()` again rejects:
  - `core` provenance; and
  - any module whose resolved permission set is empty.
- Permission-bearing modules continue through the existing `_actor_can_use_module()` effective-grant check.
- Backend `record()` remains unchanged so trusted server-side module code can use the audit contract.
- Enabled permissionless modules exposed through the browser runtime emit a warning that browser audit POSTs will receive HTTP 403 until an explicit module permission is declared.
- `docs/module-audit.md` documents the 403 behavior and warning.

### Regression coverage

- `tests/audit-browser-provenance-hardening.py` uses the real `_actor_can_use_module` and real registry resolution with one permissionless extension and one legacy plugin.
- It verifies both `can_record_from_browser()` denials and HTTP 403 from the real `AuditRecordView.post()` path.
- `tests/audit-contract-foundation.py` again enforces the C8 permissionless-browser block.

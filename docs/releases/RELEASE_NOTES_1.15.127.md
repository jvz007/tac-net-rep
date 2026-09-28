# Tec-Tac Core 1.15.127

## Blocking fix — restore browser audit provenance boundary

This rebuild restores the C8 browser-audit security boundary that was weakened in 1.15.127.

- `POST /api/tfd/audit/record/` rejects Core provenance and modules with no declared permission surface.
- Permissionless extensions and legacy plugins therefore return HTTP 403 from the browser writer.
- Permission-bearing modules still require the authenticated actor to hold at least one effective module grant.
- Backend/server-side `record()` behavior is unchanged; trusted module code may still write audit events through the Core backend contract.
- When an enabled permissionless module is exposed through the browser runtime, Core logs a warning that browser audit writes for that module will be rejected with HTTP 403 and that an explicit permission must be declared before exposing a browser audit surface.
- The audit contract documentation now explicitly documents the 403 behavior.

## Regression coverage

- Added `tests/audit-browser-provenance-hardening.py`, which uses the real `tec_tac.audit._actor_can_use_module` and registry resolution with a permissionless extension plus a legacy plugin.
- The regression asserts `can_record_from_browser(non-superuser, module_id)` is false for both and exercises the real `AuditRecordView.post()` path to confirm HTTP 403.
- Existing audit contract tests were returned to the original C8 expectation that permissionless browser provenance is blocked.

No other functional changes are included in this rebuild.

# Tec-Tac Framework 1.10.1

Corrective release for Developer Contracts export.

## Fixed

- Renamed the export query parameter from DRF-reserved `format` to `export_format`.
- `GET /api/tfd/contracts/export/?export_format=md` now returns Markdown export.
- `GET /api/tfd/contracts/export/?export_format=txt` now returns plain-text export.
- Added regression checks preventing reuse of DRF's reserved `format` query parameter.
- Updated Markdown and HTML tutorials plus Developer Contracts documentation.

No capability, scheduler, RBAC, or module-lifecycle contract changed.

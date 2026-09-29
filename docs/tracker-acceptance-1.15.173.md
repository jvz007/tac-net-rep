# Tracker acceptance — Core 1.15.173 / UI 0.12.67

This release pair exists only to close the 13 tracker rows that were still open/partly accepted after the earlier feature releases. It does not introduce a new product workstream.

| Tracker row | Production boundary | Executable acceptance |
| --- | --- | --- |
| D2 | destructive restore orchestration accepts an older Core and verifies the resulting installed Core version | `tests/d2-d3-restore-orchestration-1.15.173.py` + UI `backup-restore-final-closure-0.12.65.mjs` |
| D3 | restore carries verified source identity/trust and restores the pre-operation service state | `tests/d2-d3-restore-orchestration-1.15.173.py` + UI restore confirmation workflow |
| L10 | local/FTP/rclone/SCP publish sidecar first and roll it back if final archive publication fails | `tests/l10-publication-final-1.15.173.py` |
| F1 | own-password HTTP view and My Account workflow | `tests/tracker-http-feature-boundary-1.15.172.py` + UI F1/F2 acceptance |
| F2 | own-TOTP reset HTTP view and re-enrol workflow | `tests/tracker-http-feature-boundary-1.15.172.py` + UI F1/F2 acceptance |
| F4 | Tactical UI preferences in Core account API/runtime context | `tests/tracker-feature-closure-1.15.169.py` + UI runtime-context acceptance |
| F5 | delete site + relocate agents | `tests/tracker-http-feature-boundary-1.15.172.py` + UI Resources acceptance |
| F6 | delete client + relocate agents | `tests/tracker-http-feature-boundary-1.15.172.py` + UI Resources acceptance |
| F7 | client/site custom-field values | `tests/tracker-http-feature-boundary-1.15.172.py` + UI Resources acceptance |
| F8 | public SSO provider hook | companion UI 0.12.67 tracker acceptance runner |
| F9 | authenticated module header contribution | companion UI 0.12.67 tracker acceptance runner |
| F10 | client/site context-menu module actions | companion UI 0.12.67 tracker acceptance runner |
| F11 | Core-owned OpenAPI grouping including route-prefix/module-ID mismatches | `tests/f11-openapi-ownership-1.15.172.py` |

`tests/tracker-acceptance-1.15.173.py` is the single Core acceptance entrypoint for the rows above.

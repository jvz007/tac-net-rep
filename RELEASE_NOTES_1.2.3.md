# Tec-Tac 1.2.3

Tec-Tac 1.2.3 hardens module lifecycle diagnostics and verification and makes the framework API easier to navigate in Swagger/OpenAPI.

## Module upload diagnostics

- Package inspection now tracks the active stage (`permission-check`, `multipart-parse`, `stage-upload`, `response`).
- Expected package errors remain HTTP 400 JSON responses.
- Unexpected package-inspection exceptions are logged with a traceback and returned as structured JSON containing `detail`, `stage`, `error_type`, and `error` instead of an unhelpful blank HTML 500 response.
- Tactical permission denials continue to use the normal DRF 403 path.

## Lifecycle verification

- Module jobs now expose a lifecycle `stage` and `error_type` in addition to status and log tail.
- Install lifecycle verifies every declared Django AppConfig is registered exactly once.
- The extension model registry is loaded before the install is accepted.
- Declared Django apps are checked for unapplied migrations after migration execution.
- After Tactical services restart, a fresh Django process repeats AppConfig/model/migration verification.
- UI synchronization is verified for extensions that declare `tec_tac_ui.json`; a successful sync must leave the extension module under the deployed Tec-Tac UI modules directory.

## Swagger / OpenAPI organization

- Framework endpoints are explicitly grouped under the `Tec-Tac Framework` Swagger tag.
- Extension authors should give each extension its own stable Swagger tag using `drf_spectacular` (normally the extension display name, for example `UserInvite`).
- `TFD Reporting` remains its own existing Swagger section.

## Compatibility

No Tactical tracked/upstream source files are modified. The `framwork` directory name remains intentionally unchanged for compatibility with existing Tec-Tac deployments.

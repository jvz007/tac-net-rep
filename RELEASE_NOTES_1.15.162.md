# Tec-Tac Core 1.15.162

## D2 / D3 native Backup & Restore closure

- Added effective-superuser HTTP endpoints for the native Backup & Restore UI.
- The browser can enumerate only server-registered backup destinations; arbitrary caller-supplied remote destinations are not accepted by this UI boundary.
- Backup inventory, restore validation and restore execution run as asynchronous privileged jobs with status polling.
- Restore validation returns the recovery source installation ID, server name, signer key/fingerprint and Core version transition already produced by the recovery helper.
- Destructive restore requires an explicit confirmation flag and can only be reached after the UI has performed a non-destructive validation.
- Added behavioral regressions for the HTTP authorization/confirmation boundary and the registered-destination Core dispatch path.

No existing public module capability operation is weakened by this release.

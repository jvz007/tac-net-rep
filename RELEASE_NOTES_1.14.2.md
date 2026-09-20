# Tec-Tac Framework 1.14.2

## Module lifecycle history

- Adds `GET /api/tfd/modules/v2/jobs/` for persistent Module Manager lifecycle history.
- History is backed by the existing authoritative job records under `/var/lib/tec-tac/module-manager/jobs/`.
- Install, upgrade, remove, enable/disable and visibility jobs now record the requesting Tactical username when invoked through the web API.
- Existing job records remain readable; no database migration is required.

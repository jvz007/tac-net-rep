# TFD Tactical Reporting Extension

Upgrade-safe Django extension framework for Tactical RMM Report Manager.

Current package version: **0.4.0**.

## v0.4.0 — ingestion hardening

This release keeps the v0.3.0 Tactical API-key + TFD RBAC endpoint and hardens the write path before connecting a real telemetry source.

### API endpoint

```text
GET  /api/tfd/reporting/network-availability/
POST /api/tfd/reporting/network-availability/
```

Authentication remains Tactical's native `X-API-KEY` mechanism.

Permissions remain:

```text
GET  -> tfdreporting.networkavailability.list
POST -> tfdreporting.networkavailability.manage
```

### New validation

POST now enforces:

- non-empty trimmed `client_name`, `site_name`, `device_name`, and `source`;
- `status` must be one of `up`, `degraded`, `down`, or `unknown`;
- availability and packet-loss percentages remain within 0..100;
- latency cannot be negative;
- timestamps more than 10 minutes in the future are rejected;
- older historical timestamps remain allowed for backfill/import use.

### Provenance

Each new row now records:

- `ingested_by` — the authenticated Tactical username, set server-side;
- `received_at` — server-side receipt timestamp.

The caller cannot override either field.

### Idempotency / duplicate handling

POST accepts an optional `idempotency_key` of up to 128 characters.

The pair:

```text
source + idempotency_key
```

is unique when a key is supplied.

Behaviour:

- first request -> `201 Created`;
- exact replay with the same source/key/payload -> `200 OK` with `X-TFD-Idempotent-Replay: true`;
- same source/key with different data -> `409 Conflict` and `code=idempotency_conflict`;
- requests without an idempotency key keep normal append-only behaviour.

This allows a telemetry sender to retry safely after timeouts without creating duplicate report rows.

## Security POC already proven

The v0.3.0 POC demonstrated:

- Tactical native API-key authentication;
- a Tactical role with no unrelated native permissions;
- TFD `manage=True`, `list=False`;
- POST returned `201` and persisted a row;
- GET returned `403`;
- an unrelated Tactical endpoint returned `403`.

## Upgrade-safe integration

No Tactical tracked source files are modified.

The extension uses:

- `/rmm/.git/info/exclude` to protect `/rmm/api/tacticalrmm/tfdreporting/`;
- Tactical's ignored `tacticalrmm/local_settings.py` to load the TFD app and register the TFD URL route;
- Django migrations for TFD-owned database objects.

Tactical's Report Manager model registry is extended in memory by `TfdreportingConfig.ready()`.

## Install / upgrade

On the Tactical server:

```bash
cd /opt/tfd-tactical-reporting
git fetch origin
git reset --hard origin/main
sudo bash install.sh
```

`sudo bash install.sh` is currently used while the repository executable-bit housekeeping is being handled separately.

Expected migration on upgrade from v0.3.0:

```text
Applying tfdreporting.0003_networkavailability_ingest_hardening... OK
```

The installer verifies the model, RBAC registry, Report Manager resolution, API route, existing row count, and new ingest-hardening fields before restarting Tactical services.

## Example POST

```json
{
  "client_name": "TFD Test Client",
  "site_name": "Head Office",
  "device_name": "Internet",
  "source": "poc-api",
  "timestamp": "2026-09-17T14:20:00Z",
  "status": "up",
  "availability_pct": 99.980,
  "latency_ms": 8.400,
  "packet_loss_pct": 0.100,
  "idempotency_key": "poc-20260917-142000-internet"
}
```

## RBAC console management

```bash
cd /rmm/api/tacticalrmm
source /rmm/api/env/bin/activate
python manage.py shell
```

```python
from accounts.models import Role
from tfdreporting.rbac import (
    PERMISSION_NETWORK_AVAILABILITY_LIST,
    PERMISSION_NETWORK_AVAILABILITY_MANAGE,
    get_role_permissions,
    grant_extension_permission,
    revoke_extension_permission,
)

role = Role.objects.get(name="TFD Reporting Ingest POC")
grant_extension_permission(role, PERMISSION_NETWORK_AVAILABILITY_MANAGE)
revoke_extension_permission(role, PERMISSION_NETWORK_AVAILABILITY_LIST)
get_role_permissions(role)
```

## Uninstall

Preserve database data:

```bash
sudo bash uninstall.sh
```

Purge TFD database objects as well:

```bash
sudo bash uninstall.sh --purge-data
```

`--purge-data` is destructive.

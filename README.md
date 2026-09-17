# TFD Tactical Reporting Extension

Upgrade-safe Django extension framework for Tactical RMM Report Manager.

Current package version: **0.3.0**.

## Version 0.3.0 - authenticated API + RBAC POC

This release adds the first real TFD API endpoint and connects it to Tactical's native API-key authentication plus the TFD extension RBAC layer proven in 0.2.x.

Endpoint:

```text
GET  /api/tfd/reporting/network-availability/
POST /api/tfd/reporting/network-availability/
```

Authentication is explicitly Tactical's existing `tacticalrmm.auth.APIAuthentication`, which expects the API key in the `X-API-KEY` request header.

Authorization is separate from Tactical's native `can_*` role permissions:

```text
GET/HEAD/OPTIONS -> tfdreporting.networkavailability.list
POST             -> tfdreporting.networkavailability.manage
```

Any other method is denied.

The route is registered in memory by `TfdreportingConfig.ready()` and does not edit Tactical's tracked `tacticalrmm/urls.py`.

Swagger/OpenAPI should discover the endpoint under the **TFD Reporting** tag when Tactical Swagger is enabled.

## Existing upgrade-safe architecture

The installer adds the `tfdreporting` Django app without modifying Tactical tracked source files.

Persistence points:

- `/rmm/.git/info/exclude` protects `/rmm/api/tacticalrmm/tfdreporting/` from Tactical `git clean -df` updates.
- `tacticalrmm/local_settings.py` is already ignored by Tactical and contains one marked app-registry loader block.
- `TfdreportingConfig.ready()` patches Tactical Report Manager's model allow-list in memory and registers the TFD API route in memory.

The 0.2.1 loader protections remain in place: malformed markers or a legacy unmarked `_tfd_populate` hook cause the installer to fail safely instead of stacking loaders.

## Repository layout

```text
.
├── install.sh
├── uninstall.sh
├── VERSION
└── tfdreporting/
    ├── __init__.py
    ├── apps.py
    ├── models.py
    ├── permissions.py
    ├── rbac.py
    ├── serializers.py
    ├── urls.py
    ├── views.py
    └── migrations/
        ├── __init__.py
        ├── 0001_initial.py
        └── 0002_extensionrolepermission.py
```

There is no new database migration in 0.3.0.

## Install / upgrade

On the Tactical server:

```bash
cd /opt/tfd-tactical-reporting
git pull
sudo ./install.sh
```

If the repository executable-bit issue has not yet been fixed, `sudo bash install.sh` is functionally equivalent for this POC. The repository should ultimately store `install.sh` and `uninstall.sh` as mode `100755`.

Expected installer verification includes:

```text
TFD verification OK: ... endpoint= api/tfd/reporting/network-availability/ network_rows= <existing count>
```

No migration should be required when upgrading from 0.2.1:

```text
No migrations to apply.
```

## RBAC POC role

The dev POC created Tactical role ID `17` named:

```text
TFD Reporting Ingest POC
```

The intended state is:

```text
tfdreporting.networkavailability.list   = False
tfdreporting.networkavailability.manage = True
```

Verify it from Django shell:

```bash
cd /rmm/api/tacticalrmm
source /rmm/api/env/bin/activate
python manage.py shell
```

```python
from accounts.models import Role
from tfdreporting.rbac import get_role_permissions

role = Role.objects.get(id=17)
print(get_role_permissions(role))
```

## API request body

Example POST payload:

```json
{
  "client_name": "TFD Test Client",
  "site_name": "Head Office",
  "device_name": "Internet",
  "source": "poc",
  "timestamp": "2026-09-17T14:00:00Z",
  "status": "up",
  "availability_pct": 99.980,
  "latency_ms": 8.400,
  "packet_loss_pct": 0.100
}
```

Validation in 0.3.0:

- availability percentage: `0..100` when supplied;
- packet-loss percentage: `0..100` when supplied;
- latency: `>= 0` when supplied;
- `id` is read-only.

## Security acceptance test

Create or use a Tactical API user assigned to role 17 and create a Tactical API key for that user.

Then test the following matrix with the same key:

```text
POST /api/tfd/reporting/network-availability/ -> expected 201
GET  /api/tfd/reporting/network-availability/ -> expected 403
GET  /clients/sites/                          -> expected 403
script execution endpoint                     -> expected 403
request without X-API-KEY                     -> expected authentication failure
```

Example POST:

```bash
curl -i \
  -X POST \
  -H 'X-API-KEY: REPLACE_WITH_TEST_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name":"TFD Test Client",
    "site_name":"Head Office",
    "device_name":"Internet",
    "source":"poc",
    "timestamp":"2026-09-17T14:00:00Z",
    "status":"up",
    "availability_pct":99.980,
    "latency_ms":8.400,
    "packet_loss_pct":0.100
  }' \
  https://YOUR-TACTICAL-HOST/api/tfd/reporting/network-availability/
```

A successful POST proves the full chain:

```text
Tactical API key
    -> Tactical user
    -> Tactical role
    -> TFD ExtensionRolePermission
    -> NetworkAvailabilityPermission
    -> serializer validation
    -> Django ORM insert
```

## Swagger

With `SWAGGER_ENABLED = True`, open Tactical's existing Swagger UI and look for the **TFD Reporting** tag.

The endpoint should expose both GET and POST operations. Swagger authentication uses Tactical's existing API authentication schema; no second TFD token system is introduced.

## Current models

### NetworkAvailability

- client name
- site name
- device name
- source
- timestamp
- status
- availability percentage
- latency milliseconds
- packet-loss percentage

### ExtensionRolePermission

- Tactical `role_id`
- registered TFD permission `codename`
- `granted` state
- created/updated timestamps

`role_id` remains an integer rather than a ForeignKey so TFD migrations remain independent of Tactical's accounts migration graph.

## Uninstall

Preserve database data:

```bash
sudo ./uninstall.sh
```

Remove migration/database objects too:

```bash
sudo ./uninstall.sh --purge-data
```

`--purge-data` is destructive.

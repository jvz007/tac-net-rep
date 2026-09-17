# TFD Tactical Reporting Extension

Upgrade-safe Django extension framework for Tactical RMM Report Manager.

Current package version: **0.2.1**.

## What this does

The installer adds the `tfdreporting` Django app without modifying Tactical's tracked source files. It relies on two persistence points that were validated against real `update.sh --force` runs on Tactical RMM 1.5.2:

- `/rmm/.git/info/exclude` protects the custom app directory from Tactical's `git clean -df` update step.
- `tacticalrmm/local_settings.py` is already ignored by Tactical and is used to install a small Django app-registry hook.

The app's `AppConfig.ready()` extends Tactical Report Manager's in-memory model registry, so `ee/reporting/constants.py` remains untouched.


## Version 0.2.1 installer hardening

This version keeps the 0.2.0 RBAC POC unchanged and hardens the upgrade path discovered during the manual-to-repository migration test.

Changes:

- validates that the managed TFD loader markers are either absent or present as exactly one matching pair;
- detects the legacy unmarked `_tfd_populate` / `Apps.populate = _tfd_populate` POC hook and fails safely instead of stacking another loader;
- verifies that exactly one managed loader block exists after writing `local_settings.py`;
- restores the pre-install `local_settings.py` backup if post-write marker verification fails;
- verifies that `NetworkAvailability` remains queryable and reports its row count during installer verification;
- repository shell scripts are shipped with normal executable/readable mode (`0755`).

## Version 0.2.0 security POC

This version adds a TFD extension RBAC layer without modifying Tactical's `accounts.Role` model or frontend.

It provides two registered permissions:

```text
tfdreporting.networkavailability.list
tfdreporting.networkavailability.manage
```

Permissions are attached to an existing Tactical Role ID through the TFD-owned `ExtensionRolePermission` model.

Authentication remains Tactical's responsibility. The RBAC helper is intended to be used by future TFD API endpoints after Tactical has authenticated the request and populated `request.user`.

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
    ├── rbac.py
    └── migrations/
        ├── __init__.py
        ├── 0001_initial.py
        └── 0002_extensionrolepermission.py
```

## Install / upgrade

Clone or update the repository on the Tactical server and run:

```bash
sudo ./install.sh
```

Running `install.sh` again updates the app code and loader idempotently. Existing Django data is preserved; migrations apply only the schema changes required by the newer extension version.

The installer:

1. verifies the Tactical paths and Report Manager;
2. detects the Tactical service user from `rmm.service`;
3. protects `/rmm/api/tacticalrmm/tfdreporting/` in `.git/info/exclude`;
4. backs up `local_settings.py`;
5. validates existing TFD loader state and refuses unsafe legacy/malformed hooks;
6. installs/updates exactly one managed TFD loader block;
7. installs the Django app;
8. runs `manage.py check`;
9. runs the app migrations;
10. verifies the reporting model, RBAC model, registered TFD permissions, Tactical Report Manager resolution, and current `NetworkAvailability` row count;
11. restarts and validates `rmm`, `daphne`, `celery`, and `celerybeat`.

Backups of `local_settings.py` are kept under `/opt/tfd-tactical/backups/`, outside Tactical's Git checkout.

## Security POC management from Django shell

Open the Tactical Django shell:

```bash
cd /rmm/api/tacticalrmm
source /rmm/api/env/bin/activate
python manage.py shell
```

List Tactical roles:

```python
from accounts.models import Role
list(Role.objects.values("id", "name"))
```

Import the TFD RBAC helpers:

```python
from tfdreporting.rbac import (
    PERMISSION_NETWORK_AVAILABILITY_LIST,
    PERMISSION_NETWORK_AVAILABILITY_MANAGE,
    get_role_permissions,
    grant_extension_permission,
    revoke_extension_permission,
)
```

Choose an existing Tactical role:

```python
role = Role.objects.get(name="TFD Reporting Ingest")
```

Grant write/ingest permission:

```python
grant_extension_permission(
    role,
    PERMISSION_NETWORK_AVAILABILITY_MANAGE,
)
```

Leave read permission denied, or explicitly revoke it:

```python
revoke_extension_permission(
    role,
    PERMISSION_NETWORK_AVAILABILITY_LIST,
)
```

Show the role's current TFD permissions:

```python
get_role_permissions(role)
```

Expected example:

```python
{
    "tfdreporting.networkavailability.list": False,
    "tfdreporting.networkavailability.manage": True,
}
```

Unknown permission codenames are rejected by the helper instead of being silently created.

## Current database models

### NetworkAvailability

Proof-of-concept reporting data:

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

TFD-owned extension authorization data:

- Tactical `role_id`
- registered TFD permission `codename`
- `granted` state
- created/updated timestamps

`role_id` is intentionally not a Django ForeignKey. This keeps TFD migrations independent of Tactical's accounts migration graph. Runtime helper functions still require a valid Tactical `Role` object when permissions are managed.

## Uninstall

Preserve the database table/data:

```bash
sudo ./uninstall.sh
```

Remove the Django migration/database objects as well:

```bash
sudo ./uninstall.sh --purge-data
```

`--purge-data` is destructive.

## Tactical upgrade behaviour

Tactical's update process can reset tracked source files, clean untracked files, and rebuild `/rmm/api/env`. The extension does not rely on edits to Tactical tracked files, packages installed only into the venv, or systemd overrides.

The integration points are intentionally limited to:

- `/rmm/.git/info/exclude`
- `/rmm/api/tacticalrmm/tacticalrmm/local_settings.py`
- `/rmm/api/tacticalrmm/tfdreporting/`
- Django/PostgreSQL migrations for the TFD app

# Tec-Tac Extension & ReportSet Tutorial

**Framework baseline:** Tec-Tac 1.8.0  
**Purpose:** Create, package, deploy, upgrade, and validate your own Tec-Tac extension and matching ReportSet.

This tutorial uses `networkprobe` as the example extension ID.

---

# 1. Understand the Tec-Tac plugin model

Every production extension is a matched pair:

```text
extensions/<extension-id>/
reportsets/<extension-id>/
```

The two directory names must be identical.

For this tutorial:

```text
extensions/networkprobe/
reportsets/networkprobe/
```

The extension contains operational functionality and owns its source data. The ReportSet contains reporting mappings, enrichment, derived values, aggregation, and other report-facing logic.

```text
Extension
    |
    | collects / owns / manages
    v
Operational data
    |
    | mapped / enriched / aggregated by
    v
ReportSet
    |
    v
Reports / dashboards / exports
```

---

# 2. Plan the extension

Before creating files, define:

```text
Extension ID:
networkprobe

Extension responsibility:
Receive and manage network-device observations.

Extension-owned data:
Device identity
Device state
Raw check results
Measurements
Timestamps

ReportSet responsibility:
Expose availability, latency, packet loss and device-health information for reporting.
```

Use the **extension's name** as the ID. Do not name the pair after the type of report it happens to produce.

---

# 3. Scaffold the pair

**Run from:** the Tec-Tac repository root.

```bash
cd /opt/tec-tac
sudo bash scripts/scaffold-plugin.sh networkprobe 0.1.0
```

This creates:

```text
extensions/networkprobe/
├── README.md
└── tec_tac.json

reportsets/networkprobe/
├── README.md
└── tec_tac.json
```

The scaffold script currently creates the manifests and README files only. You add the actual Python/Django packages next.

---

# 4. Extension manifest

**File:** `extensions/networkprobe/tec_tac.json`

```json
{
  "id": "networkprobe",
  "type": "extension",
  "version": "0.1.0",
  "python_paths": ["."],
  "django_apps": []
}
```

At this stage there is no Django app yet, so `django_apps` is empty.

Important manifest rules:

```text
id             must match the directory name
type           must be extension or reportset as appropriate
version        must not be blank
python_paths   must remain inside the plugin directory and must exist
django_apps    must contain valid, unique Django AppConfig class paths
```

---

# 5. ReportSet manifest

**File:** `reportsets/networkprobe/tec_tac.json`

```json
{
  "id": "networkprobe",
  "type": "reportset",
  "version": "0.1.0",
  "python_paths": ["."],
  "django_apps": []
}
```

The ReportSet ID is `networkprobe`, exactly matching the extension ID.

---

# 6. Create the extension Python package

**Run from:** `/opt/tec-tac`

```bash
mkdir -p extensions/networkprobe/tec_tac_networkprobe/migrations

touch extensions/networkprobe/tec_tac_networkprobe/__init__.py
touch extensions/networkprobe/tec_tac_networkprobe/migrations/__init__.py
```

Your extension now has this structure:

```text
extensions/networkprobe/
├── README.md
├── tec_tac.json
└── tec_tac_networkprobe/
    ├── __init__.py
    └── migrations/
        └── __init__.py
```

---

# 7. Add the extension AppConfig

**File:** `extensions/networkprobe/tec_tac_networkprobe/apps.py`

```python
from django.apps import AppConfig


class TecTacNetworkProbeConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "tec_tac_networkprobe"
    label = "tec_tac_networkprobe"
    verbose_name = "Tec-Tac Network Probe"
```

The Django `label` must not collide with Tactical or another Tec-Tac Django application.

---

# 8. Register the extension Django app

**File:** `extensions/networkprobe/tec_tac.json`

Replace the original manifest with:

```json
{
  "id": "networkprobe",
  "type": "extension",
  "version": "0.1.0",
  "python_paths": ["."],
  "django_apps": [
    "tec_tac_networkprobe.apps.TecTacNetworkProbeConfig"
  ],
  "permission_groups": {
    "read": ["networkprobe.device.list"],
    "manage": ["networkprobe.device.list", "networkprobe.device.manage", "networkprobe.ingest.manage"]
  }
}
```

Tec-Tac will make the declared Python path importable and add the AppConfig to the primary Django application registry.

Do **not** edit Tactical tracked source files to register the app.

---

# 9. Create an extension-owned model

**File:** `extensions/networkprobe/tec_tac_networkprobe/models.py`

Example:

```python
from django.db import models


class NetworkDevice(models.Model):
    device_uid = models.CharField(max_length=128, unique=True)
    name = models.CharField(max_length=255)
    address = models.GenericIPAddressField()
    device_type = models.CharField(max_length=64, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name
```

This belongs on the extension side because the extension owns the operational device record.

Do not blindly copy this model for every plugin. Design models around the actual extension.

---

# 10. Create the ReportSet Python package

**Run from:** `/opt/tec-tac`

```bash
mkdir -p reportsets/networkprobe/tec_tac_networkprobe_reportset/migrations

touch reportsets/networkprobe/tec_tac_networkprobe_reportset/__init__.py
touch reportsets/networkprobe/tec_tac_networkprobe_reportset/migrations/__init__.py
```

Result:

```text
reportsets/networkprobe/
├── README.md
├── tec_tac.json
└── tec_tac_networkprobe_reportset/
    ├── __init__.py
    └── migrations/
        └── __init__.py
```

---

# 11. Add the ReportSet AppConfig

**File:** `reportsets/networkprobe/tec_tac_networkprobe_reportset/apps.py`

```python
from django.apps import AppConfig


class TecTacNetworkProbeReportsetConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "tec_tac_networkprobe_reportset"
    label = "tec_tac_networkprobe_reportset"
    verbose_name = "Tec-Tac Network Probe ReportSet"
```

---

# 12. Register the ReportSet Django app

**File:** `reportsets/networkprobe/tec_tac.json`

Replace the original manifest with:

```json
{
  "id": "networkprobe",
  "type": "reportset",
  "version": "0.1.0",
  "python_paths": ["."],
  "django_apps": [
    "tec_tac_networkprobe_reportset.apps.TecTacNetworkProbeReportsetConfig"
  ]
}
```

---

# 13. Add ReportSet mappings

A ReportSet should expose the reporting interpretation of extension-owned data.

Good ReportSet responsibilities include:

```text
friendly field labels
relationships
device-type enrichment
vendor enrichment
availability calculations
latency summaries
packet-loss summaries
derived health states
hour/day/week/month consolidation
report-facing models
```

For simple Python mapping/enrichment logic:

**File:** `reportsets/networkprobe/tec_tac_networkprobe_reportset/mappings.py`

```python
def map_device(device):
    return {
        "device_uid": device.device_uid,
        "device_name": device.name,
        "device_type": device.device_type or "unknown",
        "address": device.address,
        "last_seen": device.last_seen,
    }
```

For derived logic:

**File:** `reportsets/networkprobe/tec_tac_networkprobe_reportset/enrichment.py`

```python
def availability_status(availability_pct):
    if availability_pct is None:
        return "unknown"
    if availability_pct >= 99.0:
        return "healthy"
    if availability_pct >= 95.0:
        return "degraded"
    return "unhealthy"
```

These are examples of where mapping and enrichment logic belongs. The exact reporting contract depends on the extension.

---

# 14. Add an API only when the extension needs one

Operational ingest and management APIs normally belong on the **extension** side.

Typical files are:

```text
extensions/networkprobe/tec_tac_networkprobe/
├── serializers.py
├── views.py
├── urls.py
├── permissions.py
└── rbac.py
```

If you create a serializer:

**File:** `extensions/networkprobe/tec_tac_networkprobe/serializers.py`

```python
from rest_framework import serializers
from .models import NetworkDevice


class NetworkDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkDevice
        fields = (
            "id",
            "device_uid",
            "name",
            "address",
            "device_type",
            "last_seen",
        )
```

If you create an API view:

**File:** `extensions/networkprobe/tec_tac_networkprobe/views.py`

```python
from rest_framework.generics import ListCreateAPIView

from .models import NetworkDevice
from .serializers import NetworkDeviceSerializer


class NetworkDeviceListCreateView(ListCreateAPIView):
    queryset = NetworkDevice.objects.all()
    serializer_class = NetworkDeviceSerializer
```

If you create URL definitions:

**File:** `extensions/networkprobe/tec_tac_networkprobe/urls.py`

```python
from django.urls import path
from .views import NetworkDeviceListCreateView


urlpatterns = [
    path(
        "devices/",
        NetworkDeviceListCreateView.as_view(),
        name="networkprobe-devices",
    ),
]
```

Creating `urls.py` does not by itself make a route public. The extension still needs a supported Tec-Tac/Tactical URL registration mechanism. Do not edit Tactical tracked URL files simply to make the route available.

When building an ingest API, design these from the start:

```text
authentication
authorization
input validation
idempotency
replay behaviour
timestamp validation
duplicate handling
server-side audit fields
HTTP status codes
```

---

# 15. Permissions

Use explicit permission codenames owned by the extension.

Example:

```text
tec_tac_networkprobe.device.list
tec_tac_networkprobe.device.manage
tec_tac_networkprobe.ingest.manage
```

Keep permissions least-privilege.

Tec-Tac's current proven custom permission pattern is role-based. A grant to a Tactical role affects every Tactical user assigned to that role.

Do not silently grant new extension permissions during installation.

---

# 16. Validate the plugin registry

**Run from:** `/opt/tec-tac`

```bash
sudo bash scripts/plugin-info.sh
```

You should eventually see both:

```text
extension : networkprobe
reportset : networkprobe
```

Inspect the pair directly:

```bash
sudo bash scripts/plugin-info.sh networkprobe extension
sudo bash scripts/plugin-info.sh networkprobe reportset
```

Run framework registry validation:

```bash
sudo bash tests/registry-validation.sh
```

Do not continue until registry validation passes.

---

# 17. Run the Django system check

**Run from:** `/rmm/api/tacticalrmm`

```bash
cd /rmm/api/tacticalrmm
sudo -u tactical /rmm/api/env/bin/python manage.py check
```

Expected result:

```text
System check identified no issues
```

---

# 18. Create extension migrations

After adding or changing extension models:

**Generated files will be written under:**  
`extensions/networkprobe/tec_tac_networkprobe/migrations/`

**Run from:** `/rmm/api/tacticalrmm`

```bash
sudo -u tactical /rmm/api/env/bin/python manage.py makemigrations tec_tac_networkprobe
```

Review every generated migration before committing it.

Example generated filename:

```text
extensions/networkprobe/tec_tac_networkprobe/migrations/0001_initial.py
```

Do not edit an already-deployed migration to represent a later schema change. Create a new migration.

---

# 19. Create ReportSet migrations when needed

Only do this if the ReportSet has database models.

**Generated files will be written under:**  
`reportsets/networkprobe/tec_tac_networkprobe_reportset/migrations/`

**Run from:** `/rmm/api/tacticalrmm`

```bash
sudo -u tactical /rmm/api/env/bin/python manage.py makemigrations tec_tac_networkprobe_reportset
```

---

# 20. Apply migrations during development

**Run from:** `/rmm/api/tacticalrmm`

Extension:

```bash
sudo -u tactical /rmm/api/env/bin/python manage.py migrate tec_tac_networkprobe
```

ReportSet, if it has migrations:

```bash
sudo -u tactical /rmm/api/env/bin/python manage.py migrate tec_tac_networkprobe_reportset
```

Then:

```bash
sudo -u tactical /rmm/api/env/bin/python manage.py check
```

---

# 21. Add extension tests

Recommended test location:

```text
tests/networkprobe/
```

Suggested files:

```text
tests/networkprobe/
├── server.sh
├── api.sh
└── reportset.sh
```

For server/model validation:

**File:** `tests/networkprobe/server.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

cd /rmm/api/tacticalrmm

sudo -u tactical /rmm/api/env/bin/python manage.py check
sudo -u tactical /rmm/api/env/bin/python manage.py shell -c "
from django.apps import apps
assert apps.get_model('tec_tac_networkprobe', 'NetworkDevice')
print('[TEST] PASS networkprobe server')
"
```

For an ingest API, tests should normally cover:

```text
valid create
exact replay
conflicting replay
bad status/enum
invalid numeric ranges
future timestamp
authentication failure
authorization failure
```

For historical reporting, test the intended aggregation levels:

```text
hour
day
week
month
```

---

# 22. Update the extension READMEs

**File:** `extensions/networkprobe/README.md`

Document at least:

```text
purpose
version
owned models
API endpoints
permissions
configuration
migration requirements
dependencies
deployment notes
```

**File:** `reportsets/networkprobe/README.md`

Document at least:

```text
source extension
datasets exposed
field mappings
relationships
enrichment
aggregation
report-facing models
historical behaviour
```

---

# 23. Package the extension for deployment

A Tec-Tac extension package must contain exactly one matching pair.

Preferred archive layout:

```text
networkprobe-0.1.0/
├── extensions/
│   └── networkprobe/
│       ├── tec_tac.json
│       ├── README.md
│       └── tec_tac_networkprobe/
│           └── ...
└── reportsets/
    └── networkprobe/
        ├── tec_tac.json
        ├── README.md
        └── tec_tac_networkprobe_reportset/
            └── ...
```

A wrapper directory such as `networkprobe-0.1.0/` is optional.

Do **not** package:

```text
__pycache__/
*.pyc
API keys
passwords
environment-specific secrets
temporary output
.git/
```

---

# 24. Build a `.tar.gz` package

**Run from:** the Tec-Tac repository root.

```bash
cd /opt/tec-tac

mkdir -p /tmp/networkprobe-0.1.0/extensions
mkdir -p /tmp/networkprobe-0.1.0/reportsets

cp -a extensions/networkprobe /tmp/networkprobe-0.1.0/extensions/
cp -a reportsets/networkprobe /tmp/networkprobe-0.1.0/reportsets/

cd /tmp
tar -czf networkprobe-0.1.0.tar.gz networkprobe-0.1.0
```

Result:

```text
/tmp/networkprobe-0.1.0.tar.gz
```

---

# 25. Build a `.zip` package

**Run from:** `/tmp` after creating the package directory above.

```bash
cd /tmp
zip -r networkprobe-0.1.0.zip networkprobe-0.1.0
```

Result:

```text
/tmp/networkprobe-0.1.0.zip
```

---

# 26. Install the extension package

Tec-Tac should keep the generic package installer at:

**File:** `scripts/install-extension.sh`

The installer accepts:

```text
.zip
.tar.gz
.tgz
```

Install a new extension:

```bash
cd /opt/tec-tac
sudo bash scripts/install-extension.sh /tmp/networkprobe-0.1.0.zip
```

or:

```bash
sudo bash scripts/install-extension.sh /tmp/networkprobe-0.1.0.tar.gz
```

The installer:

```text
1. safely extracts the archive into a temporary directory
2. rejects absolute paths, path traversal and archive links
3. requires exactly one extension manifest and one ReportSet manifest
4. confirms both IDs match
5. validates the pair with the Tec-Tac registry
6. refuses to overwrite an installed plugin by default
7. copies both components into the Tec-Tac repository
8. validates the complete live registry
9. runs Django system checks
10. applies conventional migrations belonging to the package's declared Django apps
11. runs Django checks again
12. restarts Tactical services
13. verifies the services returned to active state
```

---

# 27. Upgrade an installed extension package

Build the new package with the updated version in both manifests.

Example:

**File:** `extensions/networkprobe/tec_tac.json`

```json
{
  "id": "networkprobe",
  "type": "extension",
  "version": "0.2.0",
  "python_paths": ["."],
  "django_apps": [
    "tec_tac_networkprobe.apps.TecTacNetworkProbeConfig"
  ]
}
```

**File:** `reportsets/networkprobe/tec_tac.json`

```json
{
  "id": "networkprobe",
  "type": "reportset",
  "version": "0.2.0",
  "python_paths": ["."],
  "django_apps": [
    "tec_tac_networkprobe_reportset.apps.TecTacNetworkProbeReportsetConfig"
  ]
}
```

Install the upgrade:

```bash
sudo bash scripts/install-extension.sh /tmp/networkprobe-0.2.0.tar.gz --replace
```

When `--replace` is used, the installer first backs up the currently installed extension and ReportSet under:

```text
/var/lib/tec-tac/backups/plugins/<extension-id>/<timestamp>/
```

If validation, Django checks or migrations fail, the installer restores the previous plugin files.

Database migrations that completed before a later failure are not automatically reversed. Schema changes therefore still need normal migration discipline and testing.

---

# 28. Verify the deployed extension

Framework checks:

```bash
cd /opt/tec-tac

sudo bash scripts/framework-foundation.sh
sudo bash tests/registry-validation.sh
sudo bash tests/tactical-update-survival.sh
```

Inspect the installed pair:

```bash
sudo bash scripts/plugin-info.sh networkprobe extension
sudo bash scripts/plugin-info.sh networkprobe reportset
```

Run the extension's tests:

```bash
sudo bash tests/networkprobe/server.sh
sudo -E bash tests/networkprobe/api.sh
sudo bash tests/networkprobe/reportset.sh
```

Verify Tactical services:

```bash
systemctl is-active rmm
systemctl is-active daphne
systemctl is-active celery
systemctl is-active celerybeat
```

Expected:

```text
active
active
active
active
```

---

# 29. Git-based deployment is still supported

If the extension is developed directly inside the main Tec-Tac repository, you can still deploy through Git:

```bash
cd /opt/tec-tac
git pull
sudo bash install.sh
```

The package installer is useful when:

```text
the extension is distributed separately
the extension has its own release archive
you do not want to merge extension source into the main framework branch first
you want a controlled extension upgrade/replace operation
```

Be aware that installing an extension package directly into a Git checkout creates files that are not automatically part of Git history. Decide whether the deployed plugin should later be committed, ignored, or managed as a separately deployed artifact.

---

# 30. Versioning

Framework and extensions are separate concerns.

Example:

```text
Tec-Tac framework:       1.0.0
networkprobe extension:  0.3.0
networkprobe ReportSet:  0.3.0
```

When the extension and ReportSet are released as one package, keep their versions aligned.

---

# 31. Removing an extension

Treat removal as a controlled migration.

Do not simply delete:

```text
extensions/networkprobe/
reportsets/networkprobe/
```

if the extension has database tables or live consumers.

Recommended sequence:

```text
1. stop new writes
2. disable/remove consumers
3. preserve/export required data
4. remove or migrate database objects explicitly
5. remove permission registrations
6. remove extension and ReportSet code
7. validate the registry
8. run Django checks
9. restart Tactical services
```

Data preservation should be the default unless a purge is explicitly intended.

---

# 36. Final development checklist

Before coding:

```text
[ ] extension ID chosen
[ ] operational ownership defined
[ ] data ownership defined
[ ] ReportSet responsibility defined
```

Before packaging:

```text
[ ] extension and ReportSet IDs match
[ ] both manifest versions are correct
[ ] Django app labels are unique
[ ] migrations are included and reviewed
[ ] permissions follow least privilege
[ ] tests pass
[ ] READMEs are updated
[ ] no secrets are present
[ ] no Python cache files are present
```

After deployment:

```text
[ ] package installer completed successfully
[ ] framework foundation passes
[ ] registry validation passes
[ ] Tactical update-safety passes
[ ] extension tests pass
[ ] ReportSet tests pass
[ ] all Tactical services are active
[ ] existing production data is intact
```

---

# 37. Reference implementations in Tec-Tac 1.0.0

Use:

```text
extensions/example/
reportsets/example/
```

to understand the basic paired-plugin contract.

Use the existing legacy reporting POC when studying proven patterns for:

```text
Django models
migrations
API validation
idempotency
role-based permissions
Tactical Report Manager integration
```

The `example` pair is a reference implementation only. It is not a production extension.

---

# 38. Recommended end-to-end workflow

```text
Design
  ↓
Scaffold extension + ReportSet
  ↓
Create Python/Django packages
  ↓
Create models
  ↓
Create mappings/enrichment
  ↓
Create permissions/API if needed
  ↓
Validate registry
  ↓
Run Django check
  ↓
Create and review migrations
  ↓
Build tests
  ↓
Update READMEs
  ↓
Build ZIP or TAR.GZ
  ↓
Install with scripts/install-extension.sh
  ↓
Run framework tests
  ↓
Run extension tests
  ↓
Verify Tactical services
  ↓
Release
```

The design goal is simple: new functionality should consume the Tec-Tac foundation rather than modifying Tactical RMM tracked source files.


---

# 32. Remove an installed extension

Tec-Tac should keep the generic remover at:

**File:** `scripts/remove-extension.sh`

The remover expects the same paired convention:

```text
extensions/<extension-id>/
reportsets/<extension-id>/
```

Remove the plugin code while preserving its database objects:

```bash
cd /opt/tec-tac
sudo bash scripts/remove-extension.sh networkprobe
```

This is the safer default.

The remover will:

```text
1. verify the extension and ReportSet exist
2. verify both are registered
3. show their current versions
4. warn if the reference "example" plugin is being removed
5. create a backup of both plugin directories
6. preserve database objects by default
7. remove both plugin directories
8. validate the remaining registry
9. run Django system checks
10. restart Tactical services
11. verify the services returned to active state
```

Backups are stored under:

```text
/var/lib/tec-tac/backups/plugins/<extension-id>/removed-<timestamp>/
```

---

# 33. Remove an extension and purge its database objects

Use `--purge-data` only when you explicitly intend to remove the plugin-owned database schema/data.

```bash
sudo bash scripts/remove-extension.sh networkprobe --purge-data
```

With `--purge-data`, the remover attempts to reverse conventional Django migrations for the ReportSet and extension before deleting the code.

It reverses the declared Django apps in reverse order so the ReportSet is processed before the extension.

This can permanently remove plugin-owned tables and data.

For unattended/automation use:

```bash
sudo bash scripts/remove-extension.sh networkprobe --purge-data --yes
```

Do not use `--yes` casually. It skips the confirmation prompt.

---

# 34. Restore removed plugin code manually

The remover retains a full code backup.

Example:

```text
/var/lib/tec-tac/backups/plugins/networkprobe/removed-20260917T181500/
├── extensions/
│   └── networkprobe/
└── reportsets/
    └── networkprobe/
```

To restore the code manually:

```bash
cp -a \
  /var/lib/tec-tac/backups/plugins/networkprobe/removed-20260917T181500/extensions/networkprobe \
  /opt/tec-tac/extensions/

cp -a \
  /var/lib/tec-tac/backups/plugins/networkprobe/removed-20260917T181500/reportsets/networkprobe \
  /opt/tec-tac/reportsets/
```

Then validate and gracefully reload Django:

```bash
cd /opt/tec-tac

sudo bash tests/registry-validation.sh

cd /rmm/api/tacticalrmm
sudo -u tactical /rmm/api/env/bin/python manage.py check

sudo bash /opt/tec-tac/scripts/reload-rmm-uwsgi.sh
```

If the plugin was removed with `--purge-data`, restoring only the files does **not** restore deleted database data.

You would need to reapply migrations and restore data from an appropriate database backup if required.

---

# 35. Removal design rule

Treat plugin removal as a deployment operation, not as `rm -rf`.

Use:

```text
scripts/remove-extension.sh
```

rather than deleting plugin directories directly.

The default behaviour is intentionally:

```text
remove code
preserve data
```

because preserving customer/operational data is safer than automatically deleting it.

Use `--purge-data` only when the database removal is intended and reviewed.


---

# Tutorial reference package: PackageTest

Tec-Tac 1.0.2 includes a complete installable reference package under:

```text
docs/tutorial-packages/packagetest/
```

It demonstrates a matching extension + ReportSet, runtime API registration, ReportSet mapping, manifest-declared permission groups, role-based API authorization, ZIP installation, permission assignment, and safe removal.

The source is under `docs/tutorial-packages/packagetest/source/` and a ready-built package is `docs/tutorial-packages/packagetest/packagetest-0.1.0.zip`. Rebuild it with:

```bash
cd /opt/tec-tac/docs/tutorial-packages/packagetest
bash build.sh
```

Install interactively:

```bash
cd /opt/tec-tac
sudo bash scripts/install-extension.sh docs/tutorial-packages/packagetest/packagetest-0.1.0.zip
```

PackageTest declares `read` and `manage` permission groups. The installer resolves the supplied Tactical username to its Tactical role and grants the selected group to that role.

Unattended install:

```bash
TEC_TAC_EXTENSION_USERNAME="bob" \
TEC_TAC_EXTENSION_PERMISSION_GROUP="manage" \
sudo -E bash scripts/install-extension.sh docs/tutorial-packages/packagetest/packagetest-0.1.0.zip
```

API after install:

```text
GET  /api/tfd/packagetest/sample/   requires packagetest.api.read
POST /api/tfd/packagetest/sample/   requires packagetest.api.manage
```

Remove it with:

```bash
sudo bash scripts/remove-extension.sh packagetest
```

Removal disables active grants declared by the extension before deleting the extension/reportset code.

Run the package lifecycle test:

```bash
sudo bash tests/extension-package-lifecycle.sh
```

To exercise permission assignment too:

```bash
TEC_TAC_PACKAGE_TEST_USERNAME="bob" sudo -E bash tests/extension-package-lifecycle.sh
```

## Permission-group manifest contract

Only the extension manifest may declare `permission_groups`. Permission codenames must begin with `<extension-id>.`. API code should check permissions through `tec_tac.rbac.has_extension_permission`, not by importing the persistence model directly.

**File:** `extensions/networkprobe/tec_tac_networkprobe/permissions.py`

```python
from rest_framework.permissions import BasePermission
from tec_tac.rbac import has_extension_permission

class NetworkProbePermission(BasePermission):
    def has_permission(self, request, view):
        codename = "networkprobe.device.list" if request.method in ("GET", "HEAD", "OPTIONS") else "networkprobe.device.manage"
        return has_extension_permission(request.user, codename)
```

Tec-Tac 1.0.x currently persists generic role grants in the existing shared `ExtensionRolePermission` compatibility table. Extension code should use `tec_tac.rbac` so that storage can change later without changing the extension.

---

# Public UI surfaces (Tec-Tac 1.2.1+)

Extensions that need anonymous pages can declare a separate public UI entry. This is intentionally separate from the normal authenticated module entry.

**File:** `extensions/<extension-id>/tec_tac_ui.json`

```json
{
  "id": "example",
  "version": "1.0.0",
  "entry": "ui/index.js",
  "public": {
    "entry": "ui/public.js",
    "base_path": "/public/example"
  },
  "navigation": {
    "label": "Example",
    "section": "Extensions",
    "icon": "E",
    "order": 100
  },
  "permissions": ["example.manage"]
}
```

The authenticated entry exports `register(context)`. The public entry exports `registerPublic(context)`.

Example public entry:

```javascript
export default {
  async registerPublic(ctx) {
    const { h } = ctx.Vue
    ctx.addPublicRoute({
      path: '/public/example',
      name: 'example-public',
      meta: { title: 'Example Public' },
      component: {
        setup() {
          return () => h('section', [h('h1', 'Public example')])
        },
      },
    })
  },
}
```

Public UI rules:

```text
public route namespace: /public/<extension-id>/...
public runtime loads before Tactical authentication
public runtime does not receive authenticated state, RBAC helpers, or the authenticated API helper
publicApi() deliberately omits the Tactical Authorization token
backend APIs remain private unless the extension explicitly allows anonymous access
entry and public.entry must share the same UI bundle directory when both are present
```

A public page does not grant anonymous access to backend data. If an API endpoint is intended to be public, configure that endpoint explicitly (for example with DRF `AllowAny`) and validate all public inputs as untrusted.

---

## Swagger / OpenAPI grouping convention

Every extension that exposes HTTP API endpoints must give its endpoints an explicit `drf_spectacular` tag. This keeps Tactical's Swagger UI readable as more Tec-Tac extensions are installed.

Use one stable tag for the extension, normally its display name. For example, UserInvite endpoints should use `UserInvite`; framework-owned endpoints use `Tec-Tac Framework`; TFD Reporting uses `TFD Reporting`.

```python
from drf_spectacular.utils import extend_schema, extend_schema_view

@extend_schema_view(
    get=extend_schema(tags=["UserInvite"], summary="List user invitations"),
    post=extend_schema(tags=["UserInvite"], summary="Create a user invitation"),
)
class UserInviteListCreateView(...):
    ...
```

Do not reuse `Tec-Tac Framework` for extension-owned endpoints. The framework tag is reserved for framework APIs such as module management, UI context, and extension RBAC.


## 36. Graceful Django reload

Normal extension installation and removal must not restart the full Tactical service set. Tec-Tac 1.2.4 reloads the Django/uWSGI application with `scripts/reload-rmm-uwsgi.sh`, which sends `SIGHUP` to the current `rmm.service` uWSGI master and waits for the worker set to refresh. This allows newly installed or removed Django apps and URL registrations to take effect without terminating the lifecycle worker or restarting Daphne/Celery services that were not changed.

The framework installer also ensures the production `rmm` process has the Tactical user's primary group as a supplementary group so that browser/API package staging can write to `/var/lib/tec-tac/module-manager/`. Extension authors should not solve this by changing `/opt/tec-tac` ownership or making runtime directories world-writable.


---

# Scheduling module actions (Tec-Tac 1.8.0)

If an extension needs user-configurable scheduled execution, do **not** add its own cron entry, timer, Celery Beat schedule, or browser timer. Register a schedulable action with the Tec-Tac framework.

The architecture is:

```text
Module defines the action
        |
        v
Tec-Tac Scheduler stores when/targets/parameters
        |
        v
server-side scheduler timer
        |
        v
Tactical Celery
        |
        v
module handler
        |
        v
shared execution history
```

A scheduled action is registered from the module's Django `AppConfig.ready()` so it exists even when no browser is open:

```python
from tec_tac.scheduler import register_scheduled_action

register_scheduled_action(
    id="networkprobe.discovery",
    module_id="networkprobe",
    label="Run network discovery",
    target_types=("site", "client", "dynamic"),
    permission="networkprobe.run",
    handler=run_discovery_handler,
)
```

The handler receives a single context dictionary:

```python
def run_discovery_handler(context):
    targets = context["targets"]
    parameters = context["parameters"]
    manual = context["manual"]

    # Resolve targets and execute the module's normal backend operation.
    result = run_discovery(targets=targets, parameters=parameters)

    return {
        "ok": True,
        "devices_seen": result.devices_seen,
        "new_devices": result.new_devices,
    }
```

Important rules:

```text
modules define WHAT can run
Tec-Tac defines WHEN it runs
handlers must work without request.user or a browser session
target/parameter meaning belongs to the module
raise exceptions to use the framework retry policy
return JSON-safe structured results where possible
keep action IDs stable across upgrades
```

Saved schedules run unattended. A user must be authenticated and authorized to create/manage/manual-run a schedule, but the scheduled execution itself is a system operation and does not require that user to remain logged in.

For the complete contract, including snapshot/dynamic targets, permissions, retry/concurrency behaviour, Communicator and Patch Management examples, see:

```text
docs/module-scheduling.md
```

## Do not confuse dispatch with execution success

When an extension sends work through Tactical raw commands, NATS, a queue, HTTP, a webhook, or another transport, a transport response does **not** automatically mean the requested operation succeeded.

```text
transport accepted/sent request  -> dispatched
downstream command/app success   -> executed/delivered
downstream command/app error     -> failed
no final execution evidence      -> pending/unknown
```

A Scheduler handler returns success only when it can justify that result. If the endpoint or downstream application reports failure, propagate that failure so Scheduler history and retries are accurate. If only dispatch is known, return a dispatch state instead of claiming delivery.

Raw OS commands must also be tested using the exact shell selected by the agent transport. For example, a Windows command sent with `shell: "cmd"` must follow `cmd.exe` quoting rules; executable paths containing spaces such as `C:\Program Files\...` require deliberate command construction and an end-to-end test through the same raw-command path used in production.

# Interdependent modules and soft failure

When one extension integrates with another, depend on the provider's **public contract**, not its internal models, tables, helpers, views, or filesystem structure.

Classify the relationship first:

- **Hard dependency**: the module cannot fulfil its core purpose without the provider. Declare it in `dependencies` with an explicit compatible version range.
- **Optional dependency**: the module works without the provider but enables extra features when it is available. Declare it in `optional_dependencies`.
- **Framework service**: the capability is broadly useful across many modules and should live in Tec-Tac core rather than creating a dependency web. Scheduler is already a framework service; shared resource metadata/tags is the intended pattern for tag-based targeting.

Example optional dependency:

```json
{
  "optional_dependencies": {
    "tags": ">=1.0.0,<2.0.0"
  }
}
```

## Required soft-failure behaviour

A missing, disabled, broken, or incompatible dependency must not crash Tec-Tac or unrelated features in the consumer module.

```text
provider available
    -> integration feature works

provider unavailable
    -> consumer still loads
    -> unrelated features still work
    -> dependent feature is disabled/degraded
    -> UI states the reason
    -> backend refuses the dependent operation cleanly
```

This applies even to hard dependencies after installation: Module Manager prevents known invalid dependency states, but runtime state can still drift because of faults, manual disablement, partial upgrades, or broken provider code.

Do not put unguarded optional-provider imports in `AppConfig.ready()`.

Do not hide a failed integration silently. Show whether the provider is missing, disabled, incompatible, unhealthy, or missing the required capability.

## Current framework boundary

Tec-Tac 1.9.0 implements the generic cross-module capability registry. Backend modules should consume provider contracts through `tec_tac.capabilities` rather than importing provider-private code or calling Tec-Tac HTTP APIs over localhost.

Provider example:

```python
from tec_tac.capabilities import register_capability

register_capability(
    id="communicator.messaging",
    module_id="communicator",
    version="1.0.0",
    provider=communicator_service,
)
```

Consumer example:

```python
from tec_tac.capabilities import get_capability

communicator = get_capability(
    "communicator.messaging",
    version=">=1,<2",
    required=False,
)
```

Use `capability_status()` to expose missing, disabled, unhealthy, incompatible, or unregistered states. Capability contract versions are independent from module package versions. Keep package lifecycle dependencies in `tec_tac.json` and re-check capability availability at execution time.

See `docs/capabilities.md` and `docs/core-functions.md`.

See the complete contract and examples in:

```text
docs/module-interoperability.md
```

## Scheduled integrations

If a scheduled action depends on another module, validate that dependency again when the run executes. A schedule may execute days or months after it was created.

Permanent incompatibility should produce a clear scheduler-history diagnostic rather than repeated blind retries. Temporary provider outages may use the configured scheduler retry policy when recovery is realistic.

## Live Developer Contract catalog (Framework 1.10.0+)

Before integrating with another Tec-Tac module, inspect the live contract catalog rather than assuming an older module implementation is still current.

```text
GET /api/tfd/contracts/
GET /api/tfd/contracts/export/?export_format=md
GET /api/tfd/contracts/export/?export_format=txt
```

Tec-Tac UI 0.9.0 exposes the same catalog at **Administration -> Public Contracts**. The Markdown export is intended to be handed directly to module coding agents. It includes stable core Python contracts, live registered capabilities, live Scheduler actions, extension permissions, and the `/api/tfd/` HTTP boundary.

The export is an integration contract, not permission to import provider internals. Backend modules still use Python `tec_tac.*` contracts, cross-module business operations use `tec_tac.capabilities`, and browser/external callers use authenticated HTTP.

See `docs/developer-contracts.md`.



## Scheduler execution semantics (Framework 1.11.0)

When an extension exposes a schedulable action, distinguish transport from operation completion. Queue/NATS/API acknowledgement alone does not prove the endpoint or downstream application succeeded. Return success only after the owned operation has succeeded; otherwise raise an error so Scheduler history reflects the real outcome.

Classify known failures explicitly:

```python
from tec_tac.scheduler import SchedulerPermanentError, SchedulerTransientError

if invalid_configuration:
    raise SchedulerPermanentError("Configuration cannot be executed.")

if temporary_provider_outage:
    raise SchedulerTransientError("Provider is temporarily unavailable.")
```

The handler context includes `attempt`. One-off schedule definitions are automatically removed after the operator-configured retention period (default 48 hours), while run history remains available. Do not store permanent audit data in the schedule definition itself.

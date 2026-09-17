# Tec-Tac Tactical RMM Extension POC

Version **0.5.0** restructures the POC so Tec-Tac code no longer lives inside the Tactical RMM Git checkout.

## Installed structure

```text
/opt/tec-tac/
├── framwork/
│   └── tec_tac/
│       ├── __init__.py
│       └── bootstrap.py
├── extensions/
│   └── reporting/
│       └── tfdreporting/
└── backups/
```

`framwork` is intentionally spelled exactly this way to match the agreed POC path.

The only Tec-Tac code left inside the Tactical configuration is a small bootstrap block in Tactical's already-ignored `local_settings.py`:

```python
# BEGIN TEC-TAC EXTENSION FRAMEWORK
import sys

_TEC_TAC_FRAMEWORK = "/opt/tec-tac/framwork"
if _TEC_TAC_FRAMEWORK not in sys.path:
    sys.path.insert(0, _TEC_TAC_FRAMEWORK)

from tec_tac.bootstrap import load_extensions
load_extensions()
# END TEC-TAC EXTENSION FRAMEWORK
```

No Tactical tracked source file is modified.

## What remains from v0.4.1

The reporting extension still provides the existing POC functionality:

- `NetworkAvailability` model and migrations.
- `ExtensionRolePermission` and TFD RBAC helper.
- Tactical API-key authenticated reporting endpoint.
- least-privilege GET/POST permissions.
- validation and idempotent ingestion.
- server-generated `ingested_by` and `received_at` audit fields.
- runtime registration with Tactical Report Manager.
- runtime API URL registration.

The internal Django app name remains `tfdreporting` so its migration identity stays stable.

## Installation

After removing the previous POC, install with:

```bash
sudo bash install.sh
```

The installer:

1. verifies Tactical's `local_settings.py` is Git-ignored;
2. backs it up;
3. installs the framework to `/opt/tec-tac/framwork/`;
4. installs reporting to `/opt/tec-tac/extensions/reporting/`;
5. writes only the minimal bootstrap to `local_settings.py`;
6. runs Django checks and migrations;
7. verifies Python is loading `tfdreporting` from `/opt/tec-tac/extensions/reporting/`;
8. verifies RBAC, Report Manager and the API route;
9. removes any legacy in-tree `/rmm/api/tacticalrmm/tfdreporting` copy and old Git exclude rule after successful verification;
10. restarts Tactical services.

## Uninstall

Preserve database tables/data:

```bash
sudo bash uninstall.sh
```

Full POC removal including database tables and all extension records:

```bash
sudo bash uninstall.sh --purge-data
```

With `--purge-data`, the script first runs:

```bash
python manage.py migrate tfdreporting zero --noinput
```

while the extension is still loaded, then removes the bootstrap and Tec-Tac code.

## Current API

```text
/api/tfd/reporting/network-availability/
```

The next POC phase can add server-side infrastructure devices/checks while keeping the probe design separate.

# Tec-Tac Tactical RMM Extension POC

Version **0.5.1** restructures the POC so Tec-Tac code no longer lives inside the Tactical RMM Git checkout.

The repository itself is the Tec-Tac runtime root. The scripts do **not** require the repository to be installed at a hardcoded path. `/opt/tec-tac` is the recommended location only.

## Repository structure

```text
<repo-root>/
├── install.sh
├── uninstall.sh
├── README.md
├── VERSION
├── LICENSE
├── framwork/
│   └── tec_tac/
│       ├── __init__.py
│       └── bootstrap.py
└── extensions/
    └── reporting/
        └── tfdreporting/
```

`framwork` is intentionally spelled exactly this way to match the agreed POC structure.

The installer discovers `<repo-root>` from the location of `install.sh`. The framework then discovers the extensions directory relative to its own file location.

The only Tec-Tac code placed into Tactical configuration is a small bootstrap block in Tactical's already-ignored `local_settings.py`. The installer writes the resolved framework path automatically, for example:

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

## Get the repository

Recommended location:

```bash
cd /opt
sudo git clone https://github.com/jvz007/tac-net-rep.git tec-tac
cd /opt/tec-tac
```

The repository may be cloned elsewhere. The installer will use its actual location automatically.

For an existing checkout:

```bash
cd /opt/tec-tac
sudo git fetch origin
sudo git reset --hard origin/main
```

## Installation

From the repository root:

```bash
sudo bash install.sh
```

The installer:

1. discovers the Tec-Tac repository root from `install.sh`;
2. validates the framework and reporting extension layout;
3. verifies Tactical's `local_settings.py` is Git-ignored;
4. backs up `local_settings.py` to `/var/lib/tec-tac/backups/` by default;
5. writes only the minimal bootstrap using the resolved framework path;
6. loads framework and extension code directly from the Git checkout;
7. runs Django checks and migrations;
8. verifies Python is loading `tfdreporting` from the repository's `extensions/reporting/` directory;
9. verifies RBAC, Report Manager and the API route;
10. removes any legacy in-tree `/rmm/api/tacticalrmm/tfdreporting` copy and old Git exclude rule after successful verification;
11. restarts Tactical services.

The installer does not copy Tec-Tac code into another installation directory. Mutable backups are kept outside the Git checkout so `git clean -fd` cannot delete them.


## Test scripts

Version 0.5.1 adds reusable tests under `tests/`.

Server-side framework/reporting verification:

```bash
cd /opt/tec-tac
sudo bash tests/network-reporting-server.sh
```

API ingestion/idempotency/validation smoke test:

```bash
cd /opt/tec-tac
export TEC_TAC_API_BASE="https://api.example.com"
export TEC_TAC_API_KEY="<Tactical API key with reporting manage permission>"
bash tests/network-reporting-api.sh
unset TEC_TAC_API_KEY
```

The API test creates one valid `NetworkAvailability` row using a unique idempotency key, verifies exact replay behavior, then checks conflict and validation responses. The API key is read only from the environment and must not be committed to the repository.

## Persistent state

Tec-Tac source code stays in the Git checkout. Mutable state is stored separately:

```text
<repo-root>/                 Git-managed code
/var/lib/tec-tac/backups/    local_settings.py backups
```

Set `TEC_TAC_BACKUP_DIR` when running install/uninstall if a different backup directory is required.

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

## Verification

After installation:

```bash
grep -n "TEC-TAC" /rmm/api/tacticalrmm/tacticalrmm/local_settings.py
```

Then:

```bash
cd /rmm/api/tacticalrmm
source /rmm/api/env/bin/activate
python manage.py shell -c "import tfdreporting; print(tfdreporting.__file__)"
```

If the repository was cloned to `/opt/tec-tac`, the expected path begins with:

```text
/opt/tec-tac/extensions/reporting/tfdreporting/
```

## Updating

Update the Git checkout, then rerun the installer:

```bash
cd /opt/tec-tac
sudo git fetch origin
sudo git reset --hard origin/main
sudo bash install.sh
```

If the repository is located elsewhere, run the same commands from that checkout.

## Uninstall

Preserve database tables/data:

```bash
sudo bash uninstall.sh
```

Full POC database removal:

```bash
sudo bash uninstall.sh --purge-data
```

With `--purge-data`, the script first runs:

```bash
python manage.py migrate tfdreporting zero --noinput
```

while the extension is still loaded.

The uninstall script removes the Tec-Tac bootstrap from Tactical but deliberately leaves the Git repository intact. Delete the checkout separately if it is no longer required.

## Current API

```text
/api/tfd/reporting/network-availability/
```

The next POC phase can add server-side infrastructure devices/checks while keeping the probe design separate.

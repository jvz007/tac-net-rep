# Tec-Tac Tactical RMM Extension Framework

Version **0.5.3** formalises the Tec-Tac foundation around two first-class plugin types: **extensions** and **reportsets**.

The repository itself is the runtime root. It may be cloned anywhere; `/opt/tec-tac` is only the recommended location.

## Foundation layout

```text
<repo-root>/
├── framwork/
│   └── tec_tac/
│       ├── bootstrap.py
│       └── registry.py
├── extensions/
│   └── <extension-id>/
├── reportsets/
│   └── <extension-id>/
├── scripts/
├── tests/
├── install.sh
├── uninstall.sh
└── VERSION
```

`framwork` remains intentionally spelled this way to preserve the established POC path.

### Naming contract

The stable extension ID is the directory name under `extensions/`.

A reportset belonging to that extension uses **the exact same ID**:

```text
extensions/<extension-id>/
reportsets/<extension-id>/
```

The name identifies **which extension owns the component**, not what the data is about. Purpose-specific modules belong inside the matching reportset.

Example only:

```text
extensions/networkprobe/
reportsets/networkprobe/
    availability.py
    latency.py
    packet_loss.py
```

## Plugin manifests

Convention-based plugins use a `tec_tac.json` file inside their directory.

Extension example:

```json
{
  "id": "exampleextension",
  "type": "extension",
  "python_paths": ["."],
  "django_apps": ["exampleextension.apps.ExampleExtensionConfig"]
}
```

Matching reportset example:

```json
{
  "id": "exampleextension",
  "type": "reportset",
  "python_paths": ["."],
  "django_apps": ["exampleextension_reportset.apps.ExampleReportsetConfig"]
}
```

The registry validates that a reportset has a matching extension. It also rejects duplicate Django app registrations and plugin paths that escape their plugin directory.

## Current reporting POC compatibility

The existing `tfdreporting` / `NetworkAvailability` POC predates the extension/reportset naming contract. Version 0.5.3 deliberately keeps it in its existing location so the proven migrations, RBAC and API behaviour are not broken during the framework refactor.

It is loaded as `legacy-reporting-poc` by the framework registry. It should be migrated only when the first real extension receives its final extension ID; at that point its reportset will use that same ID.

## Get the repository

```bash
cd /opt
sudo git clone https://github.com/jvz007/tac-net-rep.git tec-tac
cd /opt/tec-tac
```

For an existing checkout:

```bash
cd /opt/tec-tac
sudo git fetch origin
sudo git reset --hard origin/main
```

## Installation

```bash
sudo bash install.sh
```

The installer discovers its repository path, verifies the framework layout, backs up Tactical's ignored `local_settings.py` to `/var/lib/tec-tac/backups/`, installs the minimal bootstrap, runs Django checks/migrations, verifies the existing reporting POC, optionally assigns the reporting ingest role, and restarts Tactical services.

No tracked Tactical source file is modified.

## Framework inspection

```bash
sudo bash scripts/framework-info.sh
```

This displays the discovered extension/reportset roots and every loaded Tec-Tac plugin.

## Foundation test

```bash
sudo bash tests/framework-foundation.sh
```

Then run the existing reporting tests:

```bash
sudo bash tests/network-reporting-server.sh
sudo -E bash tests/network-reporting-api.sh
```

The API test requires:

```bash
export TEC_TAC_API_BASE="https://api.example.com"
export TEC_TAC_API_KEY="YOUR_API_KEY"
```

## Reporting permission management

During an interactive install, Tec-Tac can ask for a Tactical username whose **role** should receive reporting ingest permission.

After installation:

```bash
sudo bash scripts/reporting-permission.sh bob show
sudo bash scripts/reporting-permission.sh bob manage
sudo bash scripts/reporting-permission.sh bob list
sudo bash scripts/reporting-permission.sh bob both
```

Permissions are role-based; users sharing the same Tactical role share the Tec-Tac permissions.

## Updating

```bash
cd /opt/tec-tac
sudo git fetch origin
sudo git reset --hard origin/main
sudo bash install.sh
```

## Uninstall

Preserve extension data:

```bash
sudo bash uninstall.sh
```

Purge the existing reporting POC database objects:

```bash
sudo bash uninstall.sh --purge-data
```

The Git checkout is never deleted by the uninstaller.

## Persistent state

Mutable/persistent Tec-Tac state lives outside the Git checkout:

```text
/var/lib/tec-tac/
└── backups/
```

The repository remains code only.

## Current API

```text
/api/tfd/reporting/network-availability/
```

0.5.x remains foundation work. New functional extensions and matching reportsets should be added only after this framework lifecycle is proven.

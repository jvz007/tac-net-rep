# Tec-Tac Tactical RMM Extension Framework

Version **0.5.5** finishes the current framework-foundation pass and hardens repeat-install permission handling and upgrade-safety checks. Tec-Tac now has a validated convention for paired **extensions** and **reportsets**, reusable manifests/templates, plugin inspection and scaffolding tools, and lifecycle/upgrade-safety tests.

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
├── templates/
│   └── plugin/
│       ├── extension/
│       └── reportset/
├── scripts/
├── tests/
├── install.sh
├── uninstall.sh
└── VERSION
```

`framwork` remains intentionally spelled this way to preserve the established Tec-Tac path.

## Naming contract

The directory name under `extensions/` is the stable extension ID. Its reporting/data-mapping companion uses the exact same ID under `reportsets/`:

```text
extensions/<extension-id>/
reportsets/<extension-id>/
```

The ID describes **which extension owns the component**, not the purpose of the data. Purpose-specific report modules live inside the matching reportset.

Example only:

```text
extensions/networkprobe/
reportsets/networkprobe/
├── availability.py
├── latency.py
├── packet_loss.py
└── device_health.py
```

For convention-based plugins in 0.5.5, both sides of the pair are required. An orphan reportset or an extension without its matching reportset is rejected by the registry.

## Plugin manifests

Each convention-based plugin contains `tec_tac.json`.

Extension example:

```json
{
  "id": "exampleextension",
  "type": "extension",
  "version": "0.1.0",
  "python_paths": ["."],
  "django_apps": []
}
```

Matching reportset:

```json
{
  "id": "exampleextension",
  "type": "reportset",
  "version": "0.1.0",
  "python_paths": ["."],
  "django_apps": []
}
```

The registry validates:

- plugin IDs and manifest/directory-name consistency;
- supported plugin types;
- supported manifest keys;
- manifest list types and blank values;
- Python paths remain inside the plugin directory and exist;
- extension/reportset pairing;
- duplicate plugin registrations;
- duplicate Django app registrations.

Reference manifests live under `templates/plugin/`.

## Current reporting POC compatibility

The existing `tfdreporting` / `NetworkAvailability` POC predates the extension/reportset contract. It remains at:

```text
extensions/reporting/tfdreporting/
```

and is loaded as the compatibility plugin `legacy-reporting-poc`.

We are deliberately not renaming it until the first real extension receives its final extension ID. That avoids moving proven Django migrations/RBAC/API code twice.

## Get the repository

Recommended first install:

```bash
cd /opt
sudo git clone https://github.com/jvz007/tac-net-rep.git tec-tac
cd /opt/tec-tac
sudo bash install.sh
```

The checkout can live elsewhere; the installer discovers its own path.

For an existing checkout:

```bash
cd /opt/tec-tac
git pull
sudo bash install.sh
```

If local changes must be discarded intentionally:

```bash
git fetch origin
git reset --hard origin/main
```

## Installation lifecycle

```bash
sudo bash install.sh
```

The installer:

1. discovers the repository root;
2. validates required framework/tooling files;
3. confirms Tactical's `local_settings.py` is ignored by Tactical Git;
4. backs it up under `/var/lib/tec-tac/backups/`;
5. writes the minimal Tec-Tac bootstrap using the resolved repository path;
6. loads plugins directly from the Git checkout;
7. runs Django checks and migrations;
8. verifies the existing reporting POC, RBAC, Report Manager and API route;
9. optionally grants reporting ingest permission using a Tactical username;
10. removes obsolete legacy in-tree/exclude artifacts;
11. restarts and verifies Tactical services.

No tracked Tactical source file is modified.

## Persistent state

Mutable Tec-Tac state stays outside the Git checkout:

```text
/var/lib/tec-tac/
├── backups/
└── tests/
```

The repository remains code-only and safe to reset/clean.

## Framework and plugin inspection

Framework overview:

```bash
sudo bash scripts/framework-info.sh
```

List registered plugins:

```bash
sudo bash scripts/plugin-info.sh
```

Inspect one plugin:

```bash
sudo bash scripts/plugin-info.sh legacy-reporting-poc legacy
```

Once convention plugins exist, the optional second argument can disambiguate `extension` vs `reportset` when they share the same ID.

## Scaffold a new extension/reportset pair

Create the paired directories and manifests together:

```bash
sudo bash scripts/scaffold-plugin.sh <extension-id>
```

or with an initial version:

```bash
sudo bash scripts/scaffold-plugin.sh <extension-id> 0.1.0
```

This creates:

```text
extensions/<extension-id>/tec_tac.json
extensions/<extension-id>/README.md
reportsets/<extension-id>/tec_tac.json
reportsets/<extension-id>/README.md
```

The scaffold contains no Django apps by default. Add implementation packages and then update `python_paths` / `django_apps` explicitly.

## Reporting permission management

During installation, Tec-Tac first checks whether the reporting ingest `manage` permission is already granted to one or more Tactical roles. Existing assignments are displayed and kept by default, so repeat installs do not require entering the same username again. If no assignment exists, an interactive install asks for a Tactical username whose **role** should receive the permission. You can also choose to add/change an assignment when an existing one is detected.

After installation:

```bash
sudo bash scripts/reporting-permission.sh bob show
sudo bash scripts/reporting-permission.sh bob manage
sudo bash scripts/reporting-permission.sh bob list
sudo bash scripts/reporting-permission.sh bob both
```

Permissions are role-based; every user sharing that Tactical role inherits the Tec-Tac permissions.

For unattended installation:

```bash
TEC_TAC_REPORTING_USERNAME="bob" sudo -E bash install.sh
```

## Foundation tests

Run the non-destructive foundation checks:

```bash
sudo bash tests/framework-foundation.sh
sudo bash tests/registry-validation.sh
sudo bash tests/tactical-update-survival.sh check
sudo bash tests/network-reporting-server.sh
```

The API regression test additionally needs:

```bash
export TEC_TAC_API_BASE="https://api.example.com"
export TEC_TAC_API_KEY="YOUR_API_KEY"
sudo -E bash tests/network-reporting-api.sh
```

It validates successful ingest, idempotent replay, replay header, conflict handling, invalid status, invalid latency/percentages and future timestamps.

## Full lifecycle test

`tests/lifecycle.sh` intentionally includes a purge and is therefore **destructive to the current reporting POC data**.

It will not run unless explicitly acknowledged:

```bash
sudo bash tests/lifecycle.sh --destructive
```

Sequence tested:

```text
install
→ reinstall
→ uninstall (preserve data)
→ reinstall
→ uninstall --purge-data
→ clean reinstall
→ foundation/server verification
```

If the lifecycle install should re-grant a role permission after the purge:

```bash
TEC_TAC_LIFECYCLE_USERNAME="bob" sudo -E bash tests/lifecycle.sh --destructive
```

## Tactical update survival test

Before running the normal Tactical RMM updater:

```bash
sudo bash tests/tactical-update-survival.sh before
```

Run the Tactical updater normally. Then:

```bash
sudo bash tests/tactical-update-survival.sh after
```

The test confirms that Tactical still ignores `local_settings.py`, the Tec-Tac bootstrap remains present, and Django still imports `tfdreporting` from the external Tec-Tac checkout.

A current-state-only check is also available:

```bash
sudo bash tests/tactical-update-survival.sh check
```

## Uninstall

Disconnect Tec-Tac while preserving extension tables/data:

```bash
sudo bash uninstall.sh
```

Purge the existing reporting POC database objects:

```bash
sudo bash uninstall.sh --purge-data
```

The uninstaller never deletes the Git checkout.

## Current API

```text
/api/tfd/reporting/network-availability/
```

## Foundation status

0.5.5 is still a foundation release. No new non-agent monitoring functionality is introduced here. The next functional work should consume this framework rather than modifying Tactical tracked source.

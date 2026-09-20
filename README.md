Version **1.13.2** hardens System Updates for the split Git-source/runtime architecture. Online updates track exact commits, offline packages remain auditable Git commits, and rollback restores source state before reinstalling runtime.

# Tec-Tac

Version **1.13.5** adds first-class source/runtime architecture diagnostics while retaining the hardened System Update transaction model introduced in 1.13.3.

 Framework

Version **1.13.1** hardens the source/runtime layout migration preflight by requiring persistent module state to match the physical extension/reportset trees before cutover.

Version **1.12.3** hardens the offline System Updates path. Installer contract verification now derives the expected framework version from `VERSION` instead of a hardcoded release number, and post-install verification must pass package/version consistency, Django checks, Tec-Tac migration state, core route, public contract version, and recovery-script executability before an update is considered successful. Installer execution is bounded by a timeout and failures use the existing backup/rollback path.

Version **1.12.2** cleaned up release-integrity/version drift tests and removed stale hardcoded UI/framework release assumptions.
Version **1.12.1** is a corrective release for the Recovery Toolkit packaging. It makes every recovery shell script executable during install/update, verifies executability, and keeps the toolkit exclusively under `/opt/tec-tac/scripts/recovery/` without `/usr/local/sbin` convenience links.

Version **1.12.0** added framework self-update preservation checks, Module Manager staging repair and independent multi-package classification, the missing Scheduler model-options migration, and the console Recovery Toolkit.

Version **1.11.1** is a corrective release for the 1.11.0 installer developer-contract verification. The installer now verifies the deployed framework version against 1.11.1 instead of the stale 1.10.3 assertion.

Version **1.11.0** hardens the shared Scheduler with configurable one-off retention, preserved run history, diagnostics, self-tests and retry classification.

# Tec-Tac Tactical RMM Extension Framework

Version **1.10.3** strengthens the module-development contract around downstream execution results: transport acknowledgement is not operation success, scheduled handlers must propagate downstream failures, and raw OS commands must be shell-safe and tested through the production agent path. Version 1.10.2 fixed Public Contracts attachment export content negotiation. See `docs/module-scheduling.md` and `docs/developer-contracts.md`.

Module interoperability: `docs/module-interoperability.md`.
Core module developer reference: `docs/core-functions.md`.

Version **1.9.0** adds the cross-module capability registry. See `docs/capabilities.md`, `docs/core-functions.md`, and `docs/module-interoperability.md`.

Version **1.8.0** added the first-class Tec-Tac Scheduler. See `docs/scheduler.md` and `docs/module-scheduling.md`.

Historical release notes are archived under `docs/releases/`; only the current release note remains at repository root.

Version **1.7.1** is a corrective release for repository-installed modules: the canonical registry accepts v2 dependency/runtime metadata in every install path.
Version **1.7.0** adds multi-repository module sources, cached repository health, online catalog/update reporting, SHA-256 verified online staging, and installed source provenance while retaining the existing Module Management v2 installer.
Version **1.6.1** fixes module visibility precedence so package-defined hidden/visible settings are defaults that can always be overridden by Module Manager.
Version **1.6.0** adds independent module navigation visibility to Module Management v2. Modules can now remain enabled at runtime while being hidden from Tec-Tac navigation. The 1.5.0 package ordering, dependency enforcement, bundle planning, staged cleanup, and existing enable/disable lifecycle remain intact.

The repository itself is the runtime root. It may be cloned anywhere; `/opt/tec-tac` is only the recommended location.

## 1.2.3 highlights

- Structured module-upload diagnostics for production HTTP failures.
- Stronger AppConfig, model, migration, post-restart, and UI deployment verification.
- Module jobs expose lifecycle stage and error type.
- Framework APIs are grouped under `Tec-Tac Framework` in Swagger/OpenAPI.
- Extension documentation now requires a stable extension-specific Swagger tag.


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

For convention-based plugins in 1.0.0, both sides of the pair are required. An orphan reportset or an extension without its matching reportset is rejected by the registry.

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

## Working reference pair

Version 1.0.0 includes a deliberately small reference implementation:

```text
extensions/example/
├── tec_tac.json
└── tec_tac_example_extension/
    ├── __init__.py
    ├── apps.py
    └── sample.py

reportsets/example/
├── tec_tac.json
└── tec_tac_example_reportset/
    ├── __init__.py
    ├── apps.py
    └── sample.py
```

Both plugins use the extension ID `example`. The extension provides a deterministic raw data record; the matching reportset maps it into a tiny report-facing representation. This proves Python-path discovery, paired manifest validation, Django app registration, and the extension-to-reportset data flow without introducing a production feature or database schema.

The `example` pair is **reference implementation only**. Production extensions should use their own real extension ID and should not depend on the example packages.

Test it with:

```bash
sudo bash tests/example-plugin.sh
```


## Extension developer tutorial

The end-to-end extension and ReportSet tutorial is included in both Markdown and HTML:

```text
docs/extension-reportset-tutorial.md
docs/extension-reportset-tutorial.html
```

It covers design, scaffolding, explicit file locations, Django app creation, models, migrations, APIs, permissions, ReportSet mappings/enrichment, testing, packaging, deployment, upgrades, removal and restore considerations.

## Extension package install and removal

Tec-Tac 1.0.1 includes generic package tooling for convention-based extension/reportset pairs.

Install a `.zip`, `.tar.gz` or `.tgz` package:

```bash
sudo bash scripts/install-extension.sh ./networkprobe-0.1.0.tar.gz
```

Replace/upgrade an installed pair:

```bash
sudo bash scripts/install-extension.sh ./networkprobe-0.2.0.tar.gz --replace
```

Remove plugin code while preserving database objects:

```bash
sudo bash scripts/remove-extension.sh networkprobe
```

Explicitly reverse conventional plugin migrations before removal:

```bash
sudo bash scripts/remove-extension.sh networkprobe --purge-data
```

Plugin package/removed-code backups are kept under `/var/lib/tec-tac/backups/plugins/`. The default removal behavior preserves data. The package tools apply only to convention-based extension/reportset pairs and do not manage the legacy reporting POC.

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
sudo bash tests/example-plugin.sh
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

## Stable foundation status

1.0.0 is the stable Tec-Tac framework baseline. The included `example` pair is reference-only; no new production monitoring functionality is introduced by this release. New functional work should consume this framework through `extensions/<extension-id>/` and `reportsets/<extension-id>/` rather than modifying Tactical tracked source.

## Access API (1.1.0)

The framework now exposes upgrade-safe authenticated endpoints under `/api/tfd/` for UI context and Tec-Tac extension role grants. Tactical's existing Role IDs remain the RBAC anchor; Tactical's own account and native role permissions remain authoritative. See `docs/releases/RELEASE_NOTES_1.1.0.md`.

## Module lifecycle API (1.2.0)

Tec-Tac 1.2.0 adds an authenticated module-management surface under `/api/tfd/modules/`:

```text
GET    /api/tfd/modules/
POST   /api/tfd/modules/packages/inspect/
DELETE /api/tfd/modules/packages/<upload-id>/
POST   /api/tfd/modules/packages/<upload-id>/install/
POST   /api/tfd/modules/<extension-id>/remove/
GET    /api/tfd/modules/jobs/<job-id>/
```

Catalog reads require an authenticated Tactical session. Installation, replacement, staging cleanup, removal, and job inspection require effective module-management access, mapped to Tactical `can_do_server_maint` (or effective superuser).

The Tactical web process never runs the root lifecycle scripts directly. `install.sh` installs a root-owned helper at `/usr/local/sbin/tec-tac-module-job` plus a narrowly scoped sudoers rule that allows the Tactical service user to dispatch only opaque UUID jobs. The helper claims the staged package before execution, checks that lifecycle scripts are root-owned and not group/world writable, then runs the existing package installer/remover outside the Tactical web process. Extension install/remove now refreshes Django with a graceful uWSGI `SIGHUP` reload instead of restarting the `rmm` systemd service, so lifecycle jobs are not killed by their own deployment step.

Packages are staged below `/var/lib/tec-tac/module-manager/`. Inspection enforces archive path/link checks, upload and expansion limits, exactly one matching extension/ReportSet pair, registry validation, optional `tec_tac_ui.json` validation, and declared-permission references. Extension and ReportSet versions must match before UI-driven installation is allowed.

The UI-driven remover intentionally uses the safe default: remove code and preserve database objects/data. `--purge-data` remains a manual administrative operation and is not exposed through the web API.

When `/opt/tec-tac-ui/scripts/sync-modules.sh` is present, a successful lifecycle job synchronizes runtime UI modules after the backend package operation.

### Development UI lifecycle package

A small reference package is included at:

```text
docs/tutorial-packages/uitest/uitest-0.1.0.zip
```

It has no database models and is intended to test the complete 1.2.0 + UI 0.2.0 flow: browser upload, package inspection, install job, graceful Django/uWSGI reload, UI synchronization, runtime route/navigation registration, RBAC permission discovery, and safe code removal.

## Public extension UI in 1.2.1

A first-class extension can expose an unauthenticated browser surface without making its authenticated administration UI public. Add an optional `public` object to `extensions/<id>/tec_tac_ui.json`:

```json
{
  "id": "statusportal",
  "version": "1.0.0",
  "entry": "ui/index.js",
  "public": {
    "entry": "ui/public.js",
    "base_path": "/public/statusportal"
  },
  "permissions": ["statusportal.manage"]
}
```

`entry` is the authenticated UI module. `public.entry` is loaded before Tactical authentication and must export `registerPublic(context)`. A module may declare either surface or both. Public routes are restricted to `/public/<extension-id>` and its descendants.

The public browser runtime deliberately receives a reduced contract: Vue, app, descriptor, `addPublicRoute(route)`, and `publicApi(path, options)`. The public API helper does not attach the Tactical browser token. Any corresponding backend endpoint remains private unless the extension explicitly configures anonymous access server-side.


## 1.2.2 persistent UI deployment coordination

The paired Tec-Tac UI 0.2.2 deployment lives at `/var/lib/tec-tac/ui/tec-tac` instead of Tactical's replaceable `/var/www/rmm/dist/tec-tac`. The module manager stores this as `UI_ROOT` in `/etc/tec-tac/module-manager.conf` and passes it to `scripts/sync-modules.sh` after successful extension install/remove jobs. Nginx integration and post-update repair are owned by the UI repository.



## Local TOTP QR endpoint (1.2.5)

Tec-Tac 1.2.5 adds `GET /api/tfd/auth/totp/qr/` for the authenticated enrollment session. The framework reuses Tactical's own `TOTPSetupSerializer` provisioning URI and Tactical's installed Python `qrcode` package to generate an SVG QR code locally. No TOTP secret or provisioning URI is sent to an external QR service. The endpoint is `no-store` and requires an authenticated Tactical token.

## Graceful Django reload and runtime permissions (1.2.4)

Tec-Tac 1.2.4 removes full Tactical service restarts from extension install/remove. The lifecycle scripts send `SIGHUP` to the active uWSGI master process, which gracefully reloads the Django stack while preserving the listening socket and keeping the `rmm.service` unit alive. Daphne, Celery, and Celery Beat are not restarted for normal extension lifecycle operations.

`install.sh` also installs `/etc/systemd/system/rmm.service.d/tec-tac.conf` with the Tactical user's primary group as a supplementary group for the production `rmm` process. This gives the real uWSGI process access to `/var/lib/tec-tac/module-manager/` without widening the runtime directory permissions or changing `/opt/tec-tac` ownership. The installer verifies both the systemd setting and the live process group membership after restart.

## System updates (1.3.0)

Tec-Tac 1.3.0 can update both the framework and standalone UI through the web interface. The updater supports latest tagged GitHub releases, explicitly selected branches/custom builds, and offline `.zip`, `.tar.gz`, or `.tgz` repository archives. All sources converge into the same inspection, version comparison, backup, install, verification and rollback lifecycle.

The privileged updater is installed outside `/opt/tec-tac` at `/usr/local/lib/tec-tac-updater/system-update-helper.py` with `/usr/local/sbin/tec-tac-system-update` as its command entrypoint. Jobs run in independent transient systemd units so replacing/restarting Tec-Tac cannot terminate its own update worker.

State is stored below `/var/lib/tec-tac/system-updates/` (`staged`, `jobs`, `running`, `logs`, `backups`, and `history`). Only one system update can run at a time.

The default repositories are configured in `/etc/tec-tac/system-update.conf`. A private GitHub repository may use a root-only token in `/etc/tec-tac/github-token`; browser clients never receive that token.


## Module Management v2 (1.4.x)

Framework 1.4.x extends the module platform with persistent enable/disable state, hard and optional dependencies, semantic version constraints, framework/UI compatibility requirements, multi-package and bundle inspection, dependency-ordered installation, and dependency-safe disable/remove checks. Existing modules default to enabled when no explicit state exists.

Runtime module state is stored at `/var/lib/tec-tac/module-manager/module-state.json`. From 1.4.1 the directory is traversable and the state file is root-owned `0644`, allowing `rmm`, Daphne, Celery, and Celery Beat to import the Tec-Tac bootstrap regardless of their service identities while lifecycle writes remain privileged.

The normal installer owns both module workers:

```text
/usr/local/sbin/tec-tac-module-job
/usr/local/sbin/tec-tac-module-v2-job
```

See `docs/releases/RELEASE_NOTES_1.4.0.md` and `docs/releases/RELEASE_NOTES_1.4.1.md`.


## Module install ordering (1.5.0)

Multi-package and bundle installs may submit an explicit package order. Tec-Tac validates that every staged hard dependency still appears before its dependant; invalid sequences are rejected before a privileged lifecycle job is queued. Packages with no dependency relationship may be arranged in operator-selected order. Cancelled v2 stages can also be discarded through the v2 package staging endpoint.

## Module visibility state (planned)

Tec-Tac distinguishes **runtime state** from **navigation visibility**. A module may be fully enabled and available to other modules without requiring a permanent entry in the Tec-Tac navigation rail.

The intended states are:

| Runtime | Visibility | Behaviour |
| --- | --- | --- |
| Enabled | Visible | Module is active and its declared navigation entry is shown. |
| Enabled | Hidden | Module is active, its APIs/routes/background behaviour remain available, but its navigation entry is suppressed. |
| Disabled | Hidden | Module is inactive at runtime and is not exposed in navigation. |

`Hidden` is not a security or dependency state. It only controls whether the module contributes its normal navigation entry. Direct/internal routes may still be used by other Tec-Tac workflows when the module is enabled, and backend authorization remains authoritative.

This is intended for supporting modules such as Checks or Automation that may provide functionality to Endpoints or other operator workflows without needing their own permanent left-rail destination.

Existing modules default to:

```text
enabled = true
visible = true
```

The Modules administration surface must always list hidden modules so an administrator can restore visibility. Dependency validation considers whether a dependency is installed and enabled; visibility does not satisfy or break a dependency.

The planned persistent state shape is:

```json
{
  "schema": 1,
  "modules": {
    "checks": {
      "enabled": true,
      "visible": false
    }
  }
}
```

See `docs/module-visibility.md` for the complete behaviour contract.


## Module visibility (1.6.0)

Module runtime state and navigation visibility are independent:

- **Enabled + Visible** — active at runtime and shown in Tec-Tac navigation.
- **Enabled + Hidden** — active at runtime, dependencies and routes remain available, but the module does not add a top-level navigation entry.
- **Disabled** — excluded from runtime loading and therefore absent from navigation.

Visibility is stored in `/var/lib/tec-tac/module-manager/module-state.json` as `visible: true|false`. Missing visibility state defaults to `true` for upgrade compatibility. Hiding a module does not weaken or change RBAC and does not affect dependency satisfaction. See `docs/module-visibility.md`.

## Module repositories (1.7.0)

Module Management v2 supports multiple enabled/disabled online repositories, explicit priority and trust labels, cached sync health, online catalog reporting, SHA-256 verified package staging, and installed source provenance. See `docs/module-repositories.md` and `examples/module-repository/index.json`.

## Recovery toolkit (1.12.1)

Framework 1.12.1 keeps the Recovery Toolkit self-contained under `/opt/tec-tac/scripts/recovery/`. Offline ZIP updates may discard executable mode bits, so the framework installer now repairs every recovery `*.sh` file to `0755` before sourcing or invoking it and verifies the result. No recovery commands are installed into `/usr/local/sbin`.

Run the common entry points with their framework-local paths:

```bash
sudo /opt/tec-tac/scripts/recovery/tec-tac-diagnostics.sh
sudo /opt/tec-tac/scripts/recovery/tec-tac-repair.sh
```

`tec-tac-repair.sh` provides diagnostics, Module Manager permission repair, module pair/state validation, explicit missing-module restoration from framework backups, runtime/bootstrap repair, and Scheduler repair. The **Run all safe repairs** option deliberately does not restore backups or reinstall the framework without a separate explicit action.

For automation/support workflows, the focused scripts support `--check` / `--repair`; diagnostics and permission checks also support machine-readable `--json` output.


## Installation layout (1.13.0+)

Tec-Tac separates replaceable Git source from installed runtime code:

```text
/opt/tec-tac-src/framework   # tac-net-rep Git checkout
/opt/tec-tac-src/ui          # tec-tac-ui Git checkout
/opt/tec-tac/framework       # live framework runtime
/opt/tec-tac/extensions      # installed extension code
/opt/tec-tac/reportsets      # installed reportsets
/opt/tec-tac/scripts         # installed admin/recovery scripts
/opt/tec-tac/etc/tec-tac.conf
/var/lib/tec-tac/ui/tec-tac  # compiled UI
```

Run `sudo bash scripts/migrate-layout.sh` once when upgrading a legacy installation where `/opt/tec-tac` or `/opt/tec-tac-ui` is still a Git checkout.

## User preferences (1.13.9)

Tec-Tac now stores durable per-user UI preferences server-side against the authenticated Tactical user. `GET`, `PUT`, and `DELETE /api/tfd/ui/preferences/` operate only on `request.user`, and `/api/tfd/ui/context/` includes the normalized preference profile and initialization metadata for efficient UI startup. See `docs/user-preferences.md`.

## Dashboards (1.14.0)

Core now persists user-owned dashboards. `private` dashboards are queryable only by their owner; `shared` dashboards are visible to all authenticated users. Owners may change visibility after creation. Shared dashboards may be managed by Tec-Tac administrators/server-maintenance roles, but other users' private dashboards remain outside their query set and only the owner may cross the shared/private visibility boundary.

Authenticated endpoints:

- `GET/POST /api/tfd/dashboards/`
- `GET/PUT/DELETE /api/tfd/dashboards/<uuid>/`

Dashboard layouts store bounded widget instance metadata while widget implementations remain UI-module contributions.

## Manifest-declared module licensing (1.14.1)

Extension manifests can require a live entitlement before Module Manager will stage/install them:

```json
{
  "licensing": {
    "required": true,
    "product": "reportmanager",
    "capability": "licensing.entitlements",
    "capability_version": ">=1.0.0,<2.0.0"
  }
}
```

Core resolves the declared capability and verifies entitlement during inspection and again when installation is requested. A prior successful inspection is never treated as proof of current entitlement. Missing, disabled, unhealthy, incompatible or unregistered providers, invalid provider contracts, provider errors and explicit license denials fail closed with a structured `403` response. The same gate applies to Module Management v2, online repository staging, bundles/batches and the compatibility v1 web install endpoints. See `docs/module-licensing.md`.


## Module lifecycle history (1.14.2)

Module Manager exposes `GET /api/tfd/modules/v2/jobs/` to review persistent lifecycle records, including status, action, affected module IDs, requesting user when known, errors and log tails.

## Core server backup capability (1.15.0)

Tec-Tac Core now exposes `core.server_backup` `1.x` for privileged
Tactical/Tec-Tac backup, restore, remote storage and retention operations.
Modules consume the typed capability through `tec_tac.capabilities`; they do
not receive arbitrary `sudo` or shell access. Core uses a root-owned opaque-job
helper, Tactical's normal backup/restore scripts, checksummed Tec-Tac payloads,
root-only credential references and typed local/SFTP/FTP/SCP/WebDAV/S3
adapters. See `docs/server-backup-capability.md`.


## Remote backup destination validation (1.15.1)

`core.server_backup` capability contract 1.1.0 adds `validate_destination(...)`.
The Core-owned privileged helper performs a job-unique write/read/SHA-256/delete
round trip using the same local/rclone/SCP adapters and opaque secret references
used by normal backup operations. Structured partial check results are preserved
on failure and no credential material is returned or logged. See
`docs/server-backup-capability.md`.

## Recovery bundles and restore modes (1.15.2)

`core.server_backup` capability contract `1.2.0` replaces the old archive-appending format with a portable `tec-tac-backup-*.tgz` recovery bundle. Tactical's native `rmm-backup-*.tar` remains byte-for-byte untouched inside `tactical/`; Tec-Tac filesystem/runtime state is stored independently as `tec-tac/tec-tac-backup.tar.gz`. The bundle supports `full`, `tactical`, and `tec_tac` recovery modes and exposes component/recovery-mode metadata through inventory. FTP/explicit-FTPS storage now uses Python `ftplib` rather than rclone. See `docs/server-backup-capability.md`.


## Server backup restore validation (1.15.3)

`core.server_backup` 1.3.0 adds a non-destructive, mode-aware `validate_restore()` readiness operation. See `docs/server-backup-capability.md`.

`core.server_backup` 1.4.0 adds auditable per-check restore overrides (initially `target.os`), enforces target preflight again in the destructive restore path, validates every newly-created Tactical-native TAR before bundling/upload, and provides a narrowly allow-listed privilege bridge for the root-owned files Tactical `backup.sh` collects.

## Mixed package + bundle batches (1.15.8)

Module Manager multi-file intake accepts standalone module packages and Tec-Tac bundle ZIPs in the same selection. Bundle members are flattened into one global dependency plan; dependency relationships can cross artifact boundaries, duplicate module IDs fail closed, and the resolved modules are installed sequentially through the existing rollback-safe lifecycle.

## Independent multi-package installs (1.15.4)

Module Manager batches do not require packages to have dependency relationships with one another. When several independent packages are uploaded together, the batch is valid and the original upload order is retained. Declared hard dependencies only constrain ordering for the packages involved in that dependency relationship.


## Tactical backup bridge ownership fix (1.15.9)

Privileged backup members collected by Core are now transferred to the Tactical service UID/GID at mode `0600` and verified before the helper returns, ensuring upstream `backup.sh` can archive them without making them broadly readable.


## Tactical nginx symlink backup fix (1.15.10)

Core server backup now safely resolves the three fixed Tactical nginx `sites-enabled` symlinks to regular files under `/etc/nginx/sites-available` before collecting them. This exception is limited to `rmm.conf`, `frontend.conf`, and `meshcentral.conf`; all other privileged backup inputs keep the strict no-symlink policy.


## Core server-backup observable job status (1.15.11)

`core.server_backup` 1.5.0 adds a read-only `get_job_status()` operation for module-owned progress UIs. Jobs can be looked up by the opaque Core `job_id` or the caller's `source_run_id`. Core returns only sanitized status, stage, timestamps, progress and bounded log-tail data; modules do not read `/var/lib/tec-tac/server-backup` directly. Backup creation now persists the major creation/validation/upload stages and selected Tactical privileged-collection sub-stages.


## TAR link-safe recovery validation (1.15.12)

`core.server_backup` 1.5.1 no longer rejects every TAR symlink/hardlink. Links are accepted only when both the member path and resolved target remain within the archive extraction namespace. Relative symlinks are resolved from the member parent and hardlinks from the archive root. Absolute/escaping links and unsafe special files remain blocked.


## Canonical recovery payload roots (1.15.14)

`core.server_backup` 1.5.2 canonicalizes Tec-Tac payload roots before TAR creation. Requested descendants already recursively covered by an included ancestor are removed, preventing duplicate normalized archive members. The redundant `/opt/tec-tac/etc` include was removed from the Tec-Tac component. Duplicate-member validation remains enabled and authoritative.

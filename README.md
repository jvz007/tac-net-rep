# TFD Tactical Reporting Extension

Upgrade-safe Django extension framework for Tactical RMM Report Manager.

## What this does

The installer adds the `tfdreporting` Django app without modifying Tactical's tracked source files. It relies on two persistence points that were validated against a real `update.sh --force` run on Tactical RMM 1.5.2:

- `/rmm/.git/info/exclude` protects the custom app directory from Tactical's `git clean -df` update step.
- `tacticalrmm/local_settings.py` is already ignored by Tactical and is used to install a small Django app-registry hook.

The app's `AppConfig.ready()` extends Tactical Report Manager's in-memory model registry, so `ee/reporting/constants.py` remains untouched.

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
    └── migrations/
        ├── __init__.py
        └── 0001_initial.py
```

## Install / upgrade

Clone the repository onto the Tactical server and run:

```bash
sudo ./install.sh
```

Running `install.sh` again updates the app code and loader idempotently.

The installer:

1. verifies the Tactical paths and Report Manager;
2. detects the Tactical service user from `rmm.service`;
3. protects `/rmm/api/tacticalrmm/tfdreporting/` in `.git/info/exclude`;
4. backs up `local_settings.py`;
5. installs/updates the TFD loader block;
6. installs the Django app;
7. runs `manage.py check`;
8. runs the app migrations;
9. verifies that Tactical Report Manager resolves `NetworkAvailability`;
10. restarts and validates `rmm`, `daphne`, `celery`, and `celerybeat`.

Backups of `local_settings.py` are kept under `/opt/tfd-tactical/backups/`, outside Tactical's Git checkout.

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

The current integration points are intentionally limited to:

- `/rmm/.git/info/exclude`
- `/rmm/api/tacticalrmm/tacticalrmm/local_settings.py`
- `/rmm/api/tacticalrmm/tfdreporting/`
- Django/PostgreSQL migrations for the TFD app

## Current model

`NetworkAvailability` currently provides:

- client name
- site name
- device name
- source
- timestamp
- status
- availability percentage
- latency milliseconds
- packet-loss percentage

This is the proof-of-concept schema. Future versions should add normalized Tactical client/site relationships and production ingestion workflows as those are designed.

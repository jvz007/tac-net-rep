# Tec-Tac Framework 1.12.0

Recovery and update-safety release.

## Framework update safety

- Preserves every dynamically installed `extensions/<id>` and `reportsets/<id>` tree during framework self-updates.
- Captures a pre-deploy digest inventory and aborts/rolls back if a managed module disappears or changes during framework deployment.
- Adds a regression test that performs an isolated framework deployment while verifying a dummy managed extension/reportset remains byte-for-byte intact.

## Module Manager hardening

- Repairs `staged`, `staged/bundles`, `staged/batches`, and `jobs` to `2770 root:<Tactical group>` on every framework install.
- Verifies the Tactical service identity can actually write every required staging path before installation completes.
- Multi-file inspection now classifies each uploaded artifact independently before dependency planning.
- Multi-file errors identify the filename that failed inspection.
- Unexpected staging filesystem failures now return structured JSON instead of an unhelpful raw Django HTML 500 page.

## Scheduler migration cleanup

- Adds `0003_scheduler_model_options` so `makemigrations tec_tac --dry-run --check` no longer reports the Scheduler configuration/state `Meta.verbose_name` drift introduced in 1.11.x.

## Tec-Tac Recovery Toolkit

Installed under `/opt/tec-tac/scripts/recovery/`:

- `tec-tac-diagnostics.sh` — read-only framework/UI, service, module, permission and migration checks.
- `tec-tac-repair-permissions.sh` — checks/repairs Module Manager runtime ownership, modes and Tactical write access.
- `tec-tac-repair-modules.sh` — validates extension/reportset pairs and persistent module state without deleting modules.
- `tec-tac-recover-modules-from-backup.sh` — restores only missing managed module trees from a selected/latest framework backup after taking a safety backup.
- `tec-tac-repair-runtime.sh` — validates Django/bootstrap/routes and can rerun the installed framework installer non-interactively when repair is required.
- `tec-tac-repair-scheduler.sh` — validates/repairs Scheduler systemd timer state and Celery task registration.
- `tec-tac-repair.sh` — interactive console menu and a safe-repairs option. Safe repair deliberately excludes backup restoration and framework reinstallation.

The framework installer consumes the same recovery permission contract so install and recovery behavior do not drift.

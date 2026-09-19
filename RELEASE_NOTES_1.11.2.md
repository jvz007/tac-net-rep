# Tec-Tac Framework 1.11.2

Corrective hardening release.

- Protects dynamically installed `extensions/<id>` and `reportsets/<id>` during framework self-updates.
- Takes a pre-deploy digest inventory and aborts/rolls back if any dynamic module disappears or changes during deployment.
- Adds migration `0003_scheduler_model_options` so Django no longer reports Scheduler model Meta drift.
- Improves multi-package inspection errors by identifying the exact uploaded filename that failed validation.
- Keeps package inspection independent per uploaded archive before dependency plan resolution.

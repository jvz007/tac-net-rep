# Tec-Tac 1.2.4

## Graceful extension lifecycle reload

- Extension install/remove no longer runs `systemctl restart rmm daphne celery celerybeat`.
- New `scripts/reload-rmm-uwsgi.sh` sends `SIGHUP` to the `rmm.service` uWSGI master and waits for the worker set to refresh.
- This refreshes Django's app registry, bootstrap state, URL configuration, and extension registry while keeping the `rmm` systemd unit alive.
- Lifecycle jobs therefore survive the reload and can continue into post-reload verification and UI synchronization.
- Daphne, Celery, and Celery Beat are left untouched for ordinary Django extension lifecycle operations.

## Production runtime permission repair

- `install.sh` now creates `/etc/systemd/system/rmm.service.d/tec-tac.conf`.
- The drop-in adds the Tactical user's primary group as a supplementary group to the production `rmm` process.
- This fixes API-driven package staging into `/var/lib/tec-tac/module-manager/` without making the runtime tree world-writable and without changing `/opt/tec-tac` ownership.
- The installer verifies both `SupplementaryGroups` and the live uWSGI process group membership after restart.
- `uninstall.sh` removes the Tec-Tac drop-in and reloads systemd.

## Existing 1.2.3 hardening retained

- Structured package-inspection diagnostics remain enabled.
- AppConfig/model/migration verification remains enabled.
- Fresh-process verification still runs after deployment.
- UI deployment verification remains part of asynchronous module jobs.
- Framework Swagger endpoints remain grouped under `Tec-Tac Framework`; extensions should use their display name as their own Swagger tag.

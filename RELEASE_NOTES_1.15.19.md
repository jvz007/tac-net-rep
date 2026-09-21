# Tec-Tac Framework 1.15.19

## Module identity rename-upgrades

- Adds explicit extension-manifest `migration.previous_module_ids` support.
- Module Manager classifies a deployed previous ID -> new ID transition as `rename` rather than a new install.
- Rename preflight blocks destination collisions, multiple installed previous IDs, unresolved dependant modules, unmapped persisted RBAC permissions and unmapped persisted scheduler actions.
- The privileged lifecycle transaction backs up both identities, removes the old registry roots, installs/verifies the new pair, migrates module state, RBAC grants, scheduler ownership/action IDs, mapped navigation routes and mapped dashboard widget IDs.
- Database identity changes are reversed and code/module-state restored if the lifecycle transaction fails.
- No permanent aliases are introduced. Historical scheduler run rows remain unchanged for audit history.

## Lifecycle runtime refresh hardening

- Tactical Celery runtime refresh now waits for an active service state and retries up to three times.
- Failed attempts record `systemctl status` and recent `journalctl` output in the lifecycle log before retrying.
- Applies to single-package install/remove and v2 bundle/batch lifecycle paths.

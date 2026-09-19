# Tec-Tac Framework 1.13.2

## System Update source/runtime hardening

- System Updates now require framework/UI source roots to be real, clean Git checkouts before replacement.
- Online release/branch updates move the source checkout to the exact GitHub commit resolved during staging instead of copying archive files over an unrelated Git index.
- Offline packages are committed to a dedicated local `tec-tac/offline/...` branch, keeping the source checkout clean and auditable.
- Failed updates restore the previous source branch/HEAD before reinstalling the previous version.
- Post-update verification now rejects a runtime containing `.git`, a source checkout that lost `.git`, a dirty source checkout, or a framework source/runtime path collision.
- Framework dynamic extension/reportset trees remain inventoried before install and verified after install and rollback.
- UI verification now follows `TEC_TAC_UI_DEPLOY_ROOT` from the authoritative Tec-Tac config.
- Source backups exclude Git metadata and disposable UI build directories (`node_modules`, `dist`) to avoid oversized self-update backups.
- The updater automatically removes the known untracked `package-lock.json` left by UI 0.10.4 and earlier only when Git confirms that file is not tracked.

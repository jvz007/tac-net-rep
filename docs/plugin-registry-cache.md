# Plugin registry cache (Core 1.17.96)

`tec_tac.registry` reads one `tec_tac.json` per module folder under `extensions/` and `reportsets/`. Reading and checking them all took about 70 ms, and Django start-up did it 122 times on the dev server (46 s). Since 1.17.96 each process keeps the answer and checks that nothing changed.

## What is cached

`discover_plugins()` with no arguments, `get_plugins()` and `get_plugin()` return the same validated, frozen `PluginSpec` objects until the files change. `get_plugin()` answers from an index built once. `discover_plugins(extensions_root, reportsets_root)` with explicit roots (the module manager staging check) is never cached. The results, their order and every error text are the same as before.

## How a change is seen

There is no time-based expiry. Every call re-checks a fingerprint, about two directory scans and one stat per module:

* the root folders and each module folder (name, modification time, inode);
* each `tec_tac.json` (mode, modification time, change time, size, inode);
* the extra paths a manifest depends on: `python_paths` folders other than the module root, and the `server_maintenance_actions` executables (each path part).

The root helper changes module files in another process. The fingerprint is the guard across processes. `registry.invalidate_plugin_cache()` only clears the cache of the current process at once. Core calls it when it queues a module install, upgrade, replace, bundle install, enable, disable, visibility change, removal, hotfix apply or rollback (`module_manager._dispatch`, `module_manager_v2._dispatch_v2`, `module_hotfix._dispatch`), and when module state is saved or a module is forgotten (`module_state.save_state`, `forget_module`).

## Fail closed

* A `RegistryError`, an `OSError` or a fingerprint read error is raised or bypasses the cache and is never stored. The next call reads again. A failed read is never kept as success.
* A validation error in `get_plugins()` (duplicate Django app, duplicate permission) is raised on every call.
* A file changed within 2 seconds of the read is not trusted: the result is returned but not stored, so a rewrite that keeps the same size inside one timestamp tick cannot be missed. A module installed a moment ago is read again on the next call.
* If something changes while the manifests are being read, nothing is stored.

## Not changed

The Scheduler keeps its own manifest signature cache (`scheduler._manifest_signature`, 1.17.81).

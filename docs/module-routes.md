# Module routes

**Since:** Core 1.17.16. **Needs:** framework >=1.17.16 in the module's `requires`.

A module can ask Core to serve its URLs. You add one key to `tec_tac.json`, and Core mounts the module's urlconf at `/api/tfd/<prefix>/`. The module no longer appends to `tacticalrmm.urls` or `tec_tac.urls` from its own `AppConfig.ready()`.

The old way keeps working. Nothing breaks if a module waits.

## The key

```json
"routes": {"prefix": "windows-patching", "urlconf": "tec_tac_patching.urls"}
```

| Field | Rule |
|---|---|
| `urlconf` | Required. A dotted Python path that sits inside one of the module's own `django_apps` packages. Never `tacticalrmm`, `tec_tac` or another module's package. |
| `prefix` | Optional. One lowercase slug: `a-z`, `0-9`, `_` and `-`, up to 64 characters, no slash. It defaults to the module id. It may differ from the id. |

Only extensions may declare `routes`. A reportset is refused. Core checks the key when it reads the manifest and again when the package is inspected for install, so a bad key is refused at install and not at the next start-up. The refusal text is plain English.

The URL shape is the one every module has today: `/api/tfd/<prefix>/...`.

## When and what Core mounts

- Core mounts after every `AppConfig.ready()` has run, in any process (web, Celery, shell). A module's urls are never imported before its own `ready()`.
- Core mounts only modules whose Django app is loaded. A disabled module is not mounted. An AD-20 replacement that Core dropped because it was enabled next to the module it replaces is not mounted either.
- Core appends the module after its own routes. A Core route always matches first, so a module prefix may share a first segment with a Core route. The `audit` module's prefix and Core's `audit/record/` is the example.

## Safety

- One module at a time. Core imports each urlconf inside its own `try/except`. A urlconf that cannot be imported is logged and skipped. The other modules and Tactical start as normal.
- Two loaded modules that ask for the same prefix: Core mounts the first by sorted module id and refuses the second, with a warning in the log.

## Compatibility path (no end date)

A module that still appends to `tec_tac.urls` (licensing, serverhealth, tacticalupdater, scriptmanager, globalsettings, patching, sentinelone) or to `tacticalrmm.urls` (the others) is untouched. Core skips any prefix that is already in `tec_tac.urls.urlpatterns` as `<prefix>/` or in Tactical's list as `api/tfd/<prefix>/`. It reports that prefix as `compat`.

So a module can add `routes` and forget to drop its own append, and it still works. When you drop the append, keep the same prefix so URLs do not change.

## Status

`tec_tac.route_mounting.mounted_routes()` returns what Core did, read only:

```python
[{"prefix": "windows-patching", "module": "patching", "state": "mounted", "reason": "Mounted by Core from the manifest routes key."}]
```

| `state` | Meaning |
|---|---|
| `mounted` | Core mounted it from the `routes` key. |
| `compat` | The module already adds this prefix itself, the old way. |
| `refused` | A duplicate prefix, or a urlconf that could not be loaded. `reason` says which. |

A module whose app is not loaded is not listed. The list covers the current process.

## What it does not do

- It does not move a module's permissions. Each view still uses Core's session guard and the module's own permission checks.
- It adds no migration and changes no existing URL.
- The contract export (`/api/tfd/contracts/`) lists Core's own HTTP routes only. A mounted module's routes are the module's contract, not Core's.

## The `description` key (Core 1.17.16)

`tec_tac.json` also accepts `description`: plain text of 1 to 500 characters with no control characters (no new lines or tabs). Extensions and reportsets may both declare it, and no module has to. Core shows it as `description` on the module catalogue rows, on the package inspect preview and on the runtime module rows. The value is `null` when the module declares none. A bad value is refused with a plain message, and a package with a bad value is refused at inspect.

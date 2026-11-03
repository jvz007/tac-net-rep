# Module updates (Core 1.17.104)

Core tells you when an installed module has a newer version. It doesn't install anything by itself. You still update a module from Settings → Modules → Online catalogue, through the normal install path with its signature, digest, compatibility and licence checks.

## What you see

* **A notice** for each new module version: "Module update available", with the old and new version and the level. Only superusers get it. Each version is announced once, even after you read or clear the notice.
* **The update list** (`GET /api/tfd/modules/updates/`, needs module management). Each row shows the module, installed version, new version, level, release-notes link, whether it can install now, and why not.
* **A badge count** (`GET /api/tfd/modules/updates/count/`).

## Levels

| Level | Example | Meaning |
|---|---|---|
| patch | 1.2.3 → 1.2.4 | fixes |
| minor | 1.2.3 → 1.3.0 | new features |
| major | 1.2.3 → 2.0.0 | larger changes; read the release notes first |
| other | 1.2.3 → 1.2.4-rc1, 1.2.3 → 1.2.4-2 | a pre-release, a rebuild or any version that isn't plain X.Y.Z |

## Why an update can't install yet

| Code | Message starts with | What to do |
|---|---|---|
| `core_required` | "Needs Tec-Tac Core ..." | Update Core first. |
| `ui_required` | "Needs the Tec-Tac UI ..." | Update the UI first. |
| `runtime_unknown` | "Needs ... which Core cannot check." | Ask the module's publisher. |
| `dependency_missing` | "Needs module ..., which is not installed." | Install that module first. |
| `dependency_update` | "Needs module ... Version ... is installed." | Update that module first. |
| `source_changed` | "The installed copy came from another repository." | Confirm the source change on the Online catalogue. |

New permissions aren't listed here. A repository index doesn't carry them, so the install preview shows them before you install.

## When Core checks

* After you press **Sync** or **Sync all** on the Repositories page. The check runs in the background, so the sync answers as quickly as before.
* After the daily repository sync at 03:00 (server time).

Core announces only releases from a repository whose last sync succeeded. When the server is offline, the licence is refused, a repository refuses its credentials or is retired, nothing new is announced. The update list still shows what the cached catalogue offers, marked `source_current: false`.

## Audit

The first detection of a version writes one audit row: action `custom:update-detected`, object type `module_update`, actor `system (module update detection)`.

## For module developers

`core.module_updates` 1.0.0: call `tec_tac.module_updates.updates_for_module()` from your module's own server-side code, after `has_capability('core.module_updates')`, and require framework `>=1.17.104`. It's open to **server modules only**: your module's catalog category must be `server`. It returns the same payload as the list route. Any other caller (a core, premium or test module, Core itself, a library) gets `caller_not_allowed` (403), and Core writes one `deny` audit row (object type `module_update`, at most one per caller and reason every 5 minutes).

A repository index entry may add `release_notes`: a link to the release notes, relative to the index or absolute. Core keeps it only when it's `https` with no credential, query, fragment or `;params`; any other link becomes null (1.17.105: it was stripped before). Core never fetches it.

## Troubleshooting

| You see | Cause | Fix |
|---|---|---|
| "Module updates could not be read. Check the module repositories, then try again." (503) | The catalogue cache couldn't be read. | Sync the repositories, then reload. Check the Core log for "module update". |
| No notice, but the list shows the update with `source_current: false` | The repository's last sync failed or its licence state isn't ok. | Fix the repository, then sync. |
| No notice, and `last_detection` is old | The check wasn't queued (Celery or the broker was down). | It runs again after the next sync or the daily sync. |

---
Tech Flow Dynamics · techxflow.co.za

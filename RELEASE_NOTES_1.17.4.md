# Tec-Tac Framework 1.17.4

This release does three things. The System Updates page can show the stable release beside a branch. `tec_tac.reporting` becomes a forwarding shim over Report Manager's registry. And Core ships the row-scope hook, so a report model can be limited to a person's clients and sites.

No module needs an edit to keep working. Every public name in `tec_tac.reporting` keeps its shape. See "Module-facing changes".

## Stable release shown under a branch source

The held Low from 1.17.3: with a branch source, `GET /system/updates/` still returned the cached stable release as `latest_release`.

- `online_status(component, force, source)` with a branch source keeps the branch as the primary answer and keeps `latest_release` `null`. It now also fetches the latest stable release and returns it as `stable_release`, with the same shape as `latest_release` (tag, name, publication date, link, commit, release trust, operation).
- It uses the same GitHub calls, the same 24-hour release cache and the same stale-on-error behaviour as a release source. `checked_at`, `cache` and `release_error` describe that release check.
- A release failure sets `release_error` only. A branch failure sets `branch_error` only and never hides `stable_release`. A failed cache write becomes `release_error`, not a server error.
- `cached_online_status(component, source=None)` takes the saved source. With a branch source it returns `latest_release` null, the cached row as `stable_release` (null when none is cached) and `source`. `system_status()` passes each component's saved source, so `GET /system/updates/` no longer serves the stale row as `latest_release`. The page can fill the secondary line on first load.
- A release source, or no source, returns exactly the 1.17.3 answer, with no `stable_release` key.

## Report Manager owns the registry: `tec_tac.reporting` becomes a shim (AD-15)

Report Manager 0.3.0 keeps the report-model registry as the `reportmanager.registry` capability. Core now forwards to it. Core keeps its own registry as the single record of every registration and validates exactly as before.

- **Stand-down.** When Report Manager 0.3.0 or later is installed and enabled, Core patches nothing at start-up. `reporting_bridge_status()["installed"]` stays false, no `_tec_tac_reporting_bridge` marker is set, and `handover` is true. Report Manager reads `installed` and the marker, so it sees Core standing down. In every other case Core's bridge installs as before.
- **Pending, then forwarded.** In a handover, `register_reporting_model` returns a row with `available` false and `state` `pending-report-manager`. It does not raise. Once the capability is available, the call forwards at once to `register_model(...)` with a context whose `source_module` is the module id and `source_action` is `reporting-shim`. After every `AppConfig.ready()` has run, in any process (web, Celery, shell), Core replays the pending registrations in id order.
- **Refusals.** A Report Manager validation state (`invalid`, `duplicate`, `not-owner`, `native-model-clash`, `unknown-provider`, `provider-disabled`, `model-unavailable`) removes the registration and raises `ReportingRegistrationError` with that `state`. An availability state (`row-scope-unavailable`, `bridge-unavailable`, `core-bridge-active`, `hidden-fields-unavailable`) keeps the registration, logs a warning and returns the row without raising. A caller's `ready()` never aborts.
- **`hidden_fields`.** `register_reporting_model` takes a new optional `hidden_fields` list. Status rows gain `hidden_fields`, `forwarded` and `row_scope`.
- **`unregister_reporting_model`** also removes a forwarded registration from Report Manager. `list_reporting_models` and `reporting_model_status` return Report Manager's live row for forwarded registrations and Core's row for pending ones.
- **`reporting_bridge_status()`** keeps every key and adds `owner`, `handover`, `fallback`, `forwarded_models`, `pending_models`, `row_scope_enforced` and `row_scope_models`. It is now part of the public contract.

### Where this deviates from the request, and why

The request says to stand down when Report Manager 0.3.0 is installed. The signed 0.3.0 patches no Tactical code. Its capability can never report that it owns the bridge, and every `register_model` call is refused. If Core stood down for good, the report models of seven modules would vanish from Tactical's report editor.

So Core stands down at start-up, then settles once every module has loaded:

- The capability is available: it owns the bridge, and the pending registrations are replayed to it.
- The capability is absent, or reports mode `core-bridge-active` or `unavailable`: Core takes its bridge back (`fallback` true). A pending registration that carries `hidden_fields` is refused (`hidden-fields-unavailable`), because Core's bridge cannot hide columns.
- The capability reports mode `report-manager` but is unhealthy: nothing changes and the status shows the error. Two bridges never patch the same names.

With Report Manager 0.3.0 installed today, the visible result is today's behaviour. Core's bridge is installed again and Report Manager reports `core-bridge-active`. The real handover happens with no further Core change when Report Manager ships the release that owns the bridge. This also keeps the earlier request that Core does not remove its bridge before the owning release is signed. It is Johan's call, and it is in `reviews/questions/core.md` as CQ13.

`tec_tac.reporting` is removed after every module in `modules/` has switched. No date is promised (CQ14).

The installer self-check (`install.sh`, `VERIFY_REPORTING_CODE`) now accepts a handover or a fallback. It asserts the markers only when the bridge is installed.

## Row-scope hook for report models

Tactical's report engine scopes a query by the person's clients and sites only when the model's manager has `filter_by_role`. A registered model has none, so a scoped person sees every row. Core cannot attach the method to a module's manager after the fact, so Core ships the manager and the module adopts it.

- `scoped_report_manager(*, client=None, site=None, include_unassigned=False)` returns a Django manager. Its `filter_by_role(user)` follows Tactical's rules. A superuser, or a role with neither `can_view_clients` nor `can_view_sites`, sees all rows. No role sees none. Otherwise a row shows when its client path is in the granted client ids, or its site path is in the visible site ids (granted sites plus the sites of granted clients). A row with no client or site is hidden unless `include_unassigned` is true. A model that declares neither path shows no rows to a scoped person.
- Tactical uses it as the base queryset before every operation, aggregates included, so a filter cannot get around it. It works whichever bridge serves the model.
- Tactical falls back to an unscoped queryset when `filter_by_role` raises. Core's version never raises. Any failure returns no rows.
- `model_row_scope(app_label, model)` returns `{enforced, source, client_field, site_field, include_unassigned}`. It is true only when Core's manager is in place, not overridden, and the declared paths resolve. Every status row carries it as `row_scope`.
- `reporting_bridge_status()["row_scope_enforced"]` is always true. It means "Core offers the hook", not "every registered model is scoped". The per-model truth is `row_scope.enforced`. `row_scope_models` lists the enforced and unscoped registration ids.
- New helper `report_scope_ids(user)` in `resources_adapter.py` returns `{unrestricted, client_ids, site_ids}` (and `denied` for a user with no role). It reuses the same role rules as the Scheduler and does not load the agent list.

**What stays open.**

- A model that does not adopt the manager stays registered in Core's own bridge, with `row_scope.enforced` false, as before. A scoped person already sees every row of it, so the status makes the gap visible without hiding anything. Report Manager's registry refuses such models when it owns the bridge (CQ16).
- A report run with no signed-in user is unscoped by Tactical itself. Tactical's Celery schedule runner calls `run_scheduled_report` with no user, for native models too. Core cannot scope it without an owner for the run. This is a data-exposure question for Johan (CQ15).
- A visible row still shows its own columns. `hidden_fields` is a separate control.

What remains is module work. Each report model adopts `scoped_report_manager`. Report Manager's owning release reads `model_row_scope` and sets `ROW_SCOPE_ENFORCED`. Those requests are in `reviews/requests/core-modules.md` and `reviews/requests/premium-modules.md`.

## Module-facing changes

- **`tec_tac.reporting`**
  - New optional `hidden_fields` argument on `register_reporting_model`. Status rows gain `hidden_fields`, `forwarded` and `row_scope`. Existing keys are untouched.
  - `ReportingRegistrationError` carries `state`.
  - Pending and forwarded behaviour as above. During a handover a registration returns a `pending-report-manager` row instead of an available one. Core's own bridge exposes nothing in that window.
  - New public names: `reporting_bridge_status` (new keys above), `scoped_report_manager`, `model_row_scope`.
  - The shim is removed after every module has switched. Callers today: `alerts`, `checks`, `cyberhoot`, `huntress`, `patchmanagement`, `scoutdns` and `scriptexecution` (the request lists six; `scriptexecution` calls it from `AppConfig._register_reporting`). All keep working with no edit.
- **`tec_tac.bootstrap`** settles the handover after `Apps.populate` in every process. A failure there is logged and never stops start-up.
- **HTTP.** `GET /api/tfd/system/updates/online/` adds `stable_release` under a branch source, and `release_error` can now be non-null there. `GET /api/tfd/system/updates/` returns `release_cache[component]` with `latest_release` null, `stable_release` and `source` under a branch source. No module uses these routes. The only consumer is the Core UI shell, whose request for `stable_release` is in `reviews/requests/ui.md`.
- **Installer.** The reporting self-check accepts a handover or a fallback.

## Tests

- New `tests/update-source-1.17.4.py`: the branch answer with `stable_release`, cache use and `force`, release and branch failures kept apart, a cache write failure, the key sets, the unchanged release answer, `cached_online_status` and `system_status` under a branch source, and the contract entries and docs.
- Amended `tests/update-source-1.17.3.py` and `tests/update-source-1.17.2.py` to the 1.17.4 behaviour, with a comment naming the version.
- New `tests/reporting-handover-1.17.4.py`: the real `reporting.py` against stubs. Report Manager absent, disabled and older; the stand-down; pending and replay in id order with `hidden_fields` and context; the fallback in five capability states; the unhealthy `report-manager` case; the refusal mapping; unregister; a late call; the status keys; the contract entries; and the installer self-check run against each state.
- New `tests/reporting-row-scope-1.17.4.py`: `report_scope_ids`, the spec builder, path validation, the manager's built filter, fail-closed behaviour and `model_row_scope`.
- Extended `tests/startup-safety.py`: settle is called once after the original populate, the original result is returned when settle raises, and no settle runs when populate fails.
- `tests/reporting-registration-foundation.sh` passes untouched. `tests/contracts-foundation.sh` stops on this Windows PC in an earlier check (`fcntl`), so its reporting greps were run by hand and match.

Django is not installed on the development PC. These could not run here:

- `tests/reporting-registration-runtime.py` (needs `manage.py shell` on a server). Run it on the dev server after the update.
- New `tests/reporting-row-scope-runtime-1.17.4.py`. It builds a real scoped model over Tactical's `clients_site` table for a client-restricted, a site-restricted, an unrestricted and a no-role user. It compares each result with Tactical's own Site rule and runs Tactical's real `build_queryset`. Everything is rolled back. Run it on the dev server.
- The live handover on the dev server: with Report Manager 0.3.0 installed, `reporting_bridge_status()` should show `handover` true and `fallback` true, with Core's bridge installed again.

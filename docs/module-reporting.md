# Tec-Tac Report Manager registration contract

Tec-Tac Core owns the compatibility boundary with Tactical Report Manager. Module and reportset code must not import `ee.reporting.*`, mutate Tactical `REPORTING_MODELS`, edit Tactical tracked source, or rewrite `static/reporting/schemas/query_schema.json`.

## Provider registration

Register report-facing models from the provider module/reportset `AppConfig.ready()`:

```python
from django.apps import AppConfig


class ScoutDNSConfig(AppConfig):
    name = "tec_tac_scoutdns"

    def ready(self):
        from tec_tac.reporting import register_reporting_model

        register_reporting_model(
            module_id="scoutdns",
            app_label="tec_tac_scoutdns",
            model="ScoutDNSReportDataset",
            display_name="ScoutDNS Report Dataset",
            description="ScoutDNS reporting dataset exposed to Tactical Report Manager.",
        )
```

`reporting_id` is optional. When omitted Core generates `<module-id>.<model-name-lowercase>`, for example `scoutdns.scoutdnsreportdataset`.

Optional metadata:

- `display_name`
- `description`
- `field_metadata` for public contract/discovery metadata
- `reporting_id` when a stable explicit public identifier is required

## Runtime behavior

Core synchronizes the registration with Tactical's in-memory reporting allow-lists and dynamically augments Tactical's existing Report Manager query-schema response. Tactical's native static schema file remains untouched.

The native Report Manager query schema remains the base. Core only appends currently available Tec-Tac models. This avoids schema regeneration during normal module installation and update.

Module lifecycle is authoritative:

- enabled provider -> registration is available;
- disabled provider -> registration is unavailable and omitted from the live schema;
- re-enabled provider -> `AppConfig.ready()` registration returns after lifecycle runtime reload;
- removed provider -> registration disappears with the provider runtime;
- explicit `unregister_reporting_model(...)` removes the entry and resynchronizes runtime allow-lists immediately.

The Module Manager already performs a runtime reload for enable/disable/install/update/remove operations, so the reporting registry is rebuilt from the enabled provider set at the same lifecycle boundary.

## Query identity

Tactical Report Manager addresses data sources by Django model name, not `(app_label, model)` pair. Core therefore requires Tec-Tac report-facing model names to be globally unique in addition to rejecting duplicate public reporting IDs and duplicate `(app_label, model)` registrations.

A Tec-Tac model also may not shadow a Tactical native reporting model name.

## Public API

```python
from tec_tac.reporting import (
    register_reporting_model,
    unregister_reporting_model,
    list_reporting_models,
    reporting_model_status,
    reporting_bridge_status,
    scoped_report_manager,
    model_row_scope,
    ReportingRegistrationError,
)
```

`list_reporting_models()` returns provider module/version, Django model identity, availability/state, queryable fields when available, and descriptive metadata.

`reporting_model_status(reporting_id)` resolves one public registration without importing Tactical internals.

## ScoutDNS migration target

ScoutDNS should remove direct writes/imports involving:

```text
ee.reporting.constants.REPORTING_MODELS
ee.reporting.utils.REPORTING_MODELS
```

and replace them with:

```python
register_reporting_model(
    module_id="scoutdns",
    app_label="tec_tac_scoutdns",
    model="ScoutDNSReportDataset",
)
```

The model will then resolve in Tactical report queries and appear in the live Report Manager query schema/editor through Core.

## Report Manager owns the registry (1.17.4)

Report Manager 0.3.0 keeps the report-model registry as the `reportmanager.registry` capability (AD-15). From 1.17.4 `tec_tac.reporting` is a **forwarding shim**. Every public name and shape above stays, so no caller needs an edit to keep working.

Core keeps its own registry as the single record of every registration. It validates exactly as before, and raises `ReportingRegistrationError` for the same cases. The error now carries a `state`: `invalid`, `duplicate`, `not-owner`, `native-model-clash`, `unknown-provider`, `provider-disabled` or `model-unavailable`.

### Who patches Tactical

| Situation at start-up | Who patches Tactical |
|---|---|
| Report Manager is not installed, is disabled, or is older than 0.3.0 | Core, as before. `reporting_bridge_status()["installed"]` is true and the `_tec_tac_reporting_bridge` markers are set. |
| Report Manager 0.3.0 or later is installed and enabled | Core stands down. It patches nothing: `installed` is false, no marker is set, `handover` is true. Report Manager reads `installed` and the marker, so it sees Core standing down. |

After every module has loaded (in every process: web, celery and `manage.py shell`), Core settles the handover once:

- **The capability is available.** Report Manager reports healthy only when it owns the bridge. Core replays every pending registration to it, in id order. `owner` becomes `reportmanager`.
- **The capability is absent, or reports mode `core-bridge-active` or `unavailable`.** Report Manager is not the owner of the bridge. Core takes its own bridge back, so no report model disappears. `fallback` becomes true, `installed` becomes true, and the pending registrations are served as before. Registrations already forwarded to Report Manager before the fallback (1.17.5) are served the same way: Core clears its forwarded set, installs its bridge, and `owner` reads `core` with `forwarded_models` 0. A registration that carries `hidden_fields`, pending or formerly forwarded, is refused (`hidden-fields-unavailable`) and logged, because Core's bridge cannot hide columns. At the fallback (1.17.6), Core also makes a best-effort `unregister_model` call to Report Manager for each formerly forwarded registration, in id order, with the module's own `source_module` context, so Report Manager does not keep a row Core now serves. A failure is logged and does not stop the others or the bridge install. If Report Manager's registry cannot be reached, Core logs one warning and moves on. After the fallback, `unregister_reporting_model` makes no further call to Report Manager for them.
- **The capability reports mode `report-manager` but is unhealthy.** Nothing changes. The status shows the error, so two bridges never patch the same names.

Report Manager 0.3.0 patches no Tactical code, so today the visible result with 0.3.0 installed is the fallback: Core's bridge is installed again and Report Manager reports `core-bridge-active`. The real handover happens, with no further Core change, when Report Manager ships the release that owns the bridge.

### What a caller sees during a handover

- `register_reporting_model(...)` before the settle returns a status row with `available` false and `state` `pending-report-manager`. It does not raise.
- When the capability is available, the call forwards at once to `register_model(module_id, app_label, model, reporting_id, display_name, description, field_metadata, hidden_fields, context)`. The context is `build_operation_context(source_module=<module_id>, source_action="reporting-shim")`.
- A **validation** refusal from Report Manager (`invalid`, `duplicate`, `not-owner`, `native-model-clash`, `unknown-provider`, `provider-disabled`, `model-unavailable`) removes the registration and raises `ReportingRegistrationError` with that `state`.
- An **availability** refusal (`row-scope-unavailable`, `bridge-unavailable`, `core-bridge-active`, `hidden-fields-unavailable`) keeps the registration, logs a warning and returns the row with that state. It does not raise, so a caller's `ready()` never aborts.
- `unregister_reporting_model` also removes a forwarded registration from Report Manager.
- `list_reporting_models()` and `reporting_model_status()` return Report Manager's live row for forwarded registrations, and Core's computed row for pending ones.

### `hidden_fields`

`register_reporting_model(..., hidden_fields=["secret_token"])` names columns Report Manager must hide and refuse. It is a list of field or property names. Core's own bridge cannot enforce it, so a model that asks for hidden columns is served only through Report Manager. Under Core's bridge its row reads `hidden-fields-unavailable` and the model is not exposed. Hidden columns are a separate control from row scope: a row that is visible still shows its other columns.

### `reporting_bridge_status()`

Every earlier key is kept (`available`, `installed`, `error`, `native_models`, `tec_tac_models`, `total_models`, `dynamic_schema`). It adds:

| Key | Meaning |
|---|---|
| `owner` | `core`, `reportmanager`, or `pending` (handover, not yet settled or unhealthy) |
| `handover` | Report Manager 0.3.0 or later was enabled at start-up, so Core did not patch Tactical |
| `fallback` | Core took its bridge back at settle |
| `bridge_error`, `handover_error` | 1.17.5, additive. `bridge_error` is Core's own bridge error or null. `handover_error` is set when Report Manager owns the bridge but reports unhealthy, or null. `error` is unchanged and equals `bridge_error or handover_error`. The installer fails only on `bridge_error`, so a healthy Core is not rolled back because Report Manager is unhealthy. |
| `forwarded_models`, `pending_models` | Counts of registrations Report Manager holds, and registrations still waiting |
| `row_scope_enforced` | Always true: Core offers the scope hook (see below). It does not mean every registered model is scoped |
| `row_scope_models` | `{enforced, unscoped}`: registration ids, by the per-model truth |

The call never reads Report Manager back, so the two can read each other without looping.

### How a module switches

Switch only after Report Manager's owning release and this Core release are signed. Until then, keep calling `tec_tac.reporting`.

```python
from tec_tac.capabilities import get_capability, has_capability

if has_capability("reportmanager.registry"):
    registry = get_capability("reportmanager.registry")
    registry.register_model(
        module_id="scoutdns",
        app_label="tec_tac_scoutdns",
        model="ScoutDNSReportDataset",
        hidden_fields=["api_secret"],
        context={"source_module": "scoutdns", "source_action": "ready"},
    )
```

Declare Report Manager as an optional dependency. The argument names and status row keys are the same as the shim's, so a switch is a rename. Report Manager's registry accepts only the module's own apps (`tec_tac_<module>`) and refuses a model whose rows are not scoped (see below).

### Registration-order guarantee

Registrations that arrive before Report Manager's capability exists are held and replayed in id order after every `AppConfig.ready()` has run. A registration that arrives later, once the capability is available, is forwarded at once and replays any older pending ones first. Callers need no ordering between their own `ready()` and Report Manager's.

### Removal of the shim

`tec_tac.reporting` is removed after every module in `modules/` has switched. No date is promised.

## Row scope for registered models (1.17.4)

Tactical's report engine limits a query to the person's clients and sites only when the model's manager has `filter_by_role`. It uses `Model.objects.filter_by_role(user)` as the base queryset before every operation, aggregates included, so no filter-order bypass exists. A registered model has no such method, so a scoped person sees every row of it.

Core ships the manager. The module adopts it:

```python
from tec_tac.reporting import scoped_report_manager


class ScoutDNSReportDataset(models.Model):
    client_id = models.IntegerField(null=True)
    site_id = models.IntegerField(null=True)
    objects = scoped_report_manager(client="client_id", site="site_id")
```

Core cannot attach the method to a module's manager after the fact. A manager-class change would reach every model that shares the class, and Django discards an instance attribute when it expires its manager cache. That is why the module declares it. It works whichever bridge serves the model, because Core patches nothing for the scope.

`scoped_report_manager(*, client=None, site=None, include_unassigned=False)` takes ORM lookup paths such as `client_id`, `site_id` or `agent__site__client_id`. A path is letters, digits and single underscores, joined by `__`. Anything else is refused.

Its `filter_by_role(user)` follows Tactical's rules:

- A superuser, a role-level superuser, or a role with neither `can_view_clients` nor `can_view_sites` sees every row.
- A user with no role sees no rows.
- Otherwise a row shows when its client path is in the explicitly granted client ids, or its site path is in the visible site ids (granted sites plus the sites of granted clients).
- A site-only grant never widens a client path. The row stays hidden.
- A row with no client or site is hidden unless `include_unassigned` is true.
- A model that declares neither path shows no rows to a scoped person (fail closed).
- Tactical falls back to an unscoped queryset when `filter_by_role` raises, so Core's version never raises. Any failure returns no rows.

Core resolves the ids with `tec_tac.resources_adapter.report_scope_ids(user)`, which returns `{unrestricted, client_ids, site_ids}`. It reuses the same role rules as the Scheduler and does not load the agent list.

### Reading the result

`model_row_scope(app_label, model)` returns `{enforced, source, client_field, site_field, include_unassigned}`. `enforced` is true only when `Model.objects.filter_by_role` is Core's scoped implementation (not overridden) and the declared paths resolve on the model. `source` is `core`, `model` (a manager with its own `filter_by_role`, which Core cannot vouch for) or null. Every status row carries it as `row_scope`.

`reporting_bridge_status()["row_scope_enforced"]` is the signal Report Manager reads to set its `ROW_SCOPE_ENFORCED`. It means Core offers the hook. The per-model truth is `row_scope.enforced`. `row_scope_models` lists which registered models are scoped and which are not.

### Compatibility

A registered model that does not adopt the manager stays registered in Core's own bridge, with `row_scope.enforced` false in its row, as before. A scoped person already sees every row of such a model, so the status makes the gap visible without hiding anything. Report Manager's registry refuses such models when it owns the bridge (AD-15, condition 3).

### Limits

- A report run with no signed-in user is unscoped by Tactical itself. Tactical's Celery schedule runner calls `run_scheduled_report` with no user, for native models too. Core cannot scope it without an owner for the run. This is open for Johan's decision.
- A row that is visible still shows its own columns. Use `hidden_fields` to hide columns.

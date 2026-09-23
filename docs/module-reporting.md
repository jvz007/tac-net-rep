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

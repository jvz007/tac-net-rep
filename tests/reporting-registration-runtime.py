"""Runtime regression for the Core Tactical Report Manager bridge.

Run through Tactical manage.py shell so Django and EE Report Manager are loaded.
"""
from copy import deepcopy

from ee.reporting import constants as reporting_constants
from ee.reporting import utils as reporting_utils
from ee.reporting import views as reporting_views
from django.conf import settings as django_settings
import json

from tec_tac import reporting
from tec_tac.contracts import build_contract_catalog

native = tuple(reporting_constants.REPORTING_MODELS)
original_provider_status = reporting._provider_status


def provider(enabled=True):
    return {
        "installed": True,
        "enabled": enabled,
        "version": "9.9.9",
        "state": "available" if enabled else "disabled",
    }

try:
    reporting._provider_status = lambda module_id: provider(True)
    row = reporting.register_reporting_model(
        module_id="foundation-reporting-test",
        app_label="tec_tac",
        model="TecTacSchedule",
        reporting_id="foundation-reporting-test.schedule",
        display_name="Foundation Schedule",
        description="Runtime bridge regression model.",
    )
    assert row["available"] is True, row
    assert ("TecTacSchedule", "tec_tac") in reporting_constants.REPORTING_MODELS
    assert reporting_constants.REPORTING_MODELS == reporting_utils.REPORTING_MODELS

    # Tactical query resolution must use the registered model without the test
    # importing or editing any Tactical allow-list itself.
    resolved = reporting_utils.resolve_model(data_source={"model": "TecTacSchedule"})
    assert resolved["model"]._meta.app_label == "tec_tac"
    assert resolved["model"].__name__ == "TecTacSchedule"

    base = {
        "type": "object",
        "properties": {"model": {"type": "string", "enum": ["agent"]}},
        "required": ["model"],
        "oneOf": [{"properties": {"model": {"type": "string", "enum": ["agent"]}}}],
    }
    before = deepcopy(base)
    augmented = reporting.augment_query_schema(base)
    assert base == before, "native schema object was mutated"
    assert "agent" in augmented["properties"]["model"]["enum"]
    assert "tectacschedule" in augmented["properties"]["model"]["enum"]

    # Validate the actual Tactical Report Manager schema view is augmented while
    # its tracked/static JSON file remains byte-for-byte unchanged.
    schema_path = django_settings.BASE_DIR / "static/reporting/schemas/query_schema.json"
    schema_before = schema_path.read_bytes()
    schema_response = reporting_views.QuerySchema().get(None)
    schema_payload = json.loads(schema_response.content.decode("utf-8"))
    assert "tectacschedule" in schema_payload["properties"]["model"]["enum"]
    assert schema_path.read_bytes() == schema_before, "Core rewrote Tactical query_schema.json"

    catalog = build_contract_catalog()
    match = [item for item in catalog["reporting_models"] if item["id"] == "foundation-reporting-test.schedule"]
    assert len(match) == 1 and match[0]["available"] is True

    try:
        reporting.register_reporting_model(
            module_id="foundation-reporting-test",
            app_label="tec_tac",
            model="TecTacSchedule",
            reporting_id="foundation-reporting-test.schedule",
        )
    except reporting.ReportingRegistrationError:
        pass
    else:
        raise AssertionError("duplicate public reporting ID did not fail")

    try:
        reporting.register_reporting_model(
            module_id="foundation-reporting-test",
            app_label="tec_tac",
            model="TecTacSchedule",
            reporting_id="foundation-reporting-test.schedule-two",
        )
    except reporting.ReportingRegistrationError:
        pass
    else:
        raise AssertionError("duplicate (app_label, model) registration did not fail")

    # Disable must become unavailable immediately even before a lifecycle reload.
    reporting._provider_status = lambda module_id: provider(False)
    disabled = reporting.reporting_model_status("foundation-reporting-test.schedule")
    assert disabled["available"] is False and disabled["state"] == "disabled", disabled
    disabled_schema = reporting.augment_query_schema(base)
    assert "tectacschedule" not in disabled_schema["properties"]["model"]["enum"]
    disabled_response = reporting_views.QuerySchema().get(None)
    disabled_payload = json.loads(disabled_response.content.decode("utf-8"))
    assert "tectacschedule" not in disabled_payload["properties"]["model"]["enum"]
    try:
        reporting_utils.resolve_model(data_source={"model": "TecTacSchedule"})
    except reporting_utils.ResolveModelException:
        pass
    else:
        raise AssertionError("disabled provider still resolved through Tactical Report Manager")

    reporting._provider_status = lambda module_id: provider(True)
    enabled = reporting.reporting_model_status("foundation-reporting-test.schedule")
    assert enabled["available"] is True, enabled
    resolved = reporting_utils.resolve_model(data_source={"model": "TecTacSchedule"})
    assert resolved["model"].__name__ == "TecTacSchedule"

    assert reporting.unregister_reporting_model("foundation-reporting-test.schedule") is True
    assert reporting.reporting_model_status("foundation-reporting-test.schedule")["state"] == "missing"
    assert reporting_constants.REPORTING_MODELS == native, (reporting_constants.REPORTING_MODELS, native)
    assert reporting_utils.REPORTING_MODELS == native
finally:
    reporting._provider_status = original_provider_status
    reporting.unregister_reporting_model("foundation-reporting-test.schedule")
    reporting.sync_tactical_reporting_models()

print("[TEST] PASS Core reporting registration runtime")

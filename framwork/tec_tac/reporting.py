"""Core-owned Tec-Tac integration with Tactical Report Manager.

Tec-Tac modules register report-facing Django models here instead of importing
``ee.reporting`` internals. Core owns the compatibility bridge that keeps
Tactical's in-memory allow-lists and query-schema endpoint synchronized while
leaving Tactical tracked source and its native static schema untouched.
"""
from __future__ import annotations

import copy
import inspect
import json
import logging
import re
import sys
import threading
from dataclasses import dataclass, field
from typing import Any

from django.apps import apps as django_apps

logger = logging.getLogger("tec_tac.reporting")

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,159}$")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class ReportingRegistrationError(ValueError):
    """Invalid or conflicting reporting-model registration."""


@dataclass(frozen=True)
class ReportingModelRegistration:
    id: str
    module_id: str
    app_label: str
    model: str
    display_name: str = ""
    description: str = ""
    field_metadata: dict[str, Any] = field(default_factory=dict)


_LOCK = threading.RLock()
_REGISTRY: dict[str, ReportingModelRegistration] = {}
_PAIR_INDEX: dict[tuple[str, str], str] = {}
_MODEL_INDEX: dict[str, str] = {}
_NATIVE_REPORTING_MODELS: tuple[tuple[str, str], ...] | None = None
_BRIDGE_INSTALLED = False
_BRIDGE_ERROR = ""
_ORIGINAL_QUERY_SCHEMA_GET = None
_ORIGINAL_RESOLVE_MODEL = None


def _clean_id(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _ID_RE.fullmatch(text):
        raise ReportingRegistrationError(f"{label} must be a lowercase Tec-Tac identifier.")
    return text


def _clean_name(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _NAME_RE.fullmatch(text):
        raise ReportingRegistrationError(f"{label} must be a valid Django identifier.")
    return text


def _provider_status(module_id: str) -> dict[str, Any]:
    if module_id == "core":
        return {"installed": True, "enabled": True, "version": _framework_version(), "state": "available"}
    try:
        from .module_state import is_enabled, load_state
        from .registry import get_plugins

        matches = [
            item for item in get_plugins()
            if item.plugin_id == module_id and item.plugin_type in {"extension", "legacy"}
        ]
        if len(matches) != 1:
            return {"installed": False, "enabled": False, "version": None, "state": "missing"}
        plugin = matches[0]
        enabled = True if plugin.plugin_type == "legacy" else bool(is_enabled(module_id, load_state()))
        return {
            "installed": True,
            "enabled": enabled,
            "version": str(plugin.version or "0.0.0"),
            "state": "available" if enabled else "disabled",
        }
    except Exception as exc:
        return {
            "installed": False,
            "enabled": False,
            "version": None,
            "state": "provider-state-error",
            "reason": f"{exc.__class__.__name__}: {exc}",
        }


def _framework_version() -> str:
    try:
        from .registry import TEC_TAC_ROOT
        return (TEC_TAC_ROOT / "VERSION").read_text(encoding="utf-8").strip() or "unknown"
    except Exception:
        return "unknown"


def _resolve_model_class(app_label: str, model: str):
    try:
        return django_apps.get_model(app_label=app_label, model_name=model)
    except (LookupError, ValueError):
        return None


def _native_models() -> tuple[tuple[str, str], ...]:
    global _NATIVE_REPORTING_MODELS
    if _NATIVE_REPORTING_MODELS is not None:
        return _NATIVE_REPORTING_MODELS
    try:
        from ee.reporting import constants as reporting_constants
        _NATIVE_REPORTING_MODELS = tuple(reporting_constants.REPORTING_MODELS)
    except Exception:
        _NATIVE_REPORTING_MODELS = ()
    return _NATIVE_REPORTING_MODELS


def _native_model_names() -> set[str]:
    return {str(model).lower() for model, _ in _native_models()}


def _registration_status(registration: ReportingModelRegistration) -> dict[str, Any]:
    provider = _provider_status(registration.module_id)
    state = provider.get("state") or "unavailable"
    reason = provider.get("reason")
    available = bool(provider.get("installed") and provider.get("enabled"))
    model_class = None
    if available:
        model_class = _resolve_model_class(registration.app_label, registration.model)
        if model_class is None:
            available = False
            state = "model-unavailable"
            reason = f"Django model {registration.app_label}.{registration.model} is not loaded."
    if available and _BRIDGE_ERROR:
        available = False
        state = "bridge-unavailable"
        reason = _BRIDGE_ERROR

    fields = []
    if model_class is not None:
        try:
            fields = [field.name for field in model_class._meta.get_fields() if not field.many_to_many and not field.one_to_many]
        except Exception:
            fields = []

    return {
        "id": registration.id,
        "module_id": registration.module_id,
        "module_version": provider.get("version"),
        "app_label": registration.app_label,
        "model": registration.model,
        "display_name": registration.display_name or registration.model,
        "description": registration.description,
        "field_metadata": copy.deepcopy(registration.field_metadata),
        "fields": fields,
        "queryable_fields": fields,
        "available": available,
        "state": "available" if available else state,
        "reason": reason,
    }


def reporting_model_status(reporting_id: str) -> dict[str, Any]:
    """Return live availability for one public reporting-model registration."""
    key = _clean_id(reporting_id, "reporting_id")
    with _LOCK:
        registration = _REGISTRY.get(key)
    if registration is None:
        return {
            "id": key,
            "available": False,
            "state": "missing",
            "reason": f"Reporting model {key!r} is not registered.",
        }
    return _registration_status(registration)


def list_reporting_models(*, include_unavailable: bool = True) -> list[dict[str, Any]]:
    """List registered Tec-Tac reporting models and their live provider state."""
    with _LOCK:
        registrations = sorted(_REGISTRY.values(), key=lambda item: item.id)
    rows = [_registration_status(item) for item in registrations]
    if not include_unavailable:
        rows = [row for row in rows if row["available"]]
    return rows


def _active_pairs() -> tuple[tuple[str, str], ...]:
    rows = []
    with _LOCK:
        registrations = list(_REGISTRY.values())
    for item in registrations:
        if _registration_status(item)["available"]:
            rows.append((item.model, item.app_label))
    rows.sort(key=lambda pair: (pair[0].lower(), pair[1].lower()))
    return tuple(rows)


def sync_tactical_reporting_models() -> dict[str, Any]:
    """Synchronize Core's live registry into Tactical's in-memory allow-lists."""
    native = _native_models()
    active = _active_pairs()
    combined = tuple([*native, *active])
    from ee.reporting import constants as reporting_constants
    from ee.reporting import utils as reporting_utils

    reporting_constants.REPORTING_MODELS = combined
    reporting_utils.REPORTING_MODELS = combined
    generator = sys.modules.get("ee.reporting.management.commands.generate_json_schemas")
    if generator is not None:
        generator.REPORTING_MODELS = combined
    return {"native": len(native), "tec_tac": len(active), "total": len(combined)}


def register_reporting_model(
    *,
    module_id: str,
    app_label: str,
    model: str,
    reporting_id: str | None = None,
    display_name: str | None = None,
    description: str | None = None,
    field_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Register one module-owned Django model with Tactical Report Manager.

    Registration is process-local by design and should be called from the
    provider module/reportset ``AppConfig.ready()``. Module lifecycle reloads
    rebuild the registry from the currently enabled module set.
    """
    module_key = _clean_id(module_id, "module_id")
    app_key = _clean_name(app_label, "app_label")
    model_name = _clean_name(model, "model")
    public_id = _clean_id(reporting_id or f"{module_key}.{model_name.lower()}", "reporting_id")
    metadata = field_metadata or {}
    if not isinstance(metadata, dict):
        raise ReportingRegistrationError("field_metadata must be an object when provided.")

    provider = _provider_status(module_key)
    if not provider.get("installed"):
        raise ReportingRegistrationError(f"Unknown Tec-Tac provider module: {module_key}")
    if not provider.get("enabled"):
        raise ReportingRegistrationError(f"Tec-Tac provider module {module_key!r} is disabled.")
    if _resolve_model_class(app_key, model_name) is None:
        raise ReportingRegistrationError(f"Django model {app_key}.{model_name} is not loaded.")

    pair = (app_key.lower(), model_name.lower())
    model_key = model_name.lower()
    if model_key in _native_model_names():
        raise ReportingRegistrationError(
            f"Reporting model name {model_name!r} conflicts with a Tactical native reporting model."
        )

    registration = ReportingModelRegistration(
        id=public_id,
        module_id=module_key,
        app_label=app_key,
        model=model_name,
        display_name=str(display_name or "").strip(),
        description=str(description or "").strip(),
        field_metadata=copy.deepcopy(metadata),
    )
    with _LOCK:
        if public_id in _REGISTRY:
            raise ReportingRegistrationError(f"Duplicate public reporting ID: {public_id}")
        if pair in _PAIR_INDEX:
            raise ReportingRegistrationError(
                f"Duplicate reporting model registration: {app_key}.{model_name}"
            )
        if model_key in _MODEL_INDEX:
            other = _REGISTRY[_MODEL_INDEX[model_key]]
            raise ReportingRegistrationError(
                f"Reporting model name {model_name!r} is already registered by {other.module_id!r}; "
                "Tactical Report Manager model names must be globally unique."
            )
        _REGISTRY[public_id] = registration
        _PAIR_INDEX[pair] = public_id
        _MODEL_INDEX[model_key] = public_id

    try:
        sync_tactical_reporting_models()
    except Exception as exc:
        logger.exception("Unable to synchronize Tactical reporting model registration %s", public_id)
        _set_bridge_error(exc)
    return reporting_model_status(public_id)


def unregister_reporting_model(
    reporting_id: str | None = None,
    *,
    module_id: str | None = None,
    app_label: str | None = None,
    model: str | None = None,
) -> bool:
    """Remove one registration and immediately resynchronize Tactical runtime state."""
    key = _clean_id(reporting_id, "reporting_id") if reporting_id else None
    with _LOCK:
        if key is None:
            if not (module_id and app_label and model):
                raise ReportingRegistrationError(
                    "Provide reporting_id or module_id + app_label + model to unregister."
                )
            module_key = _clean_id(module_id, "module_id")
            pair = (_clean_name(app_label, "app_label").lower(), _clean_name(model, "model").lower())
            candidate = _PAIR_INDEX.get(pair)
            if candidate and _REGISTRY[candidate].module_id == module_key:
                key = candidate
        if not key or key not in _REGISTRY:
            return False
        registration = _REGISTRY.pop(key)
        _PAIR_INDEX.pop((registration.app_label.lower(), registration.model.lower()), None)
        _MODEL_INDEX.pop(registration.model.lower(), None)
    try:
        sync_tactical_reporting_models()
    except Exception as exc:
        logger.exception("Unable to synchronize Tactical reporting model unregistration %s", key)
        _set_bridge_error(exc)
    return True


def _property_fields(model_class) -> list[str]:
    excluded = {"pk", "fields_that_trigger_task_update_on_agent"}
    return [
        name for name, _ in inspect.getmembers(model_class, lambda value: isinstance(value, property))
        if name not in excluded
    ]


def _traverse_model_fields(*, model, prefix: str = "", depth: int = 3):
    """Mirror Tactical's schema field semantics without writing its static schema."""
    filter_obj: dict[str, Any] = {}
    pattern_obj: dict[str, Any] = {}
    select_related: list[str] = []
    field_list: list[str] = []
    if depth < 1:
        return filter_obj, pattern_obj, select_related, field_list
    for model_field in model._meta.get_fields():
        field_type = model_field.get_internal_type()
        if field_type == "CharField" and model_field.choices:
            definition = {"type": "string", "enum": [index for index, _ in model_field.choices]}
        elif field_type == "BooleanField":
            definition = {"type": "boolean"}
        elif model_field.many_to_many or model_field.one_to_many:
            continue
        elif field_type == "ForeignKey" or model_field.name == "id" or "Integer" in field_type:
            definition = {"type": "integer"}
            if field_type == "ForeignKey":
                select_related.append(prefix + model_field.name)
                nested_filter, nested_pattern, nested_select, nested_fields = _traverse_model_fields(
                    model=model_field.related_model,
                    prefix=prefix + model_field.name + "__",
                    depth=depth - 1,
                )
                filter_obj.update(nested_filter)
                pattern_obj.update(nested_pattern)
                select_related.extend(nested_select)
                field_list.extend(nested_fields)
        else:
            definition = {"type": "string"}
        filter_obj[prefix + model_field.name] = definition
        pattern_obj["^" + prefix + model_field.name + "(__[a-zA-Z]+)*$"] = definition
        field_list.append(prefix + model_field.name)
    return filter_obj, pattern_obj, select_related, field_list


def _schema_entry(registration: ReportingModelRegistration) -> dict[str, Any] | None:
    if not _registration_status(registration)["available"]:
        return None
    model_class = _resolve_model_class(registration.app_label, registration.model)
    if model_class is None:
        return None
    filter_obj, pattern_obj, select_related, field_list = _traverse_model_fields(model=model_class, depth=3)
    order_by = []
    for name in field_list:
        order_by.extend((name, f"-{name}"))
    return {
        "properties": {
            "model": {"type": "string", "enum": [registration.model.lower()]},
            "filter": {"type": "object", "properties": filter_obj, "patternProperties": pattern_obj},
            "exclude": {"type": "object", "properties": filter_obj, "patternProperties": pattern_obj},
            "defer": {"type": "array", "items": {"type": "string", "minimum": 1, "enum": field_list}},
            "only": {"type": "array", "items": {"type": "string", "minimum": 1, "enum": field_list}},
            "select_related": {"type": "array", "items": {"type": "string", "minimum": 1, "enum": select_related}},
            "order_by": {"type": "string", "enum": order_by},
            "properties": {"type": "array", "items": {"type": "string", "minimum": 1, "enum": _property_fields(model_class)}},
        }
    }


def augment_query_schema(native_schema: dict[str, Any]) -> dict[str, Any]:
    """Return Tactical's native schema plus currently available Tec-Tac models."""
    schema = copy.deepcopy(native_schema)
    properties = schema.setdefault("properties", {})
    model_definition = properties.setdefault("model", {"type": "string", "enum": []})
    enum = model_definition.setdefault("enum", [])
    one_of = schema.setdefault("oneOf", [])
    existing = {str(item).lower() for item in enum}
    with _LOCK:
        registrations = sorted(_REGISTRY.values(), key=lambda item: item.id)
    for registration in registrations:
        model_key = registration.model.lower()
        if model_key in existing:
            continue
        entry = _schema_entry(registration)
        if entry is None:
            continue
        enum.append(model_key)
        one_of.append(entry)
        existing.add(model_key)
    return schema


def _find_registration_by_model(model_name: str) -> ReportingModelRegistration | None:
    with _LOCK:
        public_id = _MODEL_INDEX.get(str(model_name or "").lower())
        return _REGISTRY.get(public_id) if public_id else None


def _set_bridge_error(exc: Exception) -> None:
    global _BRIDGE_ERROR
    _BRIDGE_ERROR = f"{exc.__class__.__name__}: {exc}"


def install_tactical_reporting_bridge() -> dict[str, Any]:
    """Install the Core compatibility bridge once per Django process."""
    global _BRIDGE_INSTALLED, _BRIDGE_ERROR, _ORIGINAL_QUERY_SCHEMA_GET, _ORIGINAL_RESOLVE_MODEL
    if _BRIDGE_INSTALLED:
        return reporting_bridge_status()
    try:
        from django.http import JsonResponse
        from ee.reporting import constants as reporting_constants
        from ee.reporting import utils as reporting_utils
        from ee.reporting import views as reporting_views

        _native_models()
        if not getattr(reporting_views.QuerySchema.get, "_tec_tac_reporting_bridge", False):
            _ORIGINAL_QUERY_SCHEMA_GET = reporting_views.QuerySchema.get

            def tec_tac_query_schema_get(self, request):
                response = _ORIGINAL_QUERY_SCHEMA_GET(self, request)
                if getattr(response, "status_code", 500) != 200:
                    return response
                try:
                    native = json.loads(response.content.decode("utf-8"))
                    return JsonResponse(augment_query_schema(native))
                except Exception:
                    logger.exception("Unable to augment Tactical Report Manager query schema")
                    return response

            tec_tac_query_schema_get._tec_tac_reporting_bridge = True
            reporting_views.QuerySchema.get = tec_tac_query_schema_get

        if not getattr(reporting_utils.resolve_model, "_tec_tac_reporting_bridge", False):
            _ORIGINAL_RESOLVE_MODEL = reporting_utils.resolve_model

            def tec_tac_resolve_model(*, data_source):
                requested = data_source.get("model") if isinstance(data_source, dict) else None
                registration = _find_registration_by_model(str(requested or ""))
                if registration is not None:
                    status = _registration_status(registration)
                    if not status["available"]:
                        raise reporting_utils.ResolveModelException(
                            f"Tec-Tac reporting model {registration.id!r} is unavailable: {status['state']}"
                        )
                return _ORIGINAL_RESOLVE_MODEL(data_source=data_source)

            tec_tac_resolve_model._tec_tac_reporting_bridge = True
            reporting_utils.resolve_model = tec_tac_resolve_model

        _BRIDGE_INSTALLED = True
        _BRIDGE_ERROR = ""
        sync_tactical_reporting_models()
        # Explicitly touch the constants object so a future Tactical refactor is
        # detected during Core startup/installer verification rather than later.
        tuple(reporting_constants.REPORTING_MODELS)
    except Exception as exc:
        _BRIDGE_INSTALLED = False
        _set_bridge_error(exc)
        logger.exception("Tec-Tac Tactical Report Manager bridge is unavailable")
    return reporting_bridge_status()


def reporting_bridge_status() -> dict[str, Any]:
    native = _native_models()
    active = list_reporting_models(include_unavailable=False)
    return {
        "available": bool(_BRIDGE_INSTALLED and not _BRIDGE_ERROR),
        "installed": bool(_BRIDGE_INSTALLED),
        "error": _BRIDGE_ERROR or None,
        "native_models": len(native),
        "tec_tac_models": len(active),
        "total_models": len(native) + len(active),
        "dynamic_schema": bool(_BRIDGE_INSTALLED and not _BRIDGE_ERROR),
    }


def _clear_reporting_registry_for_tests() -> None:
    """Private test helper; never use for production lifecycle management."""
    with _LOCK:
        _REGISTRY.clear()
        _PAIR_INDEX.clear()
        _MODEL_INDEX.clear()

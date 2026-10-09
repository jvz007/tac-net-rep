"""Core-owned Tec-Tac integration with Tactical Report Manager.

Tec-Tac modules register report-facing Django models here instead of importing
``ee.reporting`` internals. Core owns the compatibility bridge that keeps
Tactical's in-memory allow-lists and query-schema endpoint synchronized while
leaving Tactical tracked source and its native static schema untouched.

1.17.4 (AD-15): Report Manager 0.3.0 owns the report-model registry
(``reportmanager.registry``). This module is now a forwarding shim. The public names and
shapes stay, so every caller keeps working. Core keeps its own registry as the single record
of every registration. When Report Manager 0.3.0 or later is installed and enabled, Core
stands down at start-up (it patches nothing), holds registrations pending, and forwards them
to Report Manager once the capability is available. If the capability is not the owner of the
bridge when every module has loaded, Core takes its bridge back, so no report model vanishes.

1.17.4 also ships the row-scope hook: ``scoped_report_manager`` and ``model_row_scope``.
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


REPORT_MANAGER_ID = "reportmanager"
REPORT_MANAGER_MIN_VERSION = ">=0.3.0"
REGISTRY_CAPABILITY = "reportmanager.registry"
SHIM_SOURCE_ACTION = "reporting-shim"
STATE_PENDING = "pending-report-manager"
STATE_HIDDEN_UNAVAILABLE = "hidden-fields-unavailable"
STATE_REPORT_MANAGER_ERROR = "report-manager-error"
STATE_REPORT_MANAGER_UNAVAILABLE = "report-manager-unavailable"
# Report Manager refusals that remove the registration and raise, and refusals that keep it.
VALIDATION_STATES = frozenset({
    "invalid", "duplicate", "not-owner", "native-model-clash", "unknown-provider",
    "provider-disabled", "model-unavailable",
})
AVAILABILITY_STATES = frozenset({
    "row-scope-unavailable", "bridge-unavailable", "core-bridge-active", STATE_HIDDEN_UNAVAILABLE,
})


class ReportingRegistrationError(ValueError):
    """Invalid or conflicting reporting-model registration.

    ``state`` is one stable word (1.17.4): invalid, duplicate, not-owner, native-model-clash,
    unknown-provider, provider-disabled or model-unavailable.
    """

    def __init__(self, message: str = "", state: str = "invalid"):
        super().__init__(message)
        self.state = state


@dataclass(frozen=True)
class ReportingModelRegistration:
    id: str
    module_id: str
    app_label: str
    model: str
    display_name: str = ""
    description: str = ""
    field_metadata: dict[str, Any] = field(default_factory=dict)
    hidden_fields: tuple[str, ...] = ()


_LOCK = threading.RLock()
_REGISTRY: dict[str, ReportingModelRegistration] = {}
_PAIR_INDEX: dict[tuple[str, str], str] = {}
_MODEL_INDEX: dict[str, str] = {}
_NATIVE_REPORTING_MODELS: tuple[tuple[str, str], ...] | None = None
_BRIDGE_INSTALLED = False
_BRIDGE_ERROR = ""
_ORIGINAL_QUERY_SCHEMA_GET = None
_ORIGINAL_RESOLVE_MODEL = None
# 1.17.4 handover state. _HANDOVER: Report Manager >= 0.3.0 was enabled at start-up, so Core did not patch
# Tactical. _FALLBACK: Core took the bridge back at settle. _SETTLED: settle_reporting_bridge() has run.
_HANDOVER = False
_FALLBACK = False
_SETTLED = False
_REPORT_MANAGER_OWNS = False
_HANDOVER_ERROR = ""
_PENDING: set[str] = set()
_FORWARDED: set[str] = set()
_HELD: dict[str, tuple[str, str]] = {}
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


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


def _clean_hidden(value: Any) -> tuple[str, ...]:
    if value is None or value == ():
        return ()
    if isinstance(value, str) or not isinstance(value, (list, tuple, set, frozenset)):
        raise ReportingRegistrationError("hidden_fields must be a list of field or property names.")
    names: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if not _FIELD_RE.fullmatch(text):
            raise ReportingRegistrationError(f"hidden_fields entry {item!r} is not a field or property name.")
        if text not in names:
            names.append(text)
    return tuple(names)


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
    """Core's own computed row for one registration (never calls Report Manager)."""
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
    with _LOCK:
        forwarded = registration.id in _FORWARDED
        pending = registration.id in _PENDING
        held = _HELD.get(registration.id)
    if available and _BRIDGE_ERROR:
        available = False
        state = "bridge-unavailable"
        reason = _BRIDGE_ERROR
    if available and pending:
        # Handover: Report Manager has not taken this registration yet (1.17.4).
        available = False
        state, reason = held or (STATE_PENDING, _HANDOVER_ERROR or "Waiting for Report Manager to take this registration.")
    elif available and registration.hidden_fields and not forwarded:
        # Core's own bridge cannot hide columns, so it never serves a model that asks for hidden columns.
        available = False
        state = STATE_HIDDEN_UNAVAILABLE
        reason = "Hidden columns can be enforced only by Report Manager's bridge; Core's bridge would expose them."

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
        "hidden_fields": list(registration.hidden_fields),
        "forwarded": forwarded,
        "row_scope": model_row_scope(registration.app_label, registration.model),
        "available": available,
        "state": "available" if available else state,
        "reason": reason,
    }


def _registry_capability() -> tuple[dict | None, Any]:
    """Return (capability status, provider) for reportmanager.registry. Never raises: an error reads as unavailable."""
    try:
        from .capabilities import capability_status, get_capability

        status = capability_status(REGISTRY_CAPABILITY)
        provider = get_capability(REGISTRY_CAPABILITY, required=False) if status.get("available") else None
        return status, provider
    except Exception:
        logger.exception("Unable to read the reportmanager.registry capability")
        return None, None


def _live_row(registration: ReportingModelRegistration, live: dict[str, Any] | None) -> dict[str, Any]:
    """The row of a forwarded registration: Report Manager's live row, with Core's keys added."""
    if not isinstance(live, dict):
        row = _registration_status(registration)
        row.update(
            available=False, state=STATE_REPORT_MANAGER_UNAVAILABLE,
            reason="Report Manager's registry is not available to report this registration.",
        )
        return row
    row = dict(live)
    row["forwarded"] = True
    row.setdefault("hidden_fields", list(registration.hidden_fields))
    row.setdefault("row_scope", model_row_scope(registration.app_label, registration.model))
    return row


def reporting_model_status(reporting_id: str) -> dict[str, Any]:
    """Return live availability for one public reporting-model registration."""
    key = _clean_id(reporting_id, "reporting_id")
    with _LOCK:
        registration = _REGISTRY.get(key)
        forwarded = key in _FORWARDED
    if registration is None:
        return {
            "id": key,
            "available": False,
            "state": "missing",
            "reason": f"Reporting model {key!r} is not registered.",
        }
    if forwarded:
        _, provider = _registry_capability()
        live = None
        if provider is not None:
            try:
                live = provider.model_status(key)
            except Exception:
                logger.exception("Report Manager could not report reporting model %s", key)
        return _live_row(registration, live)
    return _registration_status(registration)


def list_reporting_models(*, include_unavailable: bool = True) -> list[dict[str, Any]]:
    """List registered Tec-Tac reporting models and their live provider state.

    Forwarded registrations (1.17.4) return Report Manager's live row; pending ones return Core's computed row.
    """
    with _LOCK:
        registrations = sorted(_REGISTRY.values(), key=lambda item: item.id)
        forwarded = set(_FORWARDED)
    live_rows: dict[str, dict[str, Any]] = {}
    if forwarded:
        _, provider = _registry_capability()
        if provider is not None:
            try:
                live_rows = {str(row.get("id")): row for row in provider.list_models(include_unavailable=True)}
            except Exception:
                logger.exception("Report Manager could not list reporting models")
    rows = [
        _live_row(item, live_rows.get(item.id)) if item.id in forwarded else _registration_status(item)
        for item in registrations
    ]
    if not include_unavailable:
        rows = [row for row in rows if row["available"]]
    return rows


def _active_pairs() -> tuple[tuple[str, str], ...]:
    """What Core's own bridge exposes: available registrations that Report Manager has not taken."""
    rows = []
    with _LOCK:
        registrations = [item for item in _REGISTRY.values() if item.id not in _FORWARDED and item.id not in _PENDING]
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


def _core_serves() -> bool:
    """True when Core's own bridge serves registrations: no handover, or Core took the bridge back."""
    return (not _HANDOVER) or _FALLBACK


def _sync_core_bridge(label: str) -> None:
    """Resynchronize Tactical's allow-lists, but only while Core's own bridge is the one that serves."""
    if not _core_serves():
        return
    try:
        sync_tactical_reporting_models()
    except Exception as exc:
        logger.exception("Unable to synchronize Tactical reporting model %s", label)
        _set_bridge_error(exc)


def _drop_registration(public_id: str) -> ReportingModelRegistration | None:
    with _LOCK:
        registration = _REGISTRY.pop(public_id, None)
        if registration is not None:
            _PAIR_INDEX.pop((registration.app_label.lower(), registration.model.lower()), None)
            _MODEL_INDEX.pop(registration.model.lower(), None)
        _PENDING.discard(public_id)
        _FORWARDED.discard(public_id)
        _HELD.pop(public_id, None)
    return registration


def _forward_registration(registration: ReportingModelRegistration, provider) -> bool:
    """Forward one registration to Report Manager. True when it took it.

    A validation refusal removes the registration and raises ReportingRegistrationError with the state. An
    availability refusal (or any other failure) keeps the registration pending, logs a warning and returns False.
    """
    global _REPORT_MANAGER_OWNS
    from .capabilities import build_operation_context

    context = build_operation_context(source_module=registration.module_id, source_action=SHIM_SOURCE_ACTION)
    try:
        provider.register_model(
            module_id=registration.module_id,
            app_label=registration.app_label,
            model=registration.model,
            reporting_id=registration.id,
            display_name=registration.display_name or None,
            description=registration.description or None,
            field_metadata=copy.deepcopy(registration.field_metadata),
            hidden_fields=list(registration.hidden_fields) or None,
            context=context,
        )
    except Exception as exc:
        state = str(getattr(exc, "state", "") or "")
        if state in VALIDATION_STATES:
            _drop_registration(registration.id)
            raise ReportingRegistrationError(str(exc), state) from exc
        state = state if state in AVAILABILITY_STATES else STATE_REPORT_MANAGER_ERROR
        logger.warning(
            "Report Manager did not take reporting model %s (%s): %s", registration.id, state, exc,
        )
        with _LOCK:
            _HELD[registration.id] = (state, str(exc))
        return False
    with _LOCK:
        _PENDING.discard(registration.id)
        _HELD.pop(registration.id, None)
        _FORWARDED.add(registration.id)
        _REPORT_MANAGER_OWNS = True
    return True


def _forward_pending(*, raise_for: str | None = None) -> None:
    """Replay pending registrations to Report Manager in id order, when its capability is available.

    A validation refusal for ``raise_for`` is raised after the rest have been replayed. For any other
    registration it is logged, because its caller is gone.
    """
    with _LOCK:
        ids = sorted(_PENDING)
    if not ids:
        return
    _, provider = _registry_capability()
    if provider is None:
        return
    pending_error = None
    for public_id in ids:
        with _LOCK:
            registration = _REGISTRY.get(public_id)
        if registration is None:
            continue
        try:
            _forward_registration(registration, provider)
        except ReportingRegistrationError as exc:
            if public_id == raise_for:
                pending_error = exc
            else:
                logger.warning("Report Manager refused reporting model %s (%s): %s", public_id, exc.state, exc)
    if pending_error is not None:
        raise pending_error


def register_reporting_model(
    *,
    module_id: str,
    app_label: str,
    model: str,
    reporting_id: str | None = None,
    display_name: str | None = None,
    description: str | None = None,
    field_metadata: dict[str, Any] | None = None,
    hidden_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Register one module-owned Django model with Tactical Report Manager.

    Registration is process-local by design and should be called from the provider module/reportset
    ``AppConfig.ready()``. Module lifecycle reloads rebuild the registry from the currently enabled module set.

    1.17.4: ``hidden_fields`` names columns Report Manager must hide and refuse; Core's own bridge cannot, so a
    model that asks for them is served only through Report Manager. When Report Manager owns the registry the
    call is held pending until its capability is available, then forwarded (see ``settle_reporting_bridge``).
    A validation refusal raises ReportingRegistrationError with a ``state``. An availability refusal keeps the
    registration and returns the row with that state.
    """
    module_key = _clean_id(module_id, "module_id")
    app_key = _clean_name(app_label, "app_label")
    model_name = _clean_name(model, "model")
    public_id = _clean_id(reporting_id or f"{module_key}.{model_name.lower()}", "reporting_id")
    metadata = field_metadata or {}
    if not isinstance(metadata, dict):
        raise ReportingRegistrationError("field_metadata must be an object when provided.")
    hidden = _clean_hidden(hidden_fields)

    provider = _provider_status(module_key)
    if not provider.get("installed"):
        raise ReportingRegistrationError(f"Unknown Tec-Tac provider module: {module_key}", "unknown-provider")
    if not provider.get("enabled"):
        raise ReportingRegistrationError(f"Tec-Tac provider module {module_key!r} is disabled.", "provider-disabled")
    if _resolve_model_class(app_key, model_name) is None:
        raise ReportingRegistrationError(f"Django model {app_key}.{model_name} is not loaded.", "model-unavailable")

    pair = (app_key.lower(), model_name.lower())
    model_key = model_name.lower()
    if model_key in _native_model_names():
        raise ReportingRegistrationError(
            f"Reporting model name {model_name!r} conflicts with a Tactical native reporting model.",
            "native-model-clash",
        )

    registration = ReportingModelRegistration(
        id=public_id,
        module_id=module_key,
        app_label=app_key,
        model=model_name,
        display_name=str(display_name or "").strip(),
        description=str(description or "").strip(),
        field_metadata=copy.deepcopy(metadata),
        hidden_fields=hidden,
    )
    with _LOCK:
        if public_id in _REGISTRY:
            raise ReportingRegistrationError(f"Duplicate public reporting ID: {public_id}", "duplicate")
        if pair in _PAIR_INDEX:
            raise ReportingRegistrationError(
                f"Duplicate reporting model registration: {app_key}.{model_name}", "duplicate"
            )
        if model_key in _MODEL_INDEX:
            other = _REGISTRY[_MODEL_INDEX[model_key]]
            raise ReportingRegistrationError(
                f"Reporting model name {model_name!r} is already registered by {other.module_id!r}; "
                "Tactical Report Manager model names must be globally unique.",
                "duplicate",
            )
        _REGISTRY[public_id] = registration
        _PAIR_INDEX[pair] = public_id
        _MODEL_INDEX[model_key] = public_id
        handover = _HANDOVER and not _FALLBACK
        if handover:
            _PENDING.add(public_id)

    if handover:
        _forward_pending(raise_for=public_id)
        return reporting_model_status(public_id)
    if hidden:
        logger.warning(
            "Reporting model %s asks for hidden columns, which Core's own bridge cannot enforce; it is not served.",
            public_id,
        )
    _sync_core_bridge(f"registration {public_id}")
    return reporting_model_status(public_id)


def unregister_reporting_model(
    reporting_id: str | None = None,
    *,
    module_id: str | None = None,
    app_label: str | None = None,
    model: str | None = None,
) -> bool:
    """Remove one registration and immediately resynchronize Tactical runtime state.

    A registration that was forwarded to Report Manager is removed there too.
    """
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
        was_forwarded = key in _FORWARDED
    registration = _drop_registration(key)
    if was_forwarded and registration is not None:
        _, provider = _registry_capability()
        if provider is None:
            logger.warning("Report Manager is not available to remove reporting model %s", key)
        else:
            try:
                from .capabilities import build_operation_context

                provider.unregister_model(
                    key,
                    context=build_operation_context(source_module=registration.module_id, source_action=SHIM_SOURCE_ACTION),
                )
            except Exception:
                logger.exception("Report Manager could not remove reporting model %s", key)
    _sync_core_bridge(f"unregistration {key}")
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
    with _LOCK:
        if registration.id in _FORWARDED or registration.id in _PENDING:
            return None  # Report Manager serves these (1.17.4); Core's schema never lists them
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


def _report_manager_takeover() -> bool:
    """True when Report Manager is installed as an extension, enabled, and version 0.3.0 or later (AD-15)."""
    provider = _provider_status(REPORT_MANAGER_ID)
    if not (provider.get("installed") and provider.get("enabled")):
        return False
    try:
        from .module_state import version_satisfies

        return bool(version_satisfies(str(provider.get("version") or "0.0.0"), REPORT_MANAGER_MIN_VERSION))
    except Exception:
        logger.exception("Unable to compare the Report Manager version; Core keeps its own bridge")
        return False


def install_tactical_reporting_bridge(force: bool = False) -> dict[str, Any]:
    """Install the Core compatibility bridge once per Django process.

    1.17.4: when Report Manager 0.3.0 or later is installed and enabled, Core stands down. It patches nothing, records
    ``handover`` and reports ``installed`` false with no ``_tec_tac_reporting_bridge`` marker, which is what Report
    Manager reads. ``force=True`` installs anyway; ``settle_reporting_bridge`` uses it to take the bridge back.
    """
    global _BRIDGE_INSTALLED, _BRIDGE_ERROR, _ORIGINAL_QUERY_SCHEMA_GET, _ORIGINAL_RESOLVE_MODEL, _HANDOVER
    if _BRIDGE_INSTALLED:
        return reporting_bridge_status()
    if not force:
        if _report_manager_takeover():
            _HANDOVER = True
            logger.info("Report Manager %s or later is enabled; Core's reporting bridge stands down.", REPORT_MANAGER_MIN_VERSION)
            return reporting_bridge_status()
        _HANDOVER = False
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


def _take_bridge_back(reason: str) -> None:
    """Fallback (1.17.4): Report Manager does not own the bridge, so Core installs its own again.

    Pending registrations, and (1.17.5) registrations already forwarded to Report Manager before it proved not to
    own the bridge, are served by Core's bridge. Ones that carry hidden_fields are refused (state
    hidden-fields-unavailable), because Core's bridge cannot hide columns. The forwarded set is cleared before the
    bridge is installed so the allow-lists include them; after that unregister no longer calls the provider for them.

    1.17.6: the formerly forwarded registrations are also unregistered from Report Manager's registry, best effort,
    so it does not keep a row Core now serves. The call is made after the lock is released and before the bridge is
    installed. It never raises: a failure (including Report Manager's own RegistryError in mode core-bridge-active)
    is logged and the fallback goes on. With no provider, one warning is logged.
    """
    global _FALLBACK, _REPORT_MANAGER_OWNS
    with _LOCK:
        _FALLBACK = True
        pending = sorted(_PENDING)
        forwarded = sorted(_FORWARDED)
        released = [_REGISTRY[item] for item in forwarded if item in _REGISTRY]
        _PENDING.clear()
        _HELD.clear()
        _FORWARDED.clear()
        _REPORT_MANAGER_OWNS = False
        refused = [_REGISTRY[item].id for item in pending + forwarded if item in _REGISTRY and _REGISTRY[item].hidden_fields]
    logger.warning("Core takes its reporting bridge back: %s", reason)
    for public_id in refused:
        logger.warning("Reporting model %s is refused: it carries hidden_fields and Core's bridge cannot hide columns.", public_id)
    _unregister_released(released)
    install_tactical_reporting_bridge(force=True)


def _unregister_released(released: list) -> None:
    """Best-effort removal of formerly forwarded registrations from Report Manager. Never raises."""
    if not released:
        return
    try:
        _, provider = _registry_capability()
        if provider is None:
            logger.warning(
                "Report Manager is not available to remove %d formerly forwarded reporting model(s): %s",
                len(released), ", ".join(item.id for item in released),
            )
            return
        from .capabilities import build_operation_context

        for registration in released:
            try:
                provider.unregister_model(
                    registration.id,
                    context=build_operation_context(source_module=registration.module_id, source_action=SHIM_SOURCE_ACTION),
                )
            except Exception:
                logger.exception("Report Manager could not remove formerly forwarded reporting model %s", registration.id)
    except Exception:
        logger.exception("Unable to remove formerly forwarded reporting models from Report Manager")


def settle_reporting_bridge() -> dict[str, Any]:
    """Settle the handover once every AppConfig.ready() has run (called after Apps.populate, in every process).

    Report Manager owns the bridge when its ``reportmanager.registry`` capability is available (its health is true
    only then): pending registrations are replayed in id order. When the capability is absent, or reports mode
    ``core-bridge-active`` or ``unavailable``, Core takes its bridge back. When it reports mode ``report-manager``
    but is unhealthy for another reason, nothing changes and the status shows the error, so two bridges never
    patch the same names.
    """
    global _SETTLED, _HANDOVER_ERROR
    with _LOCK:
        if _SETTLED:
            return reporting_bridge_status()
        _SETTLED = True
        handover = _HANDOVER and not _FALLBACK
    if not handover:
        return reporting_bridge_status()
    status, provider = _registry_capability()
    if provider is not None:
        _forward_pending()
        return reporting_bridge_status()
    health = (status or {}).get("health") if isinstance(status, dict) else None
    mode = health.get("mode") if isinstance(health, dict) else None
    if status is not None and status.get("state") == "unhealthy" and mode == "report-manager":
        _HANDOVER_ERROR = str(status.get("reason") or "Report Manager reports its bridge unhealthy.")
        logger.error("Report Manager owns the reporting bridge but is unhealthy: %s", _HANDOVER_ERROR)
        return reporting_bridge_status()
    detail = (status or {}).get("reason") or (status or {}).get("state") or "capability status could not be read"
    _take_bridge_back(f"reportmanager.registry is not the owner of the bridge ({detail})")
    return reporting_bridge_status()


def reporting_bridge_status() -> dict[str, Any]:
    """Public bridge status. Cheap, and it never calls Report Manager (Report Manager reads it back)."""
    native = _native_models()
    with _LOCK:
        registrations = sorted(_REGISTRY.values(), key=lambda item: item.id)
        forwarded = sorted(_FORWARDED)
        pending = sorted(_PENDING)
    served = [item for item in registrations if item.id not in _FORWARDED and item.id not in _PENDING]
    core_active = [item for item in served if _registration_status(item)["available"]]
    active_count = len(core_active) + len(forwarded)
    if _core_serves():
        owner = "core"
    else:
        owner = "reportmanager" if _REPORT_MANAGER_OWNS else "pending"
    enforced, unscoped = [], []
    for item in registrations:
        (enforced if model_row_scope(item.app_label, item.model)["enforced"] else unscoped).append(item.id)
    return {
        "available": bool(_BRIDGE_INSTALLED and not _BRIDGE_ERROR),
        "installed": bool(_BRIDGE_INSTALLED),
        "error": _BRIDGE_ERROR or _HANDOVER_ERROR or None,
        "bridge_error": _BRIDGE_ERROR or None,
        "handover_error": _HANDOVER_ERROR or None,
        "native_models": len(native),
        "tec_tac_models": active_count,
        "total_models": len(native) + active_count,
        "dynamic_schema": bool(_BRIDGE_INSTALLED and not _BRIDGE_ERROR),
        "owner": owner,
        "handover": bool(_HANDOVER),
        "fallback": bool(_FALLBACK),
        "forwarded_models": len(forwarded),
        "pending_models": len(pending),
        "row_scope_enforced": True,
        "row_scope_models": {"enforced": enforced, "unscoped": unscoped},
    }


# ----------------------------------------------------------------------------------------------
# Row scope hook (1.17.4)
#
# Tactical's report engine scopes a query by the person's clients and sites only when the model's manager has
# ``filter_by_role`` (ee/reporting/utils.py build_queryset). A registered model has no such method, so a scoped
# person would see every row. ``scoped_report_manager`` is the manager a module adopts. Core cannot attach it to a
# module's model after the fact, so the module declares it. Tactical falls back to an UNSCOPED queryset when
# ``filter_by_role`` raises, so the Core implementation never raises: any failure returns no rows.
# ----------------------------------------------------------------------------------------------

_SCOPE_SEGMENT = r"[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)*"
_SCOPE_PATH_RE = re.compile(rf"^{_SCOPE_SEGMENT}(?:__{_SCOPE_SEGMENT})*$")
_SCOPE_MANAGER_CLASS = None


def _clean_scope_path(value: Any, label: str) -> str | None:
    if value is None:
        return None
    text = value.strip() if isinstance(value, str) else ""
    if not text or len(text) > 200 or not _SCOPE_PATH_RE.fullmatch(text):
        raise ReportingRegistrationError(
            f"{label} must be an ORM lookup path such as 'client_id' or 'agent__site__client_id'."
        )
    return text


def scope_filter_spec(
    ids: dict[str, Any], *, client_path: str | None, site_path: str | None, include_unassigned: bool = False
) -> dict[str, Any]:
    """Pure decision logic: what a report model's rows look like to one person.

    ``ids`` is ``report_scope_ids(user)``. Returns ``{"mode": "all" | "none" | "filter", "clauses": [(path, ids)],
    "unassigned": [path]}``. A row matches when its client path is in the granted client ids, or its site path is in
    the visible site ids, or (``include_unassigned``) every declared path is null. A model that declares neither
    path gives no rows to a scoped person (fail closed).
    """
    if ids.get("unrestricted"):
        return {"mode": "all", "clauses": [], "unassigned": []}
    if ids.get("denied") or (not client_path and not site_path):
        return {"mode": "none", "clauses": [], "unassigned": []}
    client_ids = sorted(ids.get("client_ids") or ())
    site_ids = sorted(ids.get("site_ids") or ())
    clauses = []
    if client_path and client_ids:
        clauses.append((client_path, client_ids))
    if site_path and site_ids:
        clauses.append((site_path, site_ids))
    unassigned = [path for path in (client_path, site_path) if path] if include_unassigned else []
    if not clauses and not unassigned:
        return {"mode": "none", "clauses": [], "unassigned": []}
    return {"mode": "filter", "clauses": clauses, "unassigned": unassigned}


def _apply_scope_spec(queryset, spec: dict[str, Any]):
    if spec["mode"] == "all":
        return queryset
    if spec["mode"] == "none":
        return queryset.none()
    from django.db.models import Q

    condition = Q()
    for path, values in spec["clauses"]:
        condition |= Q(**{f"{path}__in": list(values)})
    if spec["unassigned"]:
        unassigned = Q()
        for path in spec["unassigned"]:
            unassigned &= Q(**{f"{path}__isnull": True})
        condition |= unassigned
    return queryset.filter(condition)


def _scoped_queryset(queryset, user, *, client_path, site_path, include_unassigned):
    try:
        from .resources_adapter import report_scope_ids

        spec = scope_filter_spec(
            report_scope_ids(user), client_path=client_path, site_path=site_path, include_unassigned=include_unassigned
        )
        return _apply_scope_spec(queryset, spec)
    except Exception:
        # Tactical treats a raised filter_by_role as "no scope". Fail closed instead.
        logger.exception("Tec-Tac report row scope failed; returning no rows")
        return queryset.none()


def _scoped_manager_class():
    global _SCOPE_MANAGER_CLASS
    if _SCOPE_MANAGER_CLASS is not None:
        return _SCOPE_MANAGER_CLASS
    from django.db import models

    class ScopedReportManager(models.Manager):
        """Manager whose ``filter_by_role(user)`` limits rows to the person's clients and sites."""

        _tec_tac_scoped_report_manager = True

        def __init__(self, client_field=None, site_field=None, include_unassigned=False):
            super().__init__()
            self.client_field = client_field
            self.site_field = site_field
            self.include_unassigned = bool(include_unassigned)

        def filter_by_role(self, user):
            return _scoped_queryset(
                self.get_queryset(), user,
                client_path=self.client_field, site_path=self.site_field, include_unassigned=self.include_unassigned,
            )

    _SCOPE_MANAGER_CLASS = ScopedReportManager
    return _SCOPE_MANAGER_CLASS


def scoped_report_manager(*, client: str | None = None, site: str | None = None, include_unassigned: bool = False):
    """Return a Django manager that scopes a report model's rows by client and site.

    Declare it on the report-facing model: ``objects = scoped_report_manager(client="client_id", site="site_id")``.
    ``client`` and ``site`` are ORM lookup paths (for example ``agent__site__client_id``). Its
    ``filter_by_role(user)`` mirrors Tactical's rules: a superuser, or a role with neither can_view_clients nor
    can_view_sites, sees every row; no role sees none; otherwise a row is visible when its client path is in the
    explicitly granted client ids or its site path is in the visible site ids (granted sites plus the sites of
    granted clients). A row with no client or site is hidden unless ``include_unassigned`` is true. A model that
    declares neither path shows no rows to a scoped person.
    """
    if not isinstance(include_unassigned, bool):
        raise ReportingRegistrationError("include_unassigned must be true or false.")
    return _scoped_manager_class()(
        _clean_scope_path(client, "client"), _clean_scope_path(site, "site"), include_unassigned
    )


def _path_resolves(model_class, path: str) -> bool:
    from django.core.exceptions import FieldDoesNotExist

    current = model_class
    parts = path.split("__")
    for index, part in enumerate(parts):
        try:
            model_field = current._meta.get_field(part)
        except FieldDoesNotExist:
            return False
        if index < len(parts) - 1:
            related = getattr(model_field, "related_model", None)
            if related is None or isinstance(related, str) or not getattr(model_field, "concrete", False):
                return False
            current = related
        elif not getattr(model_field, "concrete", False):
            return False
    return True


def model_row_scope(app_label: str, model: str) -> dict[str, Any]:
    """Whether a model's rows are scoped by Core's hook.

    ``enforced`` is true only when ``Model.objects.filter_by_role`` is Core's scoped implementation (not overridden)
    and the declared client or site path resolves on the model. ``source`` is ``core`` (Core's manager), ``model``
    (a manager with its own filter_by_role, which Core cannot vouch for) or null (none).
    """
    result = {"enforced": False, "source": None, "client_field": None, "site_field": None, "include_unassigned": False}
    model_class = _resolve_model_class(app_label, model)
    if model_class is None:
        return result
    manager = getattr(model_class, "objects", None)
    if not callable(getattr(manager, "filter_by_role", None)):
        return result
    if not getattr(manager, "_tec_tac_scoped_report_manager", False):
        result["source"] = "model"
        return result
    result["source"] = "core"
    if getattr(type(manager), "filter_by_role", None) is not _scoped_manager_class().filter_by_role:
        result["source"] = "model"  # a subclass replaced Core's filter_by_role
        return result
    client_path = getattr(manager, "client_field", None)
    site_path = getattr(manager, "site_field", None)
    result.update(client_field=client_path, site_field=site_path, include_unassigned=bool(getattr(manager, "include_unassigned", False)))
    paths = [path for path in (client_path, site_path) if path]
    result["enforced"] = bool(paths) and all(_path_resolves(model_class, path) for path in paths)
    return result


def _clear_reporting_registry_for_tests() -> None:
    """Private test helper; never use for production lifecycle management."""
    with _LOCK:
        _REGISTRY.clear()
        _PAIR_INDEX.clear()
        _MODEL_INDEX.clear()
        _PENDING.clear()
        _FORWARDED.clear()
        _HELD.clear()

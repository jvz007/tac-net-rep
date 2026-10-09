"""Core-owned Tec-Tac audit write contract.

Modules call this service instead of importing Tactical ``logs.models.AuditLog``.
Core resolves the authenticated actor and module provenance, validates a compact
public event vocabulary, and writes compatible rows into Tactical's existing
audit table so retention, export and reporting remain unified.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger("tec_tac.audit")

STANDARD_ACTIONS = frozenset({
    "add", "modify", "delete", "run", "approve", "deny", "enable", "disable",
    "install", "uninstall", "view", "export", "import", "sync", "test",
    "acknowledge", "resolve", "console_change_requested",
})
_CUSTOM_ACTION_RE = re.compile(r"^custom:[a-z0-9][a-z0-9_-]{0,63}$")
_OBJECT_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,99}$")


class AuditContractError(ValueError):
    """Invalid public audit event or module/actor context."""


class AuditWriteError(RuntimeError):
    """Tactical AuditLog persistence failed in strict mode."""


class AuditActor:
    """Core-owned non-human audit provenance for trusted backend work."""

    __slots__ = ("kind", "module_id", "identity", "service", "device_id")

    def __init__(self, *, kind: str, module_id: str, identity: str, service: str | None = None, device_id: str | None = None):
        self.kind = kind
        self.module_id = module_id
        self.identity = identity
        self.service = service
        self.device_id = device_id


def _actor_part(value: Any, label: str, *, maximum: int = 128) -> str:
    value = str(value or "").strip()
    if not value:
        raise AuditContractError(f"{label} is required.")
    if len(value.encode("utf-8")) > maximum:
        raise AuditContractError(f"{label} exceeds {maximum} bytes.")
    if any(ord(ch) < 32 for ch in value):
        raise AuditContractError(f"{label} contains control characters.")
    return value


def service_audit_actor(*, module_id: str, service: str, identity: str | None = None) -> AuditActor:
    """Create service/system provenance for scheduled or background module work."""
    module = _resolve_module(module_id)
    service_name = _actor_part(service, "service")
    actor_identity = _actor_part(identity or f"{module['id']}.{service_name}", "identity", maximum=255)
    return AuditActor(kind="service", module_id=module["id"], service=service_name, identity=actor_identity)


def device_audit_actor(*, module_id: str, device_id: str, identity: str | None = None, service: str | None = None) -> AuditActor:
    """Create device/probe provenance for agent or probe result callbacks."""
    module = _resolve_module(module_id)
    did = _actor_part(device_id, "device_id", maximum=255)
    service_name = _actor_part(service, "service") if service not in (None, "") else None
    actor_identity = _actor_part(identity or did, "identity", maximum=255)
    return AuditActor(kind="device", module_id=module["id"], service=service_name, identity=actor_identity, device_id=did)


def _actor_provenance(actor, module: dict, authority=None) -> tuple[str, dict[str, Any]]:
    if isinstance(actor, AuditActor):
        if actor.module_id != module["id"]:
            raise AuditContractError("non-human audit actor module_id must match the audit event module_id.")
        prefix = "service" if actor.kind == "service" else "device"
        username = f"{prefix}:{actor.identity}"[:255]
        details = {
            "actor_kind": actor.kind,
            "actor_identity": actor.identity,
            "actor_module_id": actor.module_id,
            "actor_service": actor.service,
            "actor_device_id": actor.device_id,
        }
        return username, {k: v for k, v in details.items() if v is not None}

    if not getattr(actor, "is_authenticated", False):
        raise AuditContractError("actor must be an authenticated Tactical user or a Core-owned audit actor.")
    # A person acting only under a Tactical permission is not a Tec-Tac module user (1.17.7). Core's executor has
    # already checked Tactical's permission and scope, so it passes its own internal authority.
    if authority is not _TACTICAL_OPERATION_AUTHORITY and not _actor_can_use_module(actor, module):
        raise AuditContractError(f"actor is not permitted to use Tec-Tac module {module['id']!r}.")
    username = str(getattr(actor, "username", "") or "").strip()
    if not username:
        raise AuditContractError("authenticated actor does not expose a username.")
    return username, {"actor_kind": "human", "actor_identity": username}


def _framework_version() -> str:
    try:
        return (Path(__file__).resolve().parents[2] / "VERSION").read_text(encoding="utf-8").strip() or "unknown"
    except Exception:
        return "unknown"


def _resolve_module(module_id: str):
    module_id = str(module_id or "").strip()
    if not module_id:
        raise AuditContractError("module_id is required.")
    if module_id == "core":
        return {"id": "core", "version": _framework_version(), "permissions": (), "legacy": False}

    from .registry import get_plugins
    from .module_state import is_enabled, load_state

    matches = [p for p in get_plugins() if p.plugin_id == module_id and p.plugin_type in {"extension", "legacy"}]
    if len(matches) != 1:
        raise AuditContractError(f"Unknown or ambiguous Tec-Tac module_id: {module_id}")
    plugin = matches[0]
    if plugin.plugin_type == "extension" and not is_enabled(module_id, load_state()):
        raise AuditContractError(f"Tec-Tac module {module_id!r} is disabled.")
    permissions = tuple(sorted({code for _, values in plugin.permission_groups for code in values}))
    return {
        "id": plugin.plugin_id,
        "version": str(plugin.version or "0.0.0"),
        "permissions": permissions,
        "legacy": bool(plugin.legacy),
        "category": str(getattr(plugin, "category", "") or ""),
        "audit_events": tuple(getattr(plugin, "audit_events", ()) or ()),
    }


def _actor_can_use_module(actor, module: dict) -> bool:
    if not getattr(actor, "is_authenticated", False):
        return False
    if bool(getattr(actor, "is_superuser", False)):
        return True
    try:
        role = actor.get_and_set_role_cache()
    except Exception:
        role = getattr(actor, "role", None)
    if role is not None and bool(getattr(role, "is_superuser", False)):
        return True
    permissions = tuple(module.get("permissions") or ())
    if not permissions or module.get("id") == "core":
        return True
    try:
        from .rbac import effective_permissions
        granted = effective_permissions(actor)
    except Exception:
        logger.exception("Unable to resolve Tec-Tac audit module permissions for module=%s", module.get("id"))
        return False
    return bool(set(permissions) & set(granted))


def can_record(actor, module_id: str) -> bool:
    """Return whether actor may use the browser-facing audit writer for module."""
    try:
        module = _resolve_module(module_id)
    except AuditContractError:
        return False
    return _actor_can_use_module(actor, module)


def can_record_from_browser(actor, module_id: str) -> bool:
    """Return whether an authenticated actor may write browser audit for a module.

    Browser provenance is intentionally stricter than the backend ``record``
    contract.  Core provenance and modules without an explicit permission surface
    are never available to browser callers because Core cannot prove that module
    code, rather than an arbitrary authenticated user, originated the event.
    Permission-bearing modules additionally require one of their effective grants
    through ``_actor_can_use_module``.
    """
    try:
        module = _resolve_module(module_id)
    except AuditContractError:
        return False
    if module.get("id") == "core" or not tuple(module.get("permissions") or ()):
        return False
    return _actor_can_use_module(actor, module)


# Object types whose events Core scope-checks through core.resources (and whose refusals get a deny row).
SCOPE_CHECKED_OBJECT_TYPES = ("client", "site", "agent")
BROWSER_EVENT_OBJECT_TYPES = SCOPE_CHECKED_OBJECT_TYPES  # alias kept for 1.16.0 importers
BROWSER_PROVENANCE_MARKER = "module-declared-event"
# operation_context keys only Core sets. Payloads can never supply operation_context, so a module cannot forge them.
CORE_CONTEXT_KEYS = ("browser_provenance", "core_refusal", "server_provenance")
# 1.17.7: provenance of a row Core wrote itself around a Tactical call it ran server-side (tec_tac.tactical_operations).
SERVER_PROVENANCE_TACTICAL_OPERATION = "tactical-operation"
# Core-internal authority. Passed only by Core's own executor to _record_row, never through the public record().
_TACTICAL_OPERATION_AUTHORITY = object()


def declared_browser_event(actor, module_id: str, action: Any, object_type: Any) -> bool:
    """Return whether a permissionless module declared this browser audit event.

    This is the second browser path, used only when ``can_record_from_browser``
    said no. It accepts an event only when the module resolves, is installed and
    enabled, is not legacy, has no permission groups (permissioned modules keep
    their grant path) and lists this exact ``object_type`` and ``action`` in its
    manifest ``audit_events``. Core still cannot prove the module's code sent the
    event, so the caller must also pass the resource scope check for client, site
    and agent objects (``SCOPE_CHECKED_OBJECT_TYPES``). Any other declared object
    type has no scope check; the row is recorded under the signed-in user with the marker.
    """
    if not getattr(actor, "is_authenticated", False):
        return False
    try:
        module = _resolve_module(module_id)
    except AuditContractError:
        return False
    if module.get("id") == "core" or module.get("legacy") or tuple(module.get("permissions") or ()):
        return False
    wanted_action = str(action or "").strip().lower()
    wanted_type = str(object_type or "").strip().lower()
    if not _OBJECT_TYPE_RE.fullmatch(wanted_type):
        return False
    for declared_type, declared_actions in tuple(module.get("audit_events") or ()):
        if declared_type == wanted_type and wanted_action in declared_actions:
            return _actor_can_use_module(actor, module)
    return False


def _normalize_action(value: Any) -> str:
    action = str(value or "").strip().lower()
    if action in STANDARD_ACTIONS or _CUSTOM_ACTION_RE.fullmatch(action):
        return action
    raise AuditContractError(
        "action must use the standard Tec-Tac audit vocabulary or controlled custom:<slug> fallback."
    )


def _normalize_object_type(value: Any) -> str:
    object_type = str(value or "").strip().lower()
    if not _OBJECT_TYPE_RE.fullmatch(object_type):
        raise AuditContractError("object_type must be a lowercase slug up to 100 characters.")
    return object_type


def _correlation_id(request=None, explicit: Any = None) -> str:
    value = str(explicit or "").strip()
    if value:
        return value[:255]
    if request is not None:
        for attr in ("tec_tac_request_id", "correlation_id", "request_id"):
            value = str(getattr(request, attr, "") or "").strip()
            if value:
                return value[:255]
    # Never trust browser-supplied X-Request-ID/X-Correlation-ID as audit
    # provenance. If Core middleware did not assign one, mint it here.
    return str(uuid.uuid4())


def _max_value_bytes() -> int:
    try:
        from django.conf import settings
        return int(getattr(settings, "AUDIT_MAX_VALUE_BYTES", 512 * 2**10))
    except Exception:
        return 512 * 2**10


def _tactical_json_bytes(value: Any) -> bytes:
    """Encode the way Tactical's AuditLog.save measures debug_info.

    Tactical uses json.dumps with the default ensure_ascii=True, so non-ASCII text
    counts as escaped characters. Measuring any other way undercounts and lets a row
    pass here that Tactical then replaces whole.
    """
    return json.dumps(value, default=str).encode("utf-8")


def _safe_metadata(metadata: Any) -> Any:
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise AuditContractError("metadata must be an object when provided.")
    max_bytes = _max_value_bytes()
    # Reserve headroom for Core provenance so oversized module metadata does not
    # cause Tactical to replace the entire debug_info object.
    budget = max(1024, max_bytes - 8192)
    try:
        encoded = _tactical_json_bytes(metadata)
    except Exception:
        return {"error": "could not process audit metadata"}
    if len(encoded) > budget:
        return {
            "error": "value too large to store in audit log. Check documentation for configuring AUDIT_MAX_VALUE_BYTES",
            "original_bytes": len(encoded),
        }
    return metadata


def _keep_browser_provenance(marker: dict, original: Any) -> None:
    """Carry Core's own operation_context keys onto a 'value too large' marker."""
    if not isinstance(marker, dict) or not isinstance(original, dict):
        return
    provenance = original.get("browser_provenance")
    if isinstance(provenance, str) and len(provenance) <= 100:
        marker["browser_provenance"] = provenance
    if original.get("core_refusal") is True:
        marker["core_refusal"] = True
    server = original.get("server_provenance")
    if isinstance(server, str) and len(server) <= 100:
        marker["server_provenance"] = server
        operation = original.get("operation")
        if isinstance(operation, str) and len(operation) <= 100:
            marker["operation"] = operation
        status = original.get("tactical_status")
        if isinstance(status, int) and not isinstance(status, bool):
            marker["tactical_status"] = status


def _debug_info_bytes(debug_info: dict) -> int:
    try:
        return len(_tactical_json_bytes(debug_info))
    except (TypeError, ValueError, OverflowError):
        return 0


def _fit_debug_info(debug_info: dict) -> dict:
    """Keep the whole debug_info inside AUDIT_MAX_VALUE_BYTES.

    Tactical replaces the entire debug_info when it is over the limit, which would
    wipe Core provenance. Replace module metadata and operation_context with a
    'value too large' marker, the larger of the two first, and stop as soon as the
    row fits. Only keys that are present are touched. A replaced operation_context
    keeps Core's own keys (browser_provenance, core_refusal, server_provenance with its operation and tactical_status). Core keys (source,
    module_id, module_version, correlation_id, actor_*) always stay.
    """
    max_bytes = _max_value_bytes()
    if _debug_info_bytes(debug_info) <= max_bytes:
        return debug_info
    fitted = dict(debug_info)
    present = [key for key in ("metadata", "operation_context") if key in fitted]
    sizes = {key: _debug_info_bytes({key: fitted[key]}) for key in present}
    for key in sorted(present, key=lambda item: -sizes[item]):
        marker = {
            "error": "value too large to store in audit log. Check documentation for configuring AUDIT_MAX_VALUE_BYTES",
            "original_bytes": sizes[key],
        }
        if key == "operation_context":
            _keep_browser_provenance(marker, fitted[key])
        fitted[key] = marker
        if _debug_info_bytes(fitted) <= max_bytes:
            break
    return fitted


def _bounded_value(value: Any, label: str, *, maximum: int | None = None) -> Any:
    if value is None:
        return None
    try:
        from django.conf import settings
        limit = int(maximum or getattr(settings, "AUDIT_MAX_VALUE_BYTES", 512 * 2**10))
    except Exception:
        limit = int(maximum or 512 * 2**10)
    try:
        encoded = _tactical_json_bytes(value)
    except Exception as exc:
        raise AuditContractError(f"{label} could not be serialized.") from exc
    if len(encoded) > limit:
        raise AuditContractError(f"{label} exceeds the audit size limit ({limit} bytes).")
    return value


def _auditlog_model():
    # The Tactical import lives only inside Core. Extensions must never import it.
    from logs.models import AuditLog
    return AuditLog


def record(
    *,
    actor,
    module_id: str,
    action: str,
    object_type: str,
    object_id: Any = None,
    message: Any = None,
    before: Any = None,
    after: Any = None,
    metadata: dict | None = None,
    operation_context: dict | None = None,
    request=None,
    correlation_id: Any = None,
    strict: bool = False,
) -> dict[str, Any]:
    """Persist one Tec-Tac event through Tactical's native AuditLog.

    Validation errors are contract errors and are always raised. Persistence
    failures are non-fatal by default: they are logged at ERROR and returned as
    ``recorded=False``. Pass ``strict=True`` only when a Core-owned workflow has
    explicitly decided audit persistence is transaction-critical.

    ``operation_context.core_refusal``, ``browser_provenance`` and ``server_provenance``
    are Core-owned: only Core's own rows set them, so a caller that supplies any of
    them gets a contract error (``browser_provenance`` and ``server_provenance``
    since 1.17.6 and 1.17.7).
    """
    if isinstance(operation_context, dict):
        for key in CORE_CONTEXT_KEYS:
            if key in operation_context:
                raise AuditContractError(f"operation_context.{key} is Core-owned and may not be supplied.")
    return _record_row(
        actor=actor, module_id=module_id, action=action, object_type=object_type, object_id=object_id,
        message=message, before=before, after=after, metadata=metadata, operation_context=operation_context,
        request=request, correlation_id=correlation_id, strict=strict,
    )


def record_core_refusal(
    *,
    actor,
    module_id: str,
    object_type: str,
    object_id: Any,
    message: str,
    metadata: dict,
    request=None,
) -> dict[str, Any]:
    """Write Core's own 'deny' row for a refused browser event.

    Used only by the browser audit view. The row carries the browser_provenance
    marker and operation_context.core_refusal = true, so it can be told apart from
    a 'deny' event a module declared and posted itself. Never strict: a failed
    deny write must not turn the refusal into a 500.
    """
    return _record_row(
        actor=actor, module_id=module_id, action="deny", object_type=object_type, object_id=object_id,
        message=message, metadata=metadata, request=request, strict=False,
        operation_context={"browser_provenance": BROWSER_PROVENANCE_MARKER, "core_refusal": True},
    )


def record_browser_declared(
    *,
    actor,
    module_id: str,
    action: str,
    object_type: str,
    object_id: Any = None,
    message: Any = None,
    before: Any = None,
    after: Any = None,
    metadata: dict | None = None,
    request=None,
) -> dict[str, Any]:
    """Write the row of a browser-declared event (Core 1.16.0 path), marked browser_provenance.

    Used only by the browser audit view. The public ``record()`` refuses ``browser_provenance`` since 1.17.6, so the
    view calls this Core-internal writer. Never strict.
    """
    return _record_row(
        actor=actor, module_id=module_id, action=action, object_type=object_type, object_id=object_id,
        message=message, before=before, after=after, metadata=metadata, request=request, strict=False,
        operation_context={"browser_provenance": BROWSER_PROVENANCE_MARKER},
    )


def record_tactical_operation(
    *,
    actor,
    module_id: str,
    action: str,
    object_type: str,
    object_id: Any = None,
    message: Any = None,
    before: Any = None,
    after: Any = None,
    metadata: dict | None = None,
    operation: str,
    tactical_status: int | None = None,
    refusal: bool = False,
    request=None,
) -> dict[str, Any]:
    """Write the row of a Tactical call Core ran server-side (1.17.7). Core-internal; never strict.

    The actor is the signed-in user and the module is the one that declared the operation. Core passes its internal
    authority, so a person acting only under a Tactical permission is not blocked by the module-permission check.
    The row carries operation_context.server_provenance, operation and tactical_status. ``refusal`` adds
    core_refusal = true, for Core's own deny rows.
    """
    context = {
        "server_provenance": SERVER_PROVENANCE_TACTICAL_OPERATION,
        "operation": str(operation)[:100],
        "tactical_status": tactical_status,
    }
    if refusal:
        context["core_refusal"] = True
    return _record_row(
        actor=actor, module_id=module_id, action=action, object_type=object_type, object_id=object_id,
        message=message, before=before, after=after, metadata=metadata, request=request, strict=False,
        operation_context=context, authority=_TACTICAL_OPERATION_AUTHORITY,
    )


def _record_row(
    *,
    actor,
    module_id: str,
    action: str,
    object_type: str,
    object_id: Any = None,
    message: Any = None,
    before: Any = None,
    after: Any = None,
    metadata: dict | None = None,
    operation_context: dict | None = None,
    request=None,
    correlation_id: Any = None,
    strict: bool = False,
    authority=None,
) -> dict[str, Any]:
    module = _resolve_module(module_id)
    username, actor_info = _actor_provenance(actor, module, authority)
    normalized_action = _normalize_action(action)
    normalized_object_type = _normalize_object_type(object_type)
    oid = None if object_id is None else str(object_id)[:255]
    if message is not None and len(str(message).encode("utf-8")) > 4096:
        raise AuditContractError("message exceeds the audit size limit (4096 bytes).")
    before = _bounded_value(before, "before")
    after = _bounded_value(after, "after")
    if operation_context is None:
        operation_context = {}
    if not isinstance(operation_context, dict):
        raise AuditContractError("operation_context must be an object when provided.")
    op_context = _safe_metadata(operation_context)
    if op_context is not operation_context:
        _keep_browser_provenance(op_context, operation_context)
    op_correlation = op_context.get("correlation_id") if isinstance(op_context, dict) else None
    cid = _correlation_id(request, correlation_id or op_correlation)

    debug_info = {
        "source": "tec-tac",
        "module_id": module["id"],
        "module_version": module["version"],
        "object_id": oid,
        "correlation_id": cid,
        "metadata": _safe_metadata(metadata),
        "operation_context": op_context,
        **actor_info,
    }
    # Keep null provenance keys out of Tactical output without losing stable fields.
    debug_info = {key: value for key, value in debug_info.items() if value is not None}
    debug_info = _fit_debug_info(debug_info)

    try:
        row = _auditlog_model().objects.create(
            username=username,
            action=normalized_action,
            object_type=normalized_object_type,
            before_value=before,
            after_value=after,
            message=None if message is None else str(message),
            debug_info=debug_info,
        )
        return {
            "recorded": True,
            "id": getattr(row, "pk", getattr(row, "id", None)),
            "username": username,
            "action": normalized_action,
            "object_type": normalized_object_type,
            "module_id": module["id"],
            "module_version": module["version"],
            "correlation_id": cid,
        }
    except Exception as exc:
        logger.exception(
            "Tec-Tac audit write failed module=%s action=%s object_type=%s actor=%s",
            module["id"], normalized_action, normalized_object_type, username,
        )
        if strict:
            raise AuditWriteError("Tec-Tac audit write failed.") from exc
        return {
            "recorded": False,
            "error": "audit_write_failed",
            "error_type": exc.__class__.__name__,
            "module_id": module["id"],
        }


class AuditProvider:
    """Backend public contract exposed to server-side Tec-Tac modules."""

    def record(self, *, actor, module_id: str, **event):
        return record(actor=actor, module_id=module_id, **event)

    def service_actor(self, *, module_id: str, service: str, identity: str | None = None):
        return service_audit_actor(module_id=module_id, service=service, identity=identity)

    def device_actor(self, *, module_id: str, device_id: str, identity: str | None = None, service: str | None = None):
        return device_audit_actor(module_id=module_id, device_id=device_id, identity=identity, service=service)


_PROVIDER = AuditProvider()


def get_audit_provider() -> AuditProvider:
    return _PROVIDER

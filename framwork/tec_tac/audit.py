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
from pathlib import Path
from typing import Any

logger = logging.getLogger("tec_tac.audit")

STANDARD_ACTIONS = frozenset({
    "add", "modify", "delete", "run", "approve", "deny", "enable", "disable",
    "install", "uninstall", "view", "export", "import", "sync", "test",
    "acknowledge", "resolve",
})
_CUSTOM_ACTION_RE = re.compile(r"^custom:[a-z0-9][a-z0-9_-]{0,63}$")
_OBJECT_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,99}$")


class AuditContractError(ValueError):
    """Invalid public audit event or module/actor context."""


class AuditWriteError(RuntimeError):
    """Tactical AuditLog persistence failed in strict mode."""


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
    return {"id": plugin.plugin_id, "version": str(plugin.version or "0.0.0"), "permissions": permissions, "legacy": bool(plugin.legacy)}


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


def _correlation_id(request=None, explicit: Any = None) -> str | None:
    value = str(explicit or "").strip()
    if value:
        return value[:255]
    if request is None:
        return None
    for attr in ("tec_tac_request_id", "correlation_id", "request_id"):
        value = str(getattr(request, attr, "") or "").strip()
        if value:
            return value[:255]
    meta = getattr(request, "META", {}) or {}
    for key in ("HTTP_X_REQUEST_ID", "HTTP_X_CORRELATION_ID"):
        value = str(meta.get(key) or "").strip()
        if value:
            return value[:255]
    return None


def _safe_metadata(metadata: Any) -> Any:
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise AuditContractError("metadata must be an object when provided.")
    try:
        from django.conf import settings
        max_bytes = int(getattr(settings, "AUDIT_MAX_VALUE_BYTES", 512 * 2**10))
    except Exception:
        max_bytes = 512 * 2**10
    # Reserve headroom for Core provenance so oversized module metadata does not
    # cause Tactical to replace the entire debug_info object.
    budget = max(1024, max_bytes - 8192)
    try:
        encoded = json.dumps(metadata, ensure_ascii=False, default=str).encode("utf-8")
    except Exception:
        return {"error": "could not process audit metadata"}
    if len(encoded) > budget:
        return {
            "error": "value too large to store in audit log. Check documentation for configuring AUDIT_MAX_VALUE_BYTES",
            "original_bytes": len(encoded),
        }
    return metadata


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
    request=None,
    correlation_id: Any = None,
    strict: bool = False,
) -> dict[str, Any]:
    """Persist one Tec-Tac event through Tactical's native AuditLog.

    Validation errors are contract errors and are always raised. Persistence
    failures are non-fatal by default: they are logged at ERROR and returned as
    ``recorded=False``. Pass ``strict=True`` only when a Core-owned workflow has
    explicitly decided audit persistence is transaction-critical.
    """
    module = _resolve_module(module_id)
    if not getattr(actor, "is_authenticated", False):
        raise AuditContractError("actor must be an authenticated Tactical user.")
    if not _actor_can_use_module(actor, module):
        raise AuditContractError(f"actor is not permitted to use Tec-Tac module {module_id!r}.")

    username = str(getattr(actor, "username", "") or "").strip()
    if not username:
        raise AuditContractError("authenticated actor does not expose a username.")
    normalized_action = _normalize_action(action)
    normalized_object_type = _normalize_object_type(object_type)
    oid = None if object_id is None else str(object_id)[:255]
    cid = _correlation_id(request, correlation_id)

    debug_info = {
        "source": "tec-tac",
        "module_id": module["id"],
        "module_version": module["version"],
        "object_id": oid,
        "correlation_id": cid,
        "metadata": _safe_metadata(metadata),
    }
    # Keep null provenance keys out of Tactical output without losing stable fields.
    debug_info = {key: value for key, value in debug_info.items() if value is not None}

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


_PROVIDER = AuditProvider()


def get_audit_provider() -> AuditProvider:
    return _PROVIDER

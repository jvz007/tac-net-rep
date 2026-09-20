"""Tec-Tac cross-module capability registry.

Modules register narrow, versioned public provider contracts during Django
application startup. Consumers resolve those contracts through this framework
module instead of importing another extension's private implementation or
looping back through Tec-Tac HTTP APIs.

Capability availability is evaluated at lookup time so installed/enabled state,
version compatibility, and provider health can change safely after startup.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from threading import RLock
from typing import Any, Callable

from .module_state import ModuleStateError, is_enabled, version_satisfies
from .registry import RegistryError, get_plugin


__all__ = [
    "CapabilityError",
    "CapabilityUnavailable",
    "CapabilityDisabled",
    "CapabilityVersionMismatch",
    "CapabilityUnhealthy",
    "CapabilityOperationError",
    "CapabilityRegistration",
    "register_capability",
    "get_capability",
    "has_capability",
    "capability_status",
    "list_capabilities",
    "build_operation_context",
]


class CapabilityError(RuntimeError):
    """Base class for Tec-Tac capability failures."""

    state = "capability-error"

    def __init__(self, capability_id: str, message: str, *, status: dict | None = None):
        super().__init__(message)
        self.capability_id = capability_id
        self.status = status or {}


class CapabilityUnavailable(CapabilityError):
    state = "capability-unavailable"


class CapabilityDisabled(CapabilityUnavailable):
    state = "disabled"


class CapabilityVersionMismatch(CapabilityUnavailable):
    state = "version-incompatible"


class CapabilityUnhealthy(CapabilityUnavailable):
    state = "unhealthy"


class CapabilityOperationError(CapabilityError):
    state = "operation-error"


@dataclass(frozen=True)
class CapabilityRegistration:
    id: str
    module_id: str
    version: str
    provider: object = field(compare=False, repr=False)
    description: str = ""
    health: Callable[[], object] | None = field(default=None, compare=False, repr=False)
    operations: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)


_CAPABILITIES: dict[str, CapabilityRegistration] = {}
_CAPABILITY_LOCK = RLock()


def _clean_identifier(value: str, label: str) -> str:
    value = str(value or "").strip()
    if not value:
        raise ValueError(f"{label} is required.")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if any(ch not in allowed for ch in value):
        raise ValueError(f"{label} contains unsupported characters: {value!r}")
    return value


def _validate_capability_version(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        raise ValueError("Capability version is required.")
    try:
        # Parse both sides through the framework's existing semantic-version
        # implementation. Using an exact self-comparison keeps one canonical
        # version parser for module and capability compatibility.
        version_satisfies(value, f"=={value}")
    except ModuleStateError as exc:
        raise ValueError(f"Invalid capability version: {value!r}") from exc
    return value


def register_capability(
    *,
    id: str,
    module_id: str,
    version: str,
    provider: object,
    description: str = "",
    health: Callable[[], object] | None = None,
    operations=(),
    metadata: dict[str, Any] | None = None,
) -> CapabilityRegistration:
    """Register a public module capability for the current Python process.

    Registration is normally called from the provider module's AppConfig.ready().
    The capability ID is namespaced by the provider module ID so runtime status
    can still be explained when the provider is absent and registration never ran.
    """
    capability_id = _clean_identifier(id, "Capability id")
    owner = _clean_identifier(module_id, "Capability module_id")
    if "." not in capability_id:
        raise ValueError("Capability id must be namespaced, for example communicator.messaging.")
    if owner != "tec-tac" and not capability_id.startswith(owner + "."):
        raise ValueError(
            f"Capability id {capability_id!r} must begin with provider module prefix {owner + '.'!r}."
        )
    cap_version = _validate_capability_version(version)
    if provider is None:
        raise ValueError("Capability provider is required.")
    if health is not None and not callable(health):
        raise TypeError("Capability health callback must be callable.")
    ops = tuple(str(item).strip() for item in operations if str(item).strip())
    if len(set(ops)) != len(ops):
        raise ValueError("Capability operations contains duplicate values.")
    meta = dict(metadata or {})
    try:
        json.dumps(meta)
    except TypeError as exc:
        raise ValueError("Capability metadata must be JSON-serializable.") from exc

    registration = CapabilityRegistration(
        id=capability_id,
        module_id=owner,
        version=cap_version,
        provider=provider,
        description=str(description or "").strip(),
        health=health,
        operations=ops,
        metadata=meta,
    )

    with _CAPABILITY_LOCK:
        previous = _CAPABILITIES.get(capability_id)
        if previous is not None:
            # AppConfig.ready() should only register once per process. Treat an
            # identical public contract as idempotent while refusing ambiguous
            # duplicate providers or changed contract metadata.
            same_contract = (
                previous.module_id == registration.module_id
                and previous.version == registration.version
                and previous.description == registration.description
                and previous.operations == registration.operations
                and previous.provider is registration.provider
                and previous.health == registration.health
            )
            if same_contract:
                return previous
            raise ValueError(f"Capability {capability_id!r} is already registered by {previous.module_id!r}.")
        _CAPABILITIES[capability_id] = registration
    return registration


def _registration(capability_id: str) -> CapabilityRegistration | None:
    with _CAPABILITY_LOCK:
        return _CAPABILITIES.get(capability_id)


def _provider_module_status(module_id: str) -> tuple[str, str | None, str | None]:
    """Return (state, installed_version, reason) for a provider module."""
    if module_id in {"tec-tac", "core"}:
        return "available", None, None
    try:
        plugin = get_plugin(module_id, "extension")
    except RegistryError:
        return "missing", None, f"Provider module {module_id!r} is not installed."
    try:
        enabled = is_enabled(module_id)
    except ModuleStateError as exc:
        return "unhealthy", plugin.version, f"Provider module state is unreadable: {exc}"
    if not enabled:
        return "disabled", plugin.version, f"Provider module {module_id!r} is disabled."
    return "available", plugin.version, None


def _health_status(registration: CapabilityRegistration) -> tuple[bool, str | None, dict]:
    callback = registration.health
    if callback is None:
        return True, None, {}
    try:
        value = callback()
    except Exception as exc:  # provider health must never break registry discovery
        return False, f"Capability health check raised {exc.__class__.__name__}: {exc}", {
            "error_type": exc.__class__.__name__
        }

    if isinstance(value, bool):
        return value, None if value else "Provider health check reported unhealthy.", {}
    if isinstance(value, tuple) and len(value) == 2:
        healthy, reason = value
        return bool(healthy), str(reason) if reason else None, {}
    if isinstance(value, dict):
        details = dict(value)
        try:
            details = json.loads(json.dumps(details, default=str))
        except Exception:
            details = {"value": str(value)}
        if "healthy" in details:
            healthy = bool(details.get("healthy"))
        elif "available" in details:
            healthy = bool(details.get("available"))
        else:
            healthy = True
        reason = details.get("reason") or details.get("message")
        return healthy, str(reason) if reason else None, details
    healthy = bool(value)
    return healthy, None if healthy else "Provider health check reported unhealthy.", {}


def capability_status(
    capability_id: str,
    *,
    version: str | None = None,
    module_id: str | None = None,
) -> dict:
    """Return a structured runtime availability result for one capability."""
    capability_id = _clean_identifier(capability_id, "Capability id")
    registration = _registration(capability_id)
    owner = registration.module_id if registration else str(module_id or capability_id.split(".", 1)[0]).strip()

    module_state, installed_version, module_reason = _provider_module_status(owner)
    base = {
        "id": capability_id,
        "module_id": owner,
        "available": False,
        "state": module_state,
        "required_version": str(version or "").strip() or None,
        "installed_version": installed_version,
        "capability_version": registration.version if registration else None,
        "description": registration.description if registration else "",
        "operations": list(registration.operations) if registration else [],
        "metadata": dict(registration.metadata) if registration else {},
        "reason": module_reason,
        "health": {},
    }

    if module_state != "available":
        return base

    if registration is None:
        base.update(
            state="capability-unavailable",
            reason=f"Provider module {owner!r} is enabled but capability {capability_id!r} is not registered in this runtime.",
        )
        return base

    if version:
        try:
            compatible = version_satisfies(registration.version, version)
        except ModuleStateError as exc:
            base.update(state="version-incompatible", reason=f"Invalid requested capability version range: {exc}")
            return base
        if not compatible:
            base.update(
                state="version-incompatible",
                reason=(
                    f"Capability {capability_id!r} version {registration.version} does not satisfy {version}."
                ),
            )
            return base

    healthy, health_reason, health_details = _health_status(registration)
    base["health"] = health_details
    if not healthy:
        base.update(state="unhealthy", reason=health_reason or "Capability provider is unhealthy.")
        return base

    base.update(available=True, state="available", reason=None)
    return base


def _exception_for_status(status: dict) -> CapabilityUnavailable:
    capability_id = status.get("id") or "unknown"
    reason = status.get("reason") or f"Capability {capability_id!r} is unavailable."
    state = status.get("state")
    if state == "disabled":
        return CapabilityDisabled(capability_id, reason, status=status)
    if state == "version-incompatible":
        return CapabilityVersionMismatch(capability_id, reason, status=status)
    if state == "unhealthy":
        return CapabilityUnhealthy(capability_id, reason, status=status)
    return CapabilityUnavailable(capability_id, reason, status=status)


def get_capability(
    capability_id: str,
    *,
    version: str | None = None,
    required: bool = True,
    module_id: str | None = None,
):
    """Resolve and return a public provider contract.

    When ``required=False`` an unavailable/incompatible capability returns None.
    Required lookups raise a framework-level CapabilityUnavailable subclass.
    """
    status = capability_status(capability_id, version=version, module_id=module_id)
    if not status["available"]:
        if not required:
            return None
        raise _exception_for_status(status)
    registration = _registration(capability_id)
    if registration is None:  # defensive: status available implies registration
        if not required:
            return None
        raise CapabilityUnavailable(capability_id, "Capability registration disappeared during lookup.", status=status)
    return registration.provider


def has_capability(capability_id: str, *, version: str | None = None, module_id: str | None = None) -> bool:
    return bool(capability_status(capability_id, version=version, module_id=module_id)["available"])


def list_capabilities(*, include_unavailable: bool = True) -> list[dict]:
    """List registered capability metadata with live runtime status."""
    with _CAPABILITY_LOCK:
        ids = sorted(_CAPABILITIES)
    rows = [capability_status(capability_id) for capability_id in ids]
    if not include_unavailable:
        rows = [row for row in rows if row["available"]]
    return rows


def build_operation_context(
    *,
    source_module: str,
    source_action: str,
    source_run_id: str | None = None,
    requested_by: str | None = None,
    **extra,
) -> dict:
    """Build common audit/source context for cross-module operations."""
    context = {
        "source_module": str(source_module or "").strip(),
        "source_action": str(source_action or "").strip(),
        "source_run_id": str(source_run_id) if source_run_id not in (None, "") else None,
        "requested_by": str(requested_by) if requested_by not in (None, "") else None,
    }
    context.update(extra)
    return context


def _clear_capabilities_for_tests() -> None:
    """Private test helper; never use for production lifecycle management."""
    with _CAPABILITY_LOCK:
        _CAPABILITIES.clear()

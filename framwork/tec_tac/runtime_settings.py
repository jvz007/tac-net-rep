"""Core runtime settings the browser shell reads (1.17.1).

One is how long a module's ``register()`` may take before the UI marks the module
failed and carries on. The UI, not modules, applies the limit. Core only stores it
and publishes it in ``GET /api/tfd/ui/context/`` as ``module_register_timeout_seconds``.

The other (1.17.2) is the remembered update source per component: release or a
branch, read by the System Updates page and used as the default when staging.
"""
from __future__ import annotations

import re

from django.db import transaction
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import TecTacRuntimeConfig
from .rbac import can_manage_runtime_settings, is_effective_superuser
from .session_security import SessionAuthenticated
from .throttles import RuntimeSettingsWriteDayThrottle, RuntimeSettingsWriteMinThrottle

SETTING_MODULE_REGISTER_TIMEOUT = "module_register_timeout_seconds"
DEFAULT_MODULE_REGISTER_TIMEOUT_SECONDS = 30
MIN_MODULE_REGISTER_TIMEOUT_SECONDS = 5
MAX_MODULE_REGISTER_TIMEOUT_SECONDS = 300


RUNTIME_SETTINGS_DENIED = (
    "Tec-Tac core.runtime_settings.manage or core.privileged_operations permission is required to change runtime settings."
)


# Update source: superusers only (CQ12, Johan, 9 October 2026; 1.17.5). Staging and installing
# keep core.privileged_operations.
UPDATE_SOURCE_DENIED = "Only a Tec-Tac superuser may change the update source."


class RuntimeSettingsError(ValueError):
    pass


def validate_module_register_timeout_seconds(value) -> int:
    """Accept only a whole number of seconds from 5 to 300.

    bool, float, string and None are rejected on purpose: ``True`` is an ``int`` in
    Python, and ``"30"`` or ``30.5`` would be silently coerced by a looser check.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeSettingsError(f"{SETTING_MODULE_REGISTER_TIMEOUT} must be a whole number of seconds.")
    if value < MIN_MODULE_REGISTER_TIMEOUT_SECONDS or value > MAX_MODULE_REGISTER_TIMEOUT_SECONDS:
        raise RuntimeSettingsError(
            f"{SETTING_MODULE_REGISTER_TIMEOUT} must be between "
            f"{MIN_MODULE_REGISTER_TIMEOUT_SECONDS} and {MAX_MODULE_REGISTER_TIMEOUT_SECONDS}."
        )
    return value


def get_module_register_timeout_seconds() -> int:
    """Return the configured limit. Never raises.

    This sits on the UI startup path (``UiContextView``), so a database error must
    not stop sign-in or the shell. Any failure, or a stored value outside the valid
    range, returns the default.
    """
    try:
        value = int(TecTacRuntimeConfig.current().module_register_timeout_seconds)
        return validate_module_register_timeout_seconds(value)
    except Exception:
        return DEFAULT_MODULE_REGISTER_TIMEOUT_SECONDS


def serialize_runtime_settings(config=None) -> dict:
    config = config or TecTacRuntimeConfig.current()
    return {
        SETTING_MODULE_REGISTER_TIMEOUT: {
            "value": int(config.module_register_timeout_seconds),
            "minimum": MIN_MODULE_REGISTER_TIMEOUT_SECONDS,
            "maximum": MAX_MODULE_REGISTER_TIMEOUT_SECONDS,
            "default": DEFAULT_MODULE_REGISTER_TIMEOUT_SECONDS,
        },
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
        "updated_by": config.updated_by.username if config.updated_by else None,
    }


def _audit_change(user, before: int, after: int) -> None:
    """Strict Core audit row, written in the same transaction as the change."""
    from .audit import record

    record(
        actor=user,
        module_id="core",
        action="modify",
        object_type="runtime_settings",
        object_id=SETTING_MODULE_REGISTER_TIMEOUT,
        message="Tec-Tac runtime setting changed.",
        before={SETTING_MODULE_REGISTER_TIMEOUT: before},
        after={SETTING_MODULE_REGISTER_TIMEOUT: after},
        strict=True,
    )


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Runtime Settings"], summary="Get the Core runtime settings"),
    patch=extend_schema(tags=["Tec-Tac Runtime Settings"], summary="Change the module register() time limit"),
)
class RuntimeSettingsView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [RuntimeSettingsWriteMinThrottle, RuntimeSettingsWriteDayThrottle]

    def get(self, request):
        return Response(serialize_runtime_settings())

    def patch(self, request):
        if not can_manage_runtime_settings(request.user):
            raise PermissionDenied(RUNTIME_SETTINGS_DENIED)
        data = request.data
        if not isinstance(data, dict):
            return Response({"detail": "Runtime settings must be a JSON object."}, status=400)
        unknown = sorted(set(data) - {SETTING_MODULE_REGISTER_TIMEOUT})
        if unknown:
            return Response({"detail": "Unknown runtime setting(s): " + ", ".join(unknown)}, status=400)
        if SETTING_MODULE_REGISTER_TIMEOUT not in data:
            return Response({"detail": f"{SETTING_MODULE_REGISTER_TIMEOUT} is required."}, status=400)
        try:
            value = validate_module_register_timeout_seconds(data[SETTING_MODULE_REGISTER_TIMEOUT])
        except RuntimeSettingsError as exc:
            return Response({"detail": str(exc)}, status=400)
        with transaction.atomic():
            config = TecTacRuntimeConfig.objects.select_for_update().get(pk=TecTacRuntimeConfig.current().pk)
            before = int(config.module_register_timeout_seconds)
            if before != value:
                config.module_register_timeout_seconds = value
                config.updated_by = request.user
                config.save(update_fields=[SETTING_MODULE_REGISTER_TIMEOUT, "updated_by", "updated_at"])
                # A failed audit write raises and rolls the change back.
                _audit_change(request.user, before, value)
        return Response(serialize_runtime_settings(config))


# --------------------------------------------------------------- update source (1.17.2)
UPDATE_COMPONENTS = ("framework", "ui")
UPDATE_SOURCE_TYPES = ("release", "branch")
UPDATE_BRANCH_MAX_LENGTH = 200
# Letters, digits and . _ / - only. The shape rules below catch the git-invalid forms.
_BRANCH_CHARS = re.compile(r"[A-Za-z0-9._/-]+")


class UpdateSourceError(ValueError):
    pass


def default_update_source() -> dict:
    return {"type": "release", "ref": None}


def validate_branch_ref(value) -> str:
    """A strict branch name. It is not checked against GitHub on save."""
    if not isinstance(value, str):
        raise UpdateSourceError("ref must be a branch name.")
    if not value or len(value) > UPDATE_BRANCH_MAX_LENGTH:
        raise UpdateSourceError(f"ref must be 1 to {UPDATE_BRANCH_MAX_LENGTH} characters.")
    if not _BRANCH_CHARS.fullmatch(value):
        raise UpdateSourceError("ref may only contain letters, digits and . _ / -")
    if (
        ".." in value
        or "//" in value
        or value[0] in "-/"
        or value.endswith(("/", ".lock", "."))
    ):
        raise UpdateSourceError("ref is not a valid branch name.")
    return value


def validate_update_source(type_value, ref) -> dict:
    if isinstance(type_value, bool) or type_value not in UPDATE_SOURCE_TYPES:
        raise UpdateSourceError("type must be release or branch.")
    if type_value == "release":
        return default_update_source()
    return {"type": "branch", "ref": validate_branch_ref(ref)}


def _stored_update_source(config, component: str) -> dict:
    try:
        raw = (config.update_sources or {}).get(component)
        if not isinstance(raw, dict):
            return default_update_source()
        return validate_update_source(raw.get("type"), raw.get("ref"))
    except Exception:
        return default_update_source()


def get_update_source(component: str) -> dict:
    """Return the remembered ``{type, ref}`` for ``framework`` or ``ui``. Never raises.

    A missing, invalid or unreadable value reads as the default: release, ref None.
    """
    try:
        if component not in UPDATE_COMPONENTS:
            return default_update_source()
        return _stored_update_source(TecTacRuntimeConfig.current(), component)
    except Exception:
        return default_update_source()


def get_update_sources() -> dict:
    return {component: get_update_source(component) for component in UPDATE_COMPONENTS}


def serialize_update_sources(config=None) -> dict:
    config = config or TecTacRuntimeConfig.current()
    return {
        "update_sources": {component: _stored_update_source(config, component) for component in UPDATE_COMPONENTS},
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
        "updated_by": config.updated_by.username if config.updated_by else None,
    }


def _audit_update_source_change(user, component: str, before: dict, after: dict) -> None:
    """Strict Core audit row, written in the same transaction as the change."""
    from .audit import record

    record(
        actor=user,
        module_id="core",
        action="modify",
        object_type="update_source",
        object_id=component,
        message="Tec-Tac update source changed.",
        before=before,
        after=after,
        strict=True,
    )


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Runtime Settings"], summary="Get the remembered update source for framework and ui"),
    patch=extend_schema(tags=["Tec-Tac Runtime Settings"], summary="Change the remembered update source for one component"),
)
class UpdateSourceView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [RuntimeSettingsWriteMinThrottle, RuntimeSettingsWriteDayThrottle]

    def get(self, request):
        return Response(serialize_update_sources())

    def patch(self, request):
        # Checked before the body, so a non-superuser gets 403 and never 400.
        if not is_effective_superuser(request.user):
            raise PermissionDenied(UPDATE_SOURCE_DENIED)
        data = request.data
        if not isinstance(data, dict):
            return Response({"detail": "The update source must be a JSON object."}, status=400)
        unknown = sorted(set(data) - {"component", "type", "ref"})
        if unknown:
            return Response({"detail": "Unknown field(s): " + ", ".join(unknown)}, status=400)
        component = data.get("component")
        if isinstance(component, bool) or component not in UPDATE_COMPONENTS:
            return Response({"detail": "component must be framework or ui."}, status=400)
        try:
            after = validate_update_source(data.get("type"), data.get("ref"))
        except UpdateSourceError as exc:
            return Response({"detail": str(exc)}, status=400)
        with transaction.atomic():
            config = TecTacRuntimeConfig.objects.select_for_update().get(pk=TecTacRuntimeConfig.current().pk)
            before = _stored_update_source(config, component)
            if before != after:
                sources = dict(config.update_sources) if isinstance(config.update_sources, dict) else {}
                sources[component] = after
                config.update_sources = sources
                config.updated_by = request.user
                config.save(update_fields=["update_sources", "updated_by", "updated_at"])
                # A failed audit write raises and rolls the change back.
                _audit_update_source_change(request.user, component, before, after)
        return Response(serialize_update_sources(config))

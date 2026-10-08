"""Core runtime settings the browser shell reads (1.17.1).

Today there is one: how long a module's ``register()`` may take before the UI marks
the module failed and carries on. The UI, not modules, applies the limit. Core only
stores it and publishes it in ``GET /api/tfd/ui/context/`` as
``module_register_timeout_seconds``.
"""
from __future__ import annotations

from django.db import transaction
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import TecTacRuntimeConfig
from .rbac import can_manage_privileged_operations
from .session_security import SessionAuthenticated
from .throttles import RuntimeSettingsWriteDayThrottle, RuntimeSettingsWriteMinThrottle

SETTING_MODULE_REGISTER_TIMEOUT = "module_register_timeout_seconds"
DEFAULT_MODULE_REGISTER_TIMEOUT_SECONDS = 30
MIN_MODULE_REGISTER_TIMEOUT_SECONDS = 5
MAX_MODULE_REGISTER_TIMEOUT_SECONDS = 300


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
        if not can_manage_privileged_operations(request.user):
            raise PermissionDenied("Tec-Tac core.privileged_operations permission is required to change runtime settings.")
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

"""Core runtime settings the browser shell reads (1.17.1).

One is how long a module's ``register()`` may take before the UI marks the module
failed and carries on. The UI, not modules, applies the limit. Core only stores it
and publishes it in ``GET /api/tfd/ui/context/`` as ``module_register_timeout_seconds``.

The other (1.17.2) is the remembered update source per component: release or a
branch, read by the System Updates page and used as the default when staging.

1.17.14 (CQ40): ``tactical_operation_upload_max_mib`` is the largest file one Tactical operation may forward, in whole
MiB (1 to 25, default 10). Only a superuser changes it. The executor reads it on every call, so a change takes effect at once.

1.17.23: ``system_name`` is the name an authenticator app shows for this system (plain text, 1 to 60 characters, default
``Tec-Tac``, no colon). Whoever may change the register timeout may change it.

1.17.26: ``priority_mail_private_relay`` (strict bool, default off, AD-30) lets Core's own Priority 1 email go to a mail server on a
private network. Only an effective superuser changes it. ``get_priority_mail_private_relay`` is for Core's own code and is not in the
public Python contract, so no module can read it.

1.17.24: only an effective superuser may change ``system_name`` (held Low of the 1.17.23 review). A refusal writes one
best-effort Core ``deny`` row, and so does the upload-limit refusal.
"""
from __future__ import annotations

import logging
import re
import unicodedata

from django.db import transaction
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import TecTacRuntimeConfig
from .rbac import can_manage_runtime_settings, is_effective_superuser
from .session_security import SessionAuthenticated
from .throttles import RuntimeSettingsWriteDayThrottle, RuntimeSettingsWriteMinThrottle

logger = logging.getLogger("tec_tac.runtime_settings")

SETTING_MODULE_REGISTER_TIMEOUT = "module_register_timeout_seconds"
DEFAULT_MODULE_REGISTER_TIMEOUT_SECONDS = 30
MIN_MODULE_REGISTER_TIMEOUT_SECONDS = 5
MAX_MODULE_REGISTER_TIMEOUT_SECONDS = 300

SETTING_TACTICAL_UPLOAD_MAX_MIB = "tactical_operation_upload_max_mib"
DEFAULT_TACTICAL_UPLOAD_MAX_MIB = 10
MIN_TACTICAL_UPLOAD_MAX_MIB = 1
MAX_TACTICAL_UPLOAD_MAX_MIB = 25
_MIB = 2**20
SETTING_SYSTEM_NAME = "system_name"
DEFAULT_SYSTEM_NAME = "Tec-Tac"
MAX_SYSTEM_NAME_LENGTH = 60
SETTING_PRIORITY_MAIL_PRIVATE_RELAY = "priority_mail_private_relay"
DEFAULT_PRIORITY_MAIL_PRIVATE_RELAY = False
PRIORITY_MAIL_PRIVATE_RELAY_WARNING = (
    "This lets Core's own Priority 1 email go to a mail server on a private network (for example 10.x or 192.168.x). "
    "It changes nothing else. Other modules never use it, and cloud metadata, loopback and link-local addresses stay refused."
)
RUNTIME_SETTING_NAMES = (SETTING_MODULE_REGISTER_TIMEOUT, SETTING_TACTICAL_UPLOAD_MAX_MIB, SETTING_SYSTEM_NAME, SETTING_PRIORITY_MAIL_PRIVATE_RELAY)


RUNTIME_SETTINGS_DENIED = (
    "Tec-Tac core.runtime_settings.manage or core.privileged_operations permission is required to change runtime settings."
)


# Update source: superusers only (CQ12, Johan, 9 October 2026; 1.17.5). Staging and installing
# keep core.privileged_operations.
UPDATE_SOURCE_DENIED = "Only a Tec-Tac superuser may change the update source."

# The upload ceiling: superusers only, the same rule as the update source (CQ40 assumption, 1.17.14). The register timeout
# keeps core.runtime_settings.manage.
UPLOAD_LIMIT_DENIED = "Only a Tec-Tac superuser may change the Tactical operation upload limit."

# The system name: superusers only (1.17.24). The register timeout keeps core.runtime_settings.manage.
SYSTEM_NAME_DENIED = "Only a Tec-Tac superuser may change the system name."

# The private relay switch: superusers only (1.17.26, AD-30).
PRIORITY_MAIL_PRIVATE_RELAY_DENIED = "Only a Tec-Tac superuser may change the private mail relay setting."


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


def validate_tactical_upload_max_mib(value) -> int:
    """Accept only a whole number of MiB from 1 to 25. bool, float, string and None are rejected, as for the timeout."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeSettingsError(f"{SETTING_TACTICAL_UPLOAD_MAX_MIB} must be a whole number of MiB.")
    if value < MIN_TACTICAL_UPLOAD_MAX_MIB or value > MAX_TACTICAL_UPLOAD_MAX_MIB:
        raise RuntimeSettingsError(
            f"{SETTING_TACTICAL_UPLOAD_MAX_MIB} must be between {MIN_TACTICAL_UPLOAD_MAX_MIB} and {MAX_TACTICAL_UPLOAD_MAX_MIB}."
        )
    return value


def validate_system_name(value) -> str:
    """Accept only plain text of 1 to 60 characters. Returns the NFC-normalised, trimmed name.

    A colon is refused, never altered: an otpauth label uses ':' to separate the issuer from the account. Control and
    format characters (zero-width and the like) are refused. bool, number, list and empty text are refused.
    """
    if not isinstance(value, str):
        raise RuntimeSettingsError(f"{SETTING_SYSTEM_NAME} must be text.")
    name = unicodedata.normalize("NFC", value).strip()
    if not name:
        raise RuntimeSettingsError(f"{SETTING_SYSTEM_NAME} must not be empty.")
    if len(name) > MAX_SYSTEM_NAME_LENGTH:
        raise RuntimeSettingsError(f"{SETTING_SYSTEM_NAME} must be at most {MAX_SYSTEM_NAME_LENGTH} characters.")
    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in name):
        raise RuntimeSettingsError(f"{SETTING_SYSTEM_NAME} must not contain control or invisible characters.")
    if ":" in name:
        raise RuntimeSettingsError(f"{SETTING_SYSTEM_NAME} must not contain a colon.")
    return name


def validate_priority_mail_private_relay(value) -> bool:
    """Accept only a real boolean. A number, text, a list and null are refused: ``1`` and ``"true"`` must never switch it on."""
    if not isinstance(value, bool):
        raise RuntimeSettingsError(f"{SETTING_PRIORITY_MAIL_PRIVATE_RELAY} must be true or false.")
    return value


def get_priority_mail_private_relay() -> bool:
    """Whether Core's own Priority 1 email may use a private-network mail server. Never raises, and fails closed: any error or any
    stored value that is not exactly True reads as False. Not in the public Python contract."""
    try:
        return TecTacRuntimeConfig.current().priority_mail_private_relay is True
    except Exception:
        return DEFAULT_PRIORITY_MAIL_PRIVATE_RELAY


def get_system_name() -> str:
    """The name an authenticator shows for this system. Never raises: any failure or invalid stored value gives ``Tec-Tac``."""
    try:
        return validate_system_name(TecTacRuntimeConfig.current().system_name)
    except Exception:
        return DEFAULT_SYSTEM_NAME


def get_tactical_upload_max_bytes() -> int:
    """The largest file one Tactical operation may forward, in bytes. Never raises.

    The executor reads this on every upload, so a database error must not stop a call. Any failure, or a stored value
    outside 1 to 25 MiB, returns the 10 MiB default."""
    try:
        value = int(TecTacRuntimeConfig.current().tactical_operation_upload_max_mib)
        return validate_tactical_upload_max_mib(value) * _MIB
    except Exception:
        logger.debug("Could not read the Tactical operation upload limit; using the default.", exc_info=True)
        return DEFAULT_TACTICAL_UPLOAD_MAX_MIB * _MIB


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
        SETTING_TACTICAL_UPLOAD_MAX_MIB: _serialize_upload_limit(config),
        SETTING_SYSTEM_NAME: _serialize_system_name(config),
        SETTING_PRIORITY_MAIL_PRIVATE_RELAY: _serialize_private_relay(config),
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
        "updated_by": config.updated_by.username if config.updated_by else None,
    }


def _serialize_upload_limit(config) -> dict:
    try:
        value = validate_tactical_upload_max_mib(int(config.tactical_operation_upload_max_mib))
    except (AttributeError, TypeError, ValueError, RuntimeSettingsError):
        value = DEFAULT_TACTICAL_UPLOAD_MAX_MIB  # what the executor uses for a value outside the range
    return {
        "value": value,
        "minimum": MIN_TACTICAL_UPLOAD_MAX_MIB,
        "maximum": MAX_TACTICAL_UPLOAD_MAX_MIB,
        "default": DEFAULT_TACTICAL_UPLOAD_MAX_MIB,
        "bytes": value * _MIB,
    }


def _serialize_system_name(config) -> dict:
    try:
        value = validate_system_name(config.system_name)
    except (AttributeError, TypeError, ValueError, RuntimeSettingsError):
        value = DEFAULT_SYSTEM_NAME
    return {"value": value, "maximum_length": MAX_SYSTEM_NAME_LENGTH, "default": DEFAULT_SYSTEM_NAME}


def _serialize_private_relay(config) -> dict:
    return {
        "value": getattr(config, "priority_mail_private_relay", False) is True,
        "default": DEFAULT_PRIORITY_MAIL_PRIVATE_RELAY,
        "warning": PRIORITY_MAIL_PRIVATE_RELAY_WARNING,
    }


def _audit_change(user, before, after, setting: str = SETTING_MODULE_REGISTER_TIMEOUT) -> None:
    """Strict Core audit row, written in the same transaction as the change. One row per changed setting, ``object_id`` is
    the setting's name."""
    from .audit import record

    record(
        actor=user,
        module_id="core",
        action="modify",
        object_type="runtime_settings",
        object_id=setting,
        message="Tec-Tac runtime setting changed.",
        before={setting: before},
        after={setting: after},
        strict=True,
    )


def _deny_superuser_only(request, setting: str, message: str) -> None:
    """Refuse a superuser-only setting: one best-effort Core ``deny`` row (never the value), then 403."""
    try:
        from .audit import record

        record(
            actor=request.user,
            module_id="core",
            action="deny",
            object_type="runtime_settings",
            object_id=setting,
            message="Blocked a runtime setting change that needs a superuser.",
            metadata={"reason": "superuser_required"},
            strict=False,
        )
    except Exception:
        logger.exception("Unable to persist the runtime setting denial audit")
    raise PermissionDenied(message)


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Runtime Settings"], summary="Get the Core runtime settings"),
    patch=extend_schema(tags=["Tec-Tac Runtime Settings"], summary="Change the module register() time limit, or (superuser only) the Tactical operation upload limit, the system name or the private mail relay switch"),
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
        unknown = sorted(set(data) - set(RUNTIME_SETTING_NAMES))
        if unknown:
            return Response({"detail": "Unknown runtime setting(s): " + ", ".join(unknown)}, status=400)
        if not data:
            return Response({"detail": "Send at least one runtime setting: " + " or ".join(RUNTIME_SETTING_NAMES) + "."}, status=400)
        # The upload limit is superuser only. Checked before the values, so a non-superuser gets 403 and never 400.
        # The system name is superuser only too (1.17.24). A mixed body is refused whole, so nothing is saved.
        if not is_effective_superuser(request.user):
            if SETTING_TACTICAL_UPLOAD_MAX_MIB in data:
                _deny_superuser_only(request, SETTING_TACTICAL_UPLOAD_MAX_MIB, UPLOAD_LIMIT_DENIED)
            if SETTING_SYSTEM_NAME in data:
                _deny_superuser_only(request, SETTING_SYSTEM_NAME, SYSTEM_NAME_DENIED)
            if SETTING_PRIORITY_MAIL_PRIVATE_RELAY in data:
                _deny_superuser_only(request, SETTING_PRIORITY_MAIL_PRIVATE_RELAY, PRIORITY_MAIL_PRIVATE_RELAY_DENIED)
        changes = {}
        try:
            if SETTING_MODULE_REGISTER_TIMEOUT in data:
                changes[SETTING_MODULE_REGISTER_TIMEOUT] = validate_module_register_timeout_seconds(data[SETTING_MODULE_REGISTER_TIMEOUT])
            if SETTING_TACTICAL_UPLOAD_MAX_MIB in data:
                changes[SETTING_TACTICAL_UPLOAD_MAX_MIB] = validate_tactical_upload_max_mib(data[SETTING_TACTICAL_UPLOAD_MAX_MIB])
            if SETTING_SYSTEM_NAME in data:
                # JSON null resets the name to the default.
                name = data[SETTING_SYSTEM_NAME]
                changes[SETTING_SYSTEM_NAME] = DEFAULT_SYSTEM_NAME if name is None else validate_system_name(name)
            if SETTING_PRIORITY_MAIL_PRIVATE_RELAY in data:
                changes[SETTING_PRIORITY_MAIL_PRIVATE_RELAY] = validate_priority_mail_private_relay(data[SETTING_PRIORITY_MAIL_PRIVATE_RELAY])
        except RuntimeSettingsError as exc:
            return Response({"detail": str(exc)}, status=400)
        with transaction.atomic():
            config = TecTacRuntimeConfig.objects.select_for_update().get(pk=TecTacRuntimeConfig.current().pk)
            changed = []
            for setting, value in changes.items():
                before = getattr(config, setting)
                if setting == SETTING_PRIORITY_MAIL_PRIVATE_RELAY:
                    before = before is True
                elif setting != SETTING_SYSTEM_NAME:
                    before = int(before)
                if before != value:
                    setattr(config, setting, value)
                    changed.append((setting, before, value))
            if changed:
                config.updated_by = request.user
                config.save(update_fields=[*(item[0] for item in changed), "updated_by", "updated_at"])
                # One strict audit row per changed setting. A failed audit write raises and rolls every change back.
                for setting, before, value in changed:
                    _audit_change(request.user, before, value, setting)
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

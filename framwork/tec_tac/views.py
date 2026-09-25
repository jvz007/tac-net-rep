import io
import logging
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import pyotp
from pathlib import Path

from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from accounts.models import Role
from accounts.permissions import RolesPerms
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView
from tacticalrmm.throttles import LoginDayThrottle, LoginMinThrottle
from drf_spectacular.utils import extend_schema, extend_schema_view

from .module_manager import (
    ModuleManagerError,
    _load_stage,
    discard_stage,
    get_job,
    installed_catalog,
    queue_install,
    queue_remove,
    stage_uploaded_package,
)
logger = logging.getLogger("tec_tac.module_manager")



from .system_update import (
    SystemUpdateError,
    discard_stage as discard_system_stage,
    get_job as get_system_update_job,
    list_branches as system_update_branches,
    online_status as system_update_online_status,
    queue_install as queue_system_update,
    stage_online_package,
    stage_uploaded_package as stage_system_update_package,
    system_status,
)

from .module_runtime import module_runtime_snapshot
from .registry import get_plugins
from .notices import unread_count as notice_unread_count
from .preferences import get_user_preferences
from .session_security import SessionAuthenticated
from .trust_policy import TrustPolicyError, LEVEL_RANK, console_guidance as trust_policy_console_guidance, get_policy as get_update_trust_policy, set_policy as set_update_trust_policy

from .rbac import (
    CORE_PRIVILEGED_PERMISSION,
    can_manage_privileged_operations,
    is_effective_superuser,
    effective_permissions,
    get_all_role_permissions,
    permission_catalog,
    registered_permissions,
    set_extension_permission,
)


def _role_for_user(user):
    try:
        return user.get_and_set_role_cache()
    except Exception:
        return getattr(user, "role", None)


def _native_capabilities(user, role=None):
    role = role if role is not None else _role_for_user(user)
    unrestricted = bool(getattr(user, "is_superuser", False)) or bool(getattr(role, "is_superuser", False) if role else False)

    def allowed(field):
        return unrestricted or bool(getattr(role, field, False) if role else False)

    return {
        "list_accounts": allowed("can_list_accounts"),
        "manage_accounts": allowed("can_manage_accounts"),
        "list_roles": allowed("can_list_roles"),
        "manage_roles": allowed("can_manage_roles"),
        "list_modules": True,
        "manage_modules": can_manage_privileged_operations(user),
        "manage_schedules": allowed("can_do_server_maint"),
        "server_maintenance": can_manage_privileged_operations(user),
    }


def _user_payload(user, role=None):
    role = role if role is not None else _role_for_user(user)
    user_superuser = bool(getattr(user, "is_superuser", False))
    role_superuser = bool(getattr(role, "is_superuser", False)) if role else False
    display_name = " ".join(
        part for part in (
            str(getattr(user, "first_name", "") or "").strip(),
            str(getattr(user, "last_name", "") or "").strip(),
        ) if part
    ) or str(user.username)

    return {
        "id": user.id,
        "username": user.username,
        "display_name": display_name,
        "role": role.name if role else None,
        "role_id": role.id if role else None,
        "superuser": user_superuser or role_superuser,
        "tactical_superuser": user_superuser,
        "role_superuser": role_superuser,
    }


def _normalize_tec_tac_ui_url(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text or len(text) > 500:
        return None
    try:
        parsed = urlsplit(text)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    path = parsed.path or "/tec-tac/"
    if not path.endswith("/"):
        path += "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _tec_tac_ui_url(request) -> str:
    # The browser sends its actual Tec-Tac base explicitly. Origin/Referer are
    # safe fallbacks, while request.get_host() is only the last resort because
    # API and UI hosts can differ behind a reverse proxy.
    explicit = _normalize_tec_tac_ui_url(request.query_params.get("ui_url"))
    if explicit:
        return explicit

    origin = _normalize_tec_tac_ui_url(request.META.get("HTTP_ORIGIN"))
    if origin:
        parsed = urlsplit(origin)
        return urlunsplit((parsed.scheme, parsed.netloc, "/tec-tac/", "", ""))

    referer = _normalize_tec_tac_ui_url(request.META.get("HTTP_REFERER"))
    if referer:
        parsed = urlsplit(referer)
        path = parsed.path or "/tec-tac/"
        marker = "/tec-tac/"
        if marker in path:
            path = path[: path.index(marker) + len(marker)]
        else:
            path = marker
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

    scheme = "https" if request.is_secure() else "http"
    return f"{scheme}://{request.get_host()}/tec-tac/"


def _tec_tac_totp_issuer(request) -> str:
    parsed = urlsplit(_tec_tac_ui_url(request))
    host = str(parsed.hostname or "tec-tac")
    path = (parsed.path or "/tec-tac/").rstrip("/")
    # otpauth labels use ':' as the issuer/account separator. Keep the issuer
    # itself colon-free so authenticators do not parse a URL scheme or port as
    # part of the separator grammar.
    issuer = f"{host}{path}".replace(":", "-")
    return issuer[:160] or "tec-tac"


def _tec_tac_totp_uri(request) -> str:
    issuer = _tec_tac_totp_issuer(request)
    return pyotp.TOTP(request.user.totp_key).provisioning_uri(
        str(request.user.username),
        issuer_name=issuer,
    )


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Get current user TOTP enrollment QR code"))
class TotpQrView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        if not getattr(request.user, "totp_key", None):
            return Response({"detail": "TOTP enrollment has not been initialized for this account."}, status=409)

        qr_url = _tec_tac_totp_uri(request)

        try:
            import qrcode
            import qrcode.image.svg

            image = qrcode.make(
                qr_url,
                image_factory=qrcode.image.svg.SvgPathImage,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                border=4,
            )
            output = io.BytesIO()
            image.save(output)
            response = HttpResponse(output.getvalue(), content_type="image/svg+xml")
            response["Cache-Control"] = "no-store, max-age=0"
            response["Pragma"] = "no-cache"
            response["X-Content-Type-Options"] = "nosniff"
            response["X-Tec-Tac-MFA-Issuer"] = _tec_tac_totp_issuer(request)
            return response
        except Exception as exc:
            logger.exception("Tec-Tac TOTP QR generation failed")
            return Response(
                {
                    "detail": "TOTP QR generation failed.",
                    "error_type": exc.__class__.__name__,
                },
                status=500,
            )


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Get Tec-Tac UI context"))
class UiContextView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        # Startup is a hot path. Discover module manifests once and share that
        # immutable snapshot across permission, catalogue and runtime derivation
        # instead of rescanning the extension tree three times.
        plugins = get_plugins()
        role = _role_for_user(request.user)
        preferences, preferences_initialized, preferences_updated_at = get_user_preferences(request.user)
        return Response(
            {
                "user": _user_payload(request.user, role=role),
                "permissions": sorted(effective_permissions(request.user, plugins=plugins, role=role)),
                "extensions": permission_catalog(plugins),
                "capabilities": _native_capabilities(request.user, role=role),
                "module_status": module_runtime_snapshot(plugins),
                "notice_unread_count": notice_unread_count(request.user),
                "preferences": preferences,
                "preferences_initialized": preferences_initialized,
                "preferences_updated_at": preferences_updated_at,
            }
        )


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List Tec-Tac extension permissions"))
class ExtensionPermissionCatalogView(APIView):
    permission_classes = [SessionAuthenticated, RolesPerms]

    def get(self, request):
        return Response(
            {
                "extensions": permission_catalog(),
                "permission_count": len(registered_permissions()),
            }
        )


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac Framework"], summary="Get role extension permissions"),
    put=extend_schema(tags=["Tec-Tac Framework"], summary="Update role extension permissions"),
)
class RoleExtensionPermissionsView(APIView):
    permission_classes = [SessionAuthenticated, RolesPerms]

    def get(self, request, role_id):
        role = get_object_or_404(Role, pk=role_id)
        return Response(
            {
                "role": {
                    "id": role.id,
                    "name": role.name,
                    "is_superuser": role.is_superuser,
                },
                "permissions": get_all_role_permissions(role),
                "extensions": permission_catalog(),
            }
        )

    def put(self, request, role_id):
        role = get_object_or_404(Role, pk=role_id)
        payload = request.data.get("permissions")
        if not isinstance(payload, dict):
            return Response(
                {"detail": "permissions must be an object of codename -> boolean values."},
                status=400,
            )

        known = registered_permissions()
        unknown = sorted(set(payload) - set(known))
        if unknown:
            return Response(
                {"detail": "Unknown Tec-Tac permission(s): " + ", ".join(unknown)},
                status=400,
            )

        if CORE_PRIVILEGED_PERMISSION in payload and not is_effective_superuser(request.user):
            raise PermissionDenied("Only a Tactical or role superuser may grant or revoke Tec-Tac privileged-operations access.")

        if CORE_PRIVILEGED_PERMISSION in payload:
            _audit_privileged(request.user, "modify", "privileged_permission", object_id=str(role.id),
                              metadata={"codename": CORE_PRIVILEGED_PERMISSION, "granted": payload[CORE_PRIVILEGED_PERMISSION], "role": role.name})

        for codename, granted in payload.items():
            if not isinstance(granted, bool):
                return Response(
                    {"detail": f"Permission {codename} must be true or false."},
                    status=400,
                )
            set_extension_permission(role, codename, granted)

        return Response(
            {
                "role": {
                    "id": role.id,
                    "name": role.name,
                    "is_superuser": role.is_superuser,
                },
                "permissions": get_all_role_permissions(role),
            }
        )


def _can_manage_modules(user):
    return can_manage_privileged_operations(user)


def _require_module_manager(user):
    if not _can_manage_modules(user):
        raise PermissionDenied("Tec-Tac core.privileged_operations permission is required for privileged lifecycle operations.")


def _audit_privileged(actor, action, object_type, *, object_id=None, metadata=None):
    try:
        from .audit import record
        record(actor=actor, module_id="core", action=action, object_type=object_type,
               object_id=object_id, metadata=metadata or {}, strict=False)
    except Exception:
        logger.exception("Unable to persist privileged-operation audit event")


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List installed Tec-Tac modules"))
class ModuleCatalogView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        try:
            modules = installed_catalog()
        except Exception as exc:
            return Response({"detail": "Unable to load module catalog.", "error_type": exc.__class__.__name__}, status=500)
        return Response({
            "modules": modules,
            "count": len(modules),
            "manage": _can_manage_modules(request.user),
        })


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Inspect and stage a Tec-Tac module package"))
class ModulePackageInspectView(APIView):
    permission_classes = [SessionAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        stage = "permission-check"
        try:
            _require_module_manager(request.user)
            stage = "multipart-parse"
            upload = request.FILES.get("package")
            if upload is None:
                return Response({"detail": "A package upload is required.", "stage": stage}, status=400)
            signature = request.FILES.get("signature")
            release_metadata = request.FILES.get("metadata") or request.FILES.get("release_metadata")
            stage = "stage-upload"
            payload = stage_uploaded_package(upload, signature_upload=signature, metadata_upload=release_metadata)
            stage = "licensing-check"
            from .module_manager_v2 import LicensingRequirementError, _enforce_candidate_licensing, _package_metadata
            meta = _load_stage(payload["upload_id"])
            candidate = _package_metadata(Path(meta["package_path"]))
            _enforce_candidate_licensing(candidate)
            payload["licensing"] = candidate.get("licensing_status")
            stage = "response"
            return Response(payload, status=201)
        except PermissionDenied:
            raise
        except LicensingRequirementError as exc:
            try:
                if "payload" in locals() and payload.get("upload_id"):
                    discard_stage(payload["upload_id"])
            except Exception:
                pass
            return Response(exc.as_payload(), status=403)
        except ModuleManagerError as exc:
            return Response({"detail": str(exc), "stage": stage}, status=400)
        except Exception as exc:
            logger.exception("Tec-Tac module package inspection failed at stage=%s", stage)
            return Response(
                {
                    "detail": "Module package inspection failed.",
                    "stage": stage,
                    "error_type": exc.__class__.__name__,
                },
                status=500,
            )


@extend_schema_view(delete=extend_schema(tags=["Tec-Tac Framework"], summary="Discard a staged Tec-Tac module package"))
class ModulePackageStageView(APIView):
    permission_classes = [SessionAuthenticated]

    def delete(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            discard_stage(str(upload_id))
            return Response(status=204)
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=404)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Install a staged Tec-Tac module package"))
class ModulePackageInstallView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, upload_id):
        _require_module_manager(request.user)
        replace = request.data.get("replace", False)
        if not isinstance(replace, bool):
            return Response({"detail": "replace must be true or false."}, status=400)
        try:
            from .module_manager_v2 import LicensingRequirementError, _enforce_candidate_licensing, _package_metadata
            meta = _load_stage(str(upload_id))
            candidate = _package_metadata(Path(meta["package_path"]))
            _enforce_candidate_licensing(candidate)
            return Response(queue_install(str(upload_id), replace=replace, requested_by=str(request.user.username)), status=202)
        except LicensingRequirementError as exc:
            return Response(exc.as_payload(), status=403)
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Remove a Tec-Tac module"))
class ModuleRemoveView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, plugin_id):
        _require_module_manager(request.user)
        try:
            return Response(queue_remove(plugin_id, requested_by=str(request.user.username)), status=202)
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Get a Tec-Tac module lifecycle job"))
class ModuleJobView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request, job_id):
        _require_module_manager(request.user)
        try:
            return Response(get_job(str(job_id)))
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=404)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac System Updates"], summary="Get installed Tec-Tac system component versions"))
class SystemUpdateStatusView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_module_manager(request.user)
        return Response(system_status())


@extend_schema_view(
    get=extend_schema(tags=["Tec-Tac System Updates"], summary="Get global update/module trust acceptance policy"),
    put=extend_schema(tags=["Tec-Tac System Updates"], summary="Set global update/module trust acceptance policy"),
)
class SystemUpdateTrustPolicyView(APIView):
    permission_classes = [SessionAuthenticated]
    throttle_classes = [LoginMinThrottle, LoginDayThrottle]

    def get_throttles(self):
        if getattr(self.request, "method", "GET").upper() == "PUT":
            return super().get_throttles()
        return []

    def get(self, request):
        _require_module_manager(request.user)
        try:
            return Response(get_update_trust_policy())
        except TrustPolicyError as exc:
            logger.exception("Unable to read root update trust policy")
            return Response({"detail": "Unable to read update trust policy.", "error_type": exc.__class__.__name__}, status=500)

    def put(self, request):
        _require_module_manager(request.user)
        level = request.data.get("minimum_level")
        if level is None:
            return Response({"detail": "minimum_level is required."}, status=400)
        try:
            current = get_update_trust_policy()
            target = str(level).strip().lower().replace("-", "_").replace(" ", "_")
            if target not in LEVEL_RANK:
                raise TrustPolicyError("Invalid update trust level.")
            lowering = LEVEL_RANK[target] < LEVEL_RANK[current["minimum_level"]]
            if lowering:
                guidance = trust_policy_console_guidance(target)
                _audit_privileged(
                    request.user, "console_change_requested", "update_trust_policy", object_id=target,
                    metadata={
                        "previous": current["minimum_level"],
                        "requested": target,
                        "environment": guidance.get("environment"),
                        "outcome": "console_required",
                    },
                )
                return Response(guidance, status=200)
            result = set_update_trust_policy(
                target,
                updated_by=str(request.user.username),
                updated_at=datetime.now(timezone.utc).isoformat(),
            )
            _audit_privileged(request.user, "modify", "update_trust_policy", object_id=target,
                              metadata={"previous": current["minimum_level"], "lowering": False, "outcome": "applied"})
            return Response(result)
        except TrustPolicyError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac System Updates"], summary="Inspect and stage an offline Tec-Tac system update package"))
class SystemUpdatePackageInspectView(APIView):
    permission_classes = [SessionAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        _require_module_manager(request.user)
        upload = request.FILES.get("package")
        if upload is None:
            return Response({"detail": "A system update package upload is required."}, status=400)
        try:
            return Response(stage_system_update_package(upload), status=201)
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=400)
        except Exception as exc:
            logger.exception("Tec-Tac system update package inspection failed")
            return Response({"detail": "System update package inspection failed.", "error_type": exc.__class__.__name__}, status=500)


@extend_schema_view(delete=extend_schema(tags=["Tec-Tac System Updates"], summary="Discard a staged Tec-Tac system update package"))
class SystemUpdatePackageStageView(APIView):
    permission_classes = [SessionAuthenticated]

    def delete(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            discard_system_stage(str(upload_id))
            return Response(status=204)
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=404)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac System Updates"], summary="Install a staged Tec-Tac framework or UI update"))
class SystemUpdatePackageInstallView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request, upload_id):
        _require_module_manager(request.user)
        allow_downgrade = request.data.get("allow_downgrade", False)
        if not isinstance(allow_downgrade, bool):
            return Response({"detail": "allow_downgrade must be true or false."}, status=400)
        if allow_downgrade:
            _audit_privileged(request.user, "install", "system_update_downgrade", object_id=str(upload_id),
                              metadata={"allow_downgrade": True, "outcome": "requested"})
        if allow_downgrade and not is_effective_superuser(request.user):
            raise PermissionDenied("Only a Tactical or role superuser may authorize a system downgrade.")
        try:
            result = queue_system_update(str(upload_id), allow_downgrade=allow_downgrade, requested_by=str(request.user.username))
            if allow_downgrade:
                _audit_privileged(request.user, "install", "system_update_downgrade", object_id=str(upload_id),
                                  metadata={"allow_downgrade": True, "outcome": "queued"})
            return Response(result, status=202)
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac System Updates"], summary="Get a Tec-Tac system update job"))
class SystemUpdateJobView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request, job_id):
        _require_module_manager(request.user)
        try:
            return Response(get_system_update_job(str(job_id)))
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=404)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac System Updates"], summary="Check the latest stable repository release for a system component"))
class SystemUpdateOnlineStatusView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_module_manager(request.user)
        component = str(request.query_params.get("component", "")).strip()
        force = str(request.query_params.get("force", "")).strip().lower() in {"1", "true", "yes", "on"}
        try:
            return Response(system_update_online_status(component, force=force))
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac System Updates"], summary="List repository branches for advanced system update sources"))
class SystemUpdateBranchesView(APIView):
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        _require_module_manager(request.user)
        component = str(request.query_params.get("component", "")).strip()
        try:
            return Response(system_update_branches(component))
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac System Updates"], summary="Download, inspect, and stage an online release or branch system update"))
class SystemUpdateOnlineStageView(APIView):
    permission_classes = [SessionAuthenticated]

    def post(self, request):
        _require_module_manager(request.user)
        component = str(request.data.get("component", "")).strip()
        source_type = str(request.data.get("source_type", "release")).strip()
        ref = request.data.get("ref")
        try:
            return Response(stage_online_package(component, source_type, str(ref).strip() if ref is not None else None), status=201)
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=400)
        except Exception as exc:
            logger.exception("Tec-Tac online system update staging failed")
            return Response({"detail": "Online system update staging failed.", "error_type": exc.__class__.__name__}, status=500)

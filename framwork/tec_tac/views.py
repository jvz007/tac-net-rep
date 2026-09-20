import io
import logging
from pathlib import Path

from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from accounts.models import Role
from accounts.serializers import TOTPSetupSerializer
from accounts.permissions import RolesPerms
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView
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

from .preferences import get_user_preferences

from .rbac import (
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


def _native_capabilities(user):
    role = _role_for_user(user)
    unrestricted = bool(getattr(user, "is_superuser", False)) or bool(getattr(role, "is_superuser", False) if role else False)

    def allowed(field):
        return unrestricted or bool(getattr(role, field, False) if role else False)

    return {
        "list_accounts": allowed("can_list_accounts"),
        "manage_accounts": allowed("can_manage_accounts"),
        "list_roles": allowed("can_list_roles"),
        "manage_roles": allowed("can_manage_roles"),
        "list_modules": True,
        "manage_modules": allowed("can_do_server_maint"),
        "manage_schedules": allowed("can_do_server_maint"),
    }


def _user_payload(user):
    role = _role_for_user(user)
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


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Get current user TOTP enrollment QR code"))
class TotpQrView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not getattr(request.user, "totp_key", None):
            return Response({"detail": "TOTP enrollment has not been initialized for this account."}, status=409)

        # Reuse Tactical's own serializer so the issuer/account URI exactly matches
        # the value Tactical uses for authenticator enrollment. The QR image is
        # generated locally by Tactical's existing qrcode dependency; the secret
        # never leaves this server.
        qr_url = TOTPSetupSerializer(request.user).data.get("qr_url")
        if not qr_url:
            return Response({"detail": "Tactical did not provide a TOTP provisioning URI."}, status=500)

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
            return response
        except Exception as exc:
            logger.exception("Tec-Tac TOTP QR generation failed")
            return Response(
                {
                    "detail": "TOTP QR generation failed.",
                    "error_type": exc.__class__.__name__,
                    "error": str(exc) or exc.__class__.__name__,
                },
                status=500,
            )


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Get Tec-Tac UI context"))
class UiContextView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        preferences, preferences_initialized, preferences_updated_at = get_user_preferences(request.user)
        return Response(
            {
                "user": _user_payload(request.user),
                "permissions": sorted(effective_permissions(request.user)),
                "extensions": permission_catalog(),
                "capabilities": _native_capabilities(request.user),
                "preferences": preferences,
                "preferences_initialized": preferences_initialized,
                "preferences_updated_at": preferences_updated_at,
            }
        )


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List Tec-Tac extension permissions"))
class ExtensionPermissionCatalogView(APIView):
    permission_classes = [IsAuthenticated, RolesPerms]

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
    permission_classes = [IsAuthenticated, RolesPerms]

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
    role = _role_for_user(user)
    return bool(getattr(user, "is_superuser", False)) or bool(getattr(role, "is_superuser", False) if role else False) or bool(getattr(role, "can_do_server_maint", False) if role else False)


def _require_module_manager(user):
    if not _can_manage_modules(user):
        raise PermissionDenied("Tactical can_do_server_maint is required to install or remove Tec-Tac modules.")


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="List installed Tec-Tac modules"))
class ModuleCatalogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            modules = installed_catalog()
        except Exception as exc:
            return Response({"detail": str(exc)}, status=500)
        return Response({
            "modules": modules,
            "count": len(modules),
            "manage": _can_manage_modules(request.user),
        })


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Inspect and stage a Tec-Tac module package"))
class ModulePackageInspectView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        stage = "permission-check"
        try:
            _require_module_manager(request.user)
            stage = "multipart-parse"
            upload = request.FILES.get("package")
            if upload is None:
                return Response({"detail": "A package upload is required.", "stage": stage}, status=400)
            stage = "stage-upload"
            payload = stage_uploaded_package(upload)
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
                    "error": str(exc) or exc.__class__.__name__,
                },
                status=500,
            )


@extend_schema_view(delete=extend_schema(tags=["Tec-Tac Framework"], summary="Discard a staged Tec-Tac module package"))
class ModulePackageStageView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            discard_stage(str(upload_id))
            return Response(status=204)
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=404)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Install a staged Tec-Tac module package"))
class ModulePackageInstallView(APIView):
    permission_classes = [IsAuthenticated]

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
    permission_classes = [IsAuthenticated]

    def post(self, request, plugin_id):
        _require_module_manager(request.user)
        try:
            return Response(queue_remove(plugin_id, requested_by=str(request.user.username)), status=202)
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Get a Tec-Tac module lifecycle job"))
class ModuleJobView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, job_id):
        _require_module_manager(request.user)
        try:
            return Response(get_job(str(job_id)))
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=404)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac System Updates"], summary="Get installed Tec-Tac system component versions"))
class SystemUpdateStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require_module_manager(request.user)
        return Response(system_status())


@extend_schema_view(post=extend_schema(tags=["Tec-Tac System Updates"], summary="Inspect and stage an offline Tec-Tac system update package"))
class SystemUpdatePackageInspectView(APIView):
    permission_classes = [IsAuthenticated]
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
            return Response({"detail": "System update package inspection failed.", "error_type": exc.__class__.__name__, "error": str(exc) or exc.__class__.__name__}, status=500)


@extend_schema_view(delete=extend_schema(tags=["Tec-Tac System Updates"], summary="Discard a staged Tec-Tac system update package"))
class SystemUpdatePackageStageView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, upload_id):
        _require_module_manager(request.user)
        try:
            discard_system_stage(str(upload_id))
            return Response(status=204)
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=404)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac System Updates"], summary="Install a staged Tec-Tac framework or UI update"))
class SystemUpdatePackageInstallView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, upload_id):
        _require_module_manager(request.user)
        allow_downgrade = request.data.get("allow_downgrade", False)
        if not isinstance(allow_downgrade, bool):
            return Response({"detail": "allow_downgrade must be true or false."}, status=400)
        try:
            return Response(queue_system_update(str(upload_id), allow_downgrade=allow_downgrade, requested_by=str(request.user.username)), status=202)
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac System Updates"], summary="Get a Tec-Tac system update job"))
class SystemUpdateJobView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, job_id):
        _require_module_manager(request.user)
        try:
            return Response(get_system_update_job(str(job_id)))
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=404)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac System Updates"], summary="Check the latest stable repository release for a system component"))
class SystemUpdateOnlineStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require_module_manager(request.user)
        component = str(request.query_params.get("component", "")).strip()
        try:
            return Response(system_update_online_status(component))
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(get=extend_schema(tags=["Tec-Tac System Updates"], summary="List repository branches for advanced system update sources"))
class SystemUpdateBranchesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require_module_manager(request.user)
        component = str(request.query_params.get("component", "")).strip()
        try:
            return Response(system_update_branches(component))
        except SystemUpdateError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac System Updates"], summary="Download, inspect, and stage an online release or branch system update"))
class SystemUpdateOnlineStageView(APIView):
    permission_classes = [IsAuthenticated]

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
            return Response({"detail": "Online system update staging failed.", "error_type": exc.__class__.__name__, "error": str(exc) or exc.__class__.__name__}, status=500)

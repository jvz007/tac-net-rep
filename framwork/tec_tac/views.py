import logging

from django.shortcuts import get_object_or_404
from accounts.models import Role
from accounts.permissions import RolesPerms
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, extend_schema_view

from .module_manager import (
    ModuleManagerError,
    discard_stage,
    get_job,
    installed_catalog,
    queue_install,
    queue_remove,
    stage_uploaded_package,
)
logger = logging.getLogger("tec_tac.module_manager")


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


@extend_schema_view(get=extend_schema(tags=["Tec-Tac Framework"], summary="Get Tec-Tac UI context"))
class UiContextView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(
            {
                "user": _user_payload(request.user),
                "permissions": sorted(effective_permissions(request.user)),
                "extensions": permission_catalog(),
                "capabilities": _native_capabilities(request.user),
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
            stage = "response"
            return Response(payload, status=201)
        except PermissionDenied:
            raise
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
            return Response(queue_install(str(upload_id), replace=replace), status=202)
        except ModuleManagerError as exc:
            return Response({"detail": str(exc)}, status=400)


@extend_schema_view(post=extend_schema(tags=["Tec-Tac Framework"], summary="Remove a Tec-Tac module"))
class ModuleRemoveView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, plugin_id):
        _require_module_manager(request.user)
        try:
            return Response(queue_remove(plugin_id), status=202)
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

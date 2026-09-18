from django.shortcuts import get_object_or_404
from accounts.models import Role
from accounts.permissions import RolesPerms
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

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


class ExtensionPermissionCatalogView(APIView):
    permission_classes = [IsAuthenticated, RolesPerms]

    def get(self, request):
        return Response(
            {
                "extensions": permission_catalog(),
                "permission_count": len(registered_permissions()),
            }
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

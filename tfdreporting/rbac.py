from accounts.models import Role

from tfdreporting.models import ExtensionRolePermission


PERMISSION_NETWORK_AVAILABILITY_LIST = "tfdreporting.networkavailability.list"
PERMISSION_NETWORK_AVAILABILITY_MANAGE = "tfdreporting.networkavailability.manage"

REGISTERED_PERMISSIONS = frozenset(
    {
        PERMISSION_NETWORK_AVAILABILITY_LIST,
        PERMISSION_NETWORK_AVAILABILITY_MANAGE,
    }
)


def _validate_codename(codename: str) -> None:
    if codename not in REGISTERED_PERMISSIONS:
        raise ValueError(f"Unknown TFD extension permission: {codename}")


def has_extension_permission(user, codename: str) -> bool:
    """Return whether a Tactical user has a registered TFD permission."""

    _validate_codename(codename)

    if not getattr(user, "is_authenticated", False):
        return False

    if user.is_superuser:
        return True

    role = user.get_and_set_role_cache()
    if not role:
        return False

    if role.is_superuser:
        return True

    return ExtensionRolePermission.objects.filter(
        role_id=role.id,
        codename=codename,
        granted=True,
    ).exists()


def set_extension_permission(role, codename: str, granted: bool):
    _validate_codename(codename)

    if not isinstance(role, Role):
        raise TypeError("role must be an accounts.models.Role instance")

    permission, _ = ExtensionRolePermission.objects.update_or_create(
        role_id=role.id,
        codename=codename,
        defaults={"granted": bool(granted)},
    )
    return permission


def grant_extension_permission(role, codename: str):
    return set_extension_permission(role, codename, True)


def revoke_extension_permission(role, codename: str):
    return set_extension_permission(role, codename, False)


def get_role_permissions(role):
    if not isinstance(role, Role):
        raise TypeError("role must be an accounts.models.Role instance")

    stored = {
        row.codename: row.granted
        for row in ExtensionRolePermission.objects.filter(
            role_id=role.id,
            codename__in=REGISTERED_PERMISSIONS,
        )
    }

    return {
        codename: stored.get(codename, False)
        for codename in sorted(REGISTERED_PERMISSIONS)
    }

"""Generic Tec-Tac role-based permission helpers.

Extensions declare permission groups in ``tec_tac.json``. Tec-Tac persists role
assignments in the compatibility ``ExtensionRolePermission`` table while keeping
permission discovery generic at framework level.
"""
from __future__ import annotations

from accounts.models import Role
from tec_tac.registry import get_plugins


def _extension_plugins():
    return tuple(plugin for plugin in get_plugins() if plugin.plugin_type == "extension")


def registered_permissions() -> frozenset[str]:
    values = set()
    for plugin in _extension_plugins():
        for _, permissions in plugin.permission_groups:
            values.update(permissions)
    return frozenset(values)


def permission_catalog() -> list[dict]:
    catalog = []
    for plugin in _extension_plugins():
        groups = [
            {"name": name, "permissions": list(permissions)}
            for name, permissions in plugin.permission_groups
        ]
        catalog.append(
            {
                "id": plugin.plugin_id,
                "version": plugin.version,
                "groups": groups,
                "permissions": sorted({code for group in groups for code in group["permissions"]}),
            }
        )
    return catalog


def permission_groups(plugin_id: str) -> dict[str, tuple[str, ...]]:
    for plugin in _extension_plugins():
        if plugin.plugin_id == plugin_id:
            return plugin.permission_group_map()
    raise ValueError(f"Unknown Tec-Tac extension: {plugin_id}")


def _permission_model():
    from tfdreporting.models import ExtensionRolePermission

    return ExtensionRolePermission


def _validate_codename(codename: str) -> None:
    if codename not in registered_permissions():
        raise ValueError(f"Unknown Tec-Tac extension permission: {codename}")


def has_extension_permission(user, codename: str) -> bool:
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
    Permission = _permission_model()
    return Permission.objects.filter(
        role_id=role.id,
        codename=codename,
        granted=True,
    ).exists()


def effective_permissions(user) -> frozenset[str]:
    known = registered_permissions()
    if not getattr(user, "is_authenticated", False):
        return frozenset()
    if getattr(user, "is_superuser", False):
        return known
    role = user.get_and_set_role_cache()
    if not role:
        return frozenset()
    if role.is_superuser:
        return known
    Permission = _permission_model()
    granted = Permission.objects.filter(
        role_id=role.id,
        codename__in=known,
        granted=True,
    ).values_list("codename", flat=True)
    return frozenset(granted)


def set_extension_permission(role, codename: str, granted: bool):
    _validate_codename(codename)
    if not isinstance(role, Role):
        raise TypeError("role must be an accounts.models.Role instance")
    Permission = _permission_model()
    row, _ = Permission.objects.update_or_create(
        role_id=role.id,
        codename=codename,
        defaults={"granted": bool(granted)},
    )
    return row


def grant_extension_permission(role, codename: str):
    return set_extension_permission(role, codename, True)


def revoke_extension_permission(role, codename: str):
    return set_extension_permission(role, codename, False)


def grant_permission_group(role, plugin_id: str, group_name: str):
    groups = permission_groups(plugin_id)
    if group_name not in groups:
        raise ValueError(f"Unknown permission group {group_name!r} for extension {plugin_id!r}")
    return tuple(grant_extension_permission(role, codename) for codename in groups[group_name])


def get_role_permissions(role, plugin_id: str) -> dict[str, bool]:
    if not isinstance(role, Role):
        raise TypeError("role must be an accounts.models.Role instance")
    groups = permission_groups(plugin_id)
    codenames = sorted({code for values in groups.values() for code in values})
    Permission = _permission_model()
    stored = {
        row.codename: row.granted
        for row in Permission.objects.filter(role_id=role.id, codename__in=codenames)
    }
    return {codename: stored.get(codename, False) for codename in codenames}


def get_all_role_permissions(role) -> dict[str, bool]:
    if not isinstance(role, Role):
        raise TypeError("role must be an accounts.models.Role instance")
    codenames = sorted(registered_permissions())
    if role.is_superuser:
        return {codename: True for codename in codenames}
    Permission = _permission_model()
    stored = {
        row.codename: row.granted
        for row in Permission.objects.filter(role_id=role.id, codename__in=codenames)
    }
    return {codename: stored.get(codename, False) for codename in codenames}

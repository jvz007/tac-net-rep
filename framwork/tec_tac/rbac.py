"""Generic Tec-Tac role-based permission helpers.

Extensions declare permission groups in ``tec_tac.json``. Tec-Tac persists role
assignments in the ``ExtensionRolePermission`` table (``tec_tac.models``) while keeping
permission discovery generic at framework level.
"""
from __future__ import annotations

from accounts.models import Role
from tec_tac.registry import get_plugins

CORE_PRIVILEGED_PERMISSION = "core.privileged_operations"
CORE_RUNTIME_SETTINGS_MANAGE_PERMISSION = "core.runtime_settings.manage"
CORE_RESOURCES_CLIENTS_MANAGE_PERMISSION = "core.resources.clients.manage"
CORE_RESOURCES_SITES_MANAGE_PERMISSION = "core.resources.sites.manage"
CORE_PERMISSION_GROUPS = {
    "Privileged operations": (CORE_PRIVILEGED_PERMISSION,),
    "Runtime settings": (CORE_RUNTIME_SETTINGS_MANAGE_PERMISSION,),
    "Client resource management": (CORE_RESOURCES_CLIENTS_MANAGE_PERMISSION,),
    "Site resource management": (CORE_RESOURCES_SITES_MANAGE_PERMISSION,),
}


def _extension_plugins(plugins=None):
    source = get_plugins() if plugins is None else plugins
    return tuple(plugin for plugin in source if plugin.plugin_type == "extension")


def registered_permissions(plugins=None) -> frozenset[str]:
    values = {code for permissions in CORE_PERMISSION_GROUPS.values() for code in permissions}
    for plugin in _extension_plugins(plugins):
        for _, permissions in plugin.permission_groups:
            values.update(permissions)
    return frozenset(values)


def _audit_event_rows(plugin) -> list[dict]:
    """Browser audit events a permissionless module declares in its manifest."""
    return [
        {"object_type": object_type, "actions": list(actions)}
        for object_type, actions in (getattr(plugin, "audit_events", ()) or ())
    ]


def permission_catalog(plugins=None) -> list[dict]:
    catalog = [{
        "id": "core",
        "version": "1",
        "groups": [{"name": name, "permissions": list(permissions)} for name, permissions in CORE_PERMISSION_GROUPS.items()],
        "permissions": sorted({code for permissions in CORE_PERMISSION_GROUPS.values() for code in permissions}),
        "audit_events": [],
    }]
    for plugin in _extension_plugins(plugins):
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
                "audit_events": _audit_event_rows(plugin),
            }
        )
    return catalog


def permission_groups(plugin_id: str) -> dict[str, tuple[str, ...]]:
    if plugin_id == "core":
        return dict(CORE_PERMISSION_GROUPS)
    for plugin in _extension_plugins():
        if plugin.plugin_id == plugin_id:
            return plugin.permission_group_map()
    raise ValueError(f"Unknown Tec-Tac extension: {plugin_id}")


def _permission_model():
    from .models import ExtensionRolePermission

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


def effective_permissions(user, *, plugins=None, role=None) -> frozenset[str]:
    known = registered_permissions(plugins)
    if not getattr(user, "is_authenticated", False):
        return frozenset()
    if getattr(user, "is_superuser", False):
        return known
    role = role if role is not None else user.get_and_set_role_cache()
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



def is_effective_superuser(user) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    if bool(getattr(user, "is_superuser", False)):
        return True
    try:
        role = user.get_and_set_role_cache()
    except Exception:
        role = getattr(user, "role", None)
    return bool(getattr(role, "is_superuser", False)) if role else False


def can_manage_privileged_operations(user) -> bool:
    if is_effective_superuser(user):
        return True
    try:
        return has_extension_permission(user, CORE_PRIVILEGED_PERMISSION)
    except Exception:
        return False



def can_manage_runtime_settings(user) -> bool:
    """May this user change Core runtime settings (1.17.2)?

    True for an effective superuser, a holder of core.runtime_settings.manage, or a
    holder of core.privileged_operations (kept so 1.17.1 administrators lose
    nothing). Never raises: any error reads as False.
    """
    try:
        if is_effective_superuser(user):
            return True
        return has_extension_permission(user, CORE_RUNTIME_SETTINGS_MANAGE_PERMISSION) or has_extension_permission(
            user, CORE_PRIVILEGED_PERMISSION
        )
    except Exception:
        return False


def _validate_tactical_flag(flag) -> str:
    """Return flag when it names a boolean ``can_*`` field on Tactical's Role. Otherwise raise ValueError."""
    name = flag if isinstance(flag, str) else ""
    if not name.startswith("can_"):
        raise ValueError(f"Unknown Tactical role permission: {flag!r}")
    try:
        field = Role._meta.get_field(name)
        internal = field.get_internal_type()
    except Exception:
        raise ValueError(f"Unknown Tactical role permission: {flag!r}") from None
    if internal != "BooleanField":
        raise ValueError(f"Tactical role field {name!r} is not a permission flag.")
    return name


def tactical_permission_flags(user, flags) -> dict[str, bool]:
    """Evaluate Tactical role flags for a user, the way Tactical's own ``_has_perm`` does (1.17.6).

    Returns ``{flag: bool}`` for every requested flag. An authenticated Django superuser or role superuser passes
    every flag. A user with no role is denied, and so is a Tactical installer user. Otherwise the answer is the
    role's own boolean. Every flag must be a boolean ``can_*`` field on ``accounts.models.Role``, or ValueError is
    raised before anything is evaluated. A lookup failure never raises: it fails closed (every flag False).
    This adds no Tec-Tac permission and does not change ``has_extension_permission``.
    """
    names = [_validate_tactical_flag(flag) for flag in flags]
    denied = {name: False for name in names}
    try:
        if not getattr(user, "is_authenticated", False):
            return denied
        if getattr(user, "is_installer_user", False):
            return denied
        if bool(getattr(user, "is_superuser", False)):
            return {name: True for name in names}
        role = user.get_and_set_role_cache()
        if not role:
            return denied
        if bool(getattr(role, "is_superuser", False)):
            return {name: True for name in names}
        return {name: bool(getattr(role, name, False)) for name in names}
    except Exception:
        return denied


def has_tactical_permission(user, flag: str) -> bool:
    """May this user do what Tactical's role flag ``flag`` allows? See ``tactical_permission_flags``."""
    return tactical_permission_flags(user, (flag,))[flag]


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

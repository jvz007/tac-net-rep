"""Supported Tec-Tac module identity migration helpers.

Module IDs are stable identities. A rename is therefore an explicit lifecycle
migration, never an alias or case-normalization rule. Package manifests may
opt into a controlled rename by declaring ``migration.previous_module_ids``
and explicit maps for persisted namespaced state.
"""
from __future__ import annotations

from copy import deepcopy
from django.db import transaction

from .models import TecTacDashboard, TecTacSchedule, TecTacUserPreferences


class ModuleIdentityMigrationError(RuntimeError):
    pass


def _permission_model():
    from tfdreporting.models import ExtensionRolePermission
    return ExtensionRolePermission


def _mapping(migration: dict, key: str) -> dict[str, str]:
    value = (migration or {}).get(key) or {}
    if not isinstance(value, dict):
        raise ModuleIdentityMigrationError(f"migration.{key} must be an object")
    return {str(k): str(v) for k, v in value.items()}


def preflight_identity_migration(*, old_id: str, new_id: str, migration: dict) -> dict:
    """Validate persisted-state migration before the lifecycle job is queued."""
    old_id = str(old_id or "").strip()
    new_id = str(new_id or "").strip()
    if not old_id or not new_id or old_id == new_id:
        raise ModuleIdentityMigrationError("old_id and new_id must be distinct non-empty module IDs")

    permissions = _mapping(migration, "permissions")
    actions = _mapping(migration, "scheduler_actions")
    Permission = _permission_model()

    old_permission_rows = list(
        Permission.objects.filter(codename__startswith=old_id + ".")
        .values_list("codename", flat=True)
        .distinct()
    )
    missing_permissions = sorted(code for code in old_permission_rows if code not in permissions)
    if missing_permissions:
        raise ModuleIdentityMigrationError(
            "Persisted role permission(s) require explicit migration mappings: "
            + ", ".join(missing_permissions)
        )

    destination_permission_rows = sorted(
        set(Permission.objects.filter(codename__startswith=new_id + ".").values_list("codename", flat=True))
    )
    if destination_permission_rows:
        raise ModuleIdentityMigrationError(
            f"Destination permission namespace {new_id!r} already contains persisted assignments."
        )

    schedules = TecTacSchedule.objects.filter(module_id=old_id) | TecTacSchedule.objects.filter(owner_module=old_id)
    scheduler_actions = sorted({value for value in schedules.values_list("action_id", flat=True) if value})
    missing_actions = sorted(
        action for action in scheduler_actions
        if action.startswith(old_id + ".") and action not in actions
    )
    if missing_actions:
        raise ModuleIdentityMigrationError(
            "Persisted scheduler action(s) require explicit migration mappings: "
            + ", ".join(missing_actions)
        )

    if TecTacSchedule.objects.filter(module_id=new_id).exists() or TecTacSchedule.objects.filter(owner_module=new_id).exists():
        raise ModuleIdentityMigrationError(
            f"Destination module identity {new_id!r} already owns persisted schedules."
        )

    return {
        "old_id": old_id,
        "new_id": new_id,
        "permission_rows": len(old_permission_rows),
        "schedule_rows": schedules.distinct().count(),
        "preference_route_mappings": len(_mapping(migration, "ui_routes")),
        "dashboard_widget_mappings": len(_mapping(migration, "dashboard_widgets")),
    }


def _replace_navigation_routes(preferences: dict, routes: dict[str, str]) -> tuple[dict, bool]:
    if not routes or not isinstance(preferences, dict):
        return preferences, False
    updated = deepcopy(preferences)
    nav = updated.get("navigation")
    if not isinstance(nav, dict):
        return updated, False
    changed = False
    favorites = nav.get("favorites")
    if isinstance(favorites, list):
        new_values = [routes.get(value, value) if isinstance(value, str) else value for value in favorites]
        if new_values != favorites:
            nav["favorites"] = new_values
            changed = True
    order = nav.get("order")
    if isinstance(order, dict):
        new_order = {}
        for section, values in order.items():
            if isinstance(values, list):
                mapped = [routes.get(value, value) if isinstance(value, str) else value for value in values]
                new_order[section] = mapped
                changed = changed or mapped != values
            else:
                new_order[section] = values
        nav["order"] = new_order
    return updated, changed


def _replace_dashboard_widgets(layout: dict, mapping: dict[str, str]) -> tuple[dict, bool]:
    if not mapping or not isinstance(layout, dict):
        return layout, False
    updated = deepcopy(layout)
    widgets = updated.get("widgets")
    if not isinstance(widgets, list):
        return updated, False
    changed = False
    for item in widgets:
        if not isinstance(item, dict):
            continue
        current = item.get("widget_id")
        if isinstance(current, str) and current in mapping:
            item["widget_id"] = mapping[current]
            changed = True
    return updated, changed


def apply_identity_migration(*, old_id: str, new_id: str, migration: dict, reverse: bool = False) -> dict:
    """Apply or reverse persisted DB identity state in one transaction.

    Filesystem/module-state movement is handled by the privileged lifecycle
    worker and is covered by its existing backup/rollback boundary.
    """
    old_id = str(old_id or "").strip()
    new_id = str(new_id or "").strip()
    migration = dict(migration or {})
    if reverse:
        old_id, new_id = new_id, old_id
        migration = {
            **migration,
            "permissions": {v: k for k, v in _mapping(migration, "permissions").items()},
            "scheduler_actions": {v: k for k, v in _mapping(migration, "scheduler_actions").items()},
            "ui_routes": {v: k for k, v in _mapping(migration, "ui_routes").items()},
            "dashboard_widgets": {v: k for k, v in _mapping(migration, "dashboard_widgets").items()},
        }

    permissions = _mapping(migration, "permissions")
    actions = _mapping(migration, "scheduler_actions")
    routes = _mapping(migration, "ui_routes")
    widgets = _mapping(migration, "dashboard_widgets")
    Permission = _permission_model()

    with transaction.atomic():
        # Strict collision checks keep the operation reversible.
        for source, target in permissions.items():
            rows = list(Permission.objects.select_for_update().filter(codename=source))
            if rows and Permission.objects.filter(codename=target).exists():
                raise ModuleIdentityMigrationError(f"Permission migration target already exists: {target}")
            for row in rows:
                row.codename = target
                row.save(update_fields=["codename", "updated_at"])

        schedules = list(
            TecTacSchedule.objects.select_for_update().filter(module_id=old_id)
        )
        owned = list(
            TecTacSchedule.objects.select_for_update().filter(owner_module=old_id)
            .exclude(pk__in=[item.pk for item in schedules])
        )
        for schedule in [*schedules, *owned]:
            fields = []
            if schedule.module_id == old_id:
                schedule.module_id = new_id
                fields.append("module_id")
            if schedule.owner_module == old_id:
                schedule.owner_module = new_id
                fields.append("owner_module")
            if schedule.action_id in actions:
                schedule.action_id = actions[schedule.action_id]
                fields.append("action_id")
            if fields:
                schedule.save(update_fields=[*fields, "updated_at"])

        if routes:
            for prefs in TecTacUserPreferences.objects.select_for_update().all():
                value, changed = _replace_navigation_routes(prefs.preferences, routes)
                if changed:
                    prefs.preferences = value
                    prefs.save(update_fields=["preferences", "updated_at"])

        if widgets:
            for dashboard in TecTacDashboard.objects.select_for_update().all():
                value, changed = _replace_dashboard_widgets(dashboard.layout, widgets)
                if changed:
                    dashboard.layout = value
                    dashboard.save(update_fields=["layout", "updated_at"])

    return {"old_id": old_id, "new_id": new_id, "reversed": bool(reverse)}

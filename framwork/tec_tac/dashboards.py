from __future__ import annotations

import json
from copy import deepcopy

from django.db.models import Q

from .models import TecTacDashboard

MAX_LAYOUT_BYTES = 512 * 1024
MAX_WIDGETS = 100
VALID_VISIBILITY = {TecTacDashboard.Visibility.PRIVATE, TecTacDashboard.Visibility.SHARED}


class DashboardValidationError(ValueError):
    pass


def _is_admin(user):
    try:
        role = user.get_and_set_role_cache()
    except Exception:
        role = getattr(user, "role", None)
    return bool(getattr(user, "is_superuser", False)) or bool(getattr(role, "is_superuser", False) if role else False) or bool(getattr(role, "can_do_server_maint", False) if role else False)


def visible_dashboards(user):
    return TecTacDashboard.objects.filter(Q(owner=user) | Q(visibility=TecTacDashboard.Visibility.SHARED)).select_related("owner")


def get_visible_dashboard(user, dashboard_id):
    try:
        return visible_dashboards(user).get(pk=dashboard_id)
    except TecTacDashboard.DoesNotExist as exc:
        raise DashboardValidationError("Dashboard not found.") from exc


def can_edit_dashboard(user, dashboard):
    if dashboard.owner_id == user.id:
        return True
    return dashboard.visibility == TecTacDashboard.Visibility.SHARED and _is_admin(user)


def normalize_layout(value):
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise DashboardValidationError("layout must be an object.")
    widgets = value.get("widgets", [])
    if not isinstance(widgets, list):
        raise DashboardValidationError("layout.widgets must be an array.")
    if len(widgets) > MAX_WIDGETS:
        raise DashboardValidationError(f"A dashboard may contain at most {MAX_WIDGETS} widgets.")

    clean = []
    seen_instances = set()
    for index, item in enumerate(widgets):
        if not isinstance(item, dict):
            raise DashboardValidationError(f"layout.widgets[{index}] must be an object.")
        instance_id = str(item.get("instance_id", "")).strip()
        widget_id = str(item.get("widget_id", "")).strip()
        if not instance_id or not widget_id:
            raise DashboardValidationError(f"layout.widgets[{index}] requires instance_id and widget_id.")
        if instance_id in seen_instances:
            raise DashboardValidationError(f"Duplicate widget instance_id: {instance_id}")
        seen_instances.add(instance_id)
        try:
            width = int(item.get("w", 4))
            height = int(item.get("h", 3))
        except (TypeError, ValueError) as exc:
            raise DashboardValidationError(f"layout.widgets[{index}] size must be numeric.") from exc
        width = min(12, max(1, width))
        height = min(12, max(1, height))
        settings = item.get("settings", {})
        if not isinstance(settings, dict):
            raise DashboardValidationError(f"layout.widgets[{index}].settings must be an object.")
        clean.append({
            "instance_id": instance_id,
            "widget_id": widget_id,
            "w": width,
            "h": height,
            "settings": deepcopy(settings),
        })

    normalized = {"widgets": clean}
    encoded = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_LAYOUT_BYTES:
        raise DashboardValidationError("Dashboard layout exceeds the 512 KiB limit.")
    return normalized


def normalize_dashboard_payload(payload, *, partial=False, current=None):
    if not isinstance(payload, dict):
        raise DashboardValidationError("Dashboard payload must be an object.")
    allowed = {"name", "visibility", "layout"}
    unknown = set(payload) - allowed
    if unknown:
        raise DashboardValidationError("Unknown dashboard field(s): " + ", ".join(sorted(unknown)))

    result = {}
    if not partial or "name" in payload:
        name = str(payload.get("name", getattr(current, "name", "")) or "").strip()
        if not name:
            raise DashboardValidationError("Dashboard name is required.")
        if len(name) > 160:
            raise DashboardValidationError("Dashboard name may not exceed 160 characters.")
        result["name"] = name

    if not partial or "visibility" in payload:
        visibility = str(payload.get("visibility", getattr(current, "visibility", "private")) or "private").strip().lower()
        if visibility not in VALID_VISIBILITY:
            raise DashboardValidationError("visibility must be private or shared.")
        result["visibility"] = visibility

    if not partial or "layout" in payload:
        result["layout"] = normalize_layout(payload.get("layout", getattr(current, "layout", {})))
    return result


def dashboard_payload(dashboard, viewer):
    owner_name = " ".join(part for part in (
        str(getattr(dashboard.owner, "first_name", "") or "").strip(),
        str(getattr(dashboard.owner, "last_name", "") or "").strip(),
    ) if part) or str(dashboard.owner.username)
    return {
        "id": str(dashboard.id),
        "name": dashboard.name,
        "visibility": dashboard.visibility,
        "owner": {
            "id": dashboard.owner_id,
            "username": dashboard.owner.username,
            "display_name": owner_name,
        },
        "mine": dashboard.owner_id == viewer.id,
        "can_edit": can_edit_dashboard(viewer, dashboard),
        "layout": normalize_layout(dashboard.layout),
        "created_at": dashboard.created_at,
        "updated_at": dashboard.updated_at,
    }

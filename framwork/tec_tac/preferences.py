from __future__ import annotations

import json
from copy import deepcopy

from .models import TecTacUserPreferences


DEFAULT_PREFERENCES = {
    "appearance": {
        "theme": "dark",
        "font_scale": 1.0,
    },
    "navigation": {
        "order": {},
        "favorites": [],
        "collapsed_sections": {},
        "rail_collapsed": False,
    },
    "dashboard": {
        "default_dashboard_id": None,
        "last_dashboard_id": None,
        "restore_last_dashboard": True,
    },
    "extensions": {},
}

THEMES = {"dark", "light", "high-contrast"}
FONT_SCALES = {0.9, 1.0, 1.1, 1.2}
MAX_PREFERENCE_BYTES = 128 * 1024


class PreferenceValidationError(ValueError):
    pass


def _merge(base, override):
    result = deepcopy(base)
    if not isinstance(override, dict):
        return result
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge(result[key], value)
        elif key in result:
            result[key] = deepcopy(value)
    return result


def _string_list(value, field):
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PreferenceValidationError(f"{field} must be an array of strings.")
    return list(dict.fromkeys(item for item in value if item))


def normalize_preferences(payload):
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise PreferenceValidationError("preferences must be an object.")

    unknown = set(payload) - set(DEFAULT_PREFERENCES)
    if unknown:
        raise PreferenceValidationError("Unknown preference section(s): " + ", ".join(sorted(unknown)))

    merged = _merge(DEFAULT_PREFERENCES, payload)
    # These maps intentionally have dynamic keys, so preserve the caller's
    # values rather than treating the empty Core defaults as a closed schema.
    source_navigation = payload.get("navigation") if isinstance(payload.get("navigation"), dict) else {}
    for field in ("order", "favorites", "collapsed_sections", "rail_collapsed"):
        if field in source_navigation:
            merged["navigation"][field] = deepcopy(source_navigation[field])
    if "extensions" in payload:
        merged["extensions"] = deepcopy(payload["extensions"])

    appearance = merged["appearance"]
    if not isinstance(appearance, dict):
        raise PreferenceValidationError("appearance must be an object.")
    if appearance.get("theme") not in THEMES:
        raise PreferenceValidationError("appearance.theme must be dark, light, or high-contrast.")
    font_scale = appearance.get("font_scale")
    if isinstance(font_scale, bool) or not isinstance(font_scale, (int, float)):
        raise PreferenceValidationError("appearance.font_scale must be a supported numeric scale.")
    font_scale = float(font_scale)
    if font_scale not in FONT_SCALES:
        raise PreferenceValidationError("appearance.font_scale must be one of 0.9, 1.0, 1.1, or 1.2.")
    appearance["font_scale"] = font_scale

    navigation = merged["navigation"]
    if not isinstance(navigation, dict):
        raise PreferenceValidationError("navigation must be an object.")
    order = navigation.get("order")
    if not isinstance(order, dict):
        raise PreferenceValidationError("navigation.order must be an object.")
    clean_order = {}
    for section, routes in order.items():
        if not isinstance(section, str):
            raise PreferenceValidationError("navigation.order section names must be strings.")
        clean_order[section] = _string_list(routes, f"navigation.order.{section}")
    navigation["order"] = clean_order
    navigation["favorites"] = _string_list(navigation.get("favorites"), "navigation.favorites")
    collapsed = navigation.get("collapsed_sections")
    if not isinstance(collapsed, dict) or any(not isinstance(k, str) or not isinstance(v, bool) for k, v in collapsed.items()):
        raise PreferenceValidationError("navigation.collapsed_sections must be an object of boolean values.")
    if not isinstance(navigation.get("rail_collapsed"), bool):
        raise PreferenceValidationError("navigation.rail_collapsed must be true or false.")

    dashboard = merged["dashboard"]
    if not isinstance(dashboard, dict):
        raise PreferenceValidationError("dashboard must be an object.")
    dashboard_id = dashboard.get("default_dashboard_id")
    if dashboard_id is not None and not isinstance(dashboard_id, str):
        raise PreferenceValidationError("dashboard.default_dashboard_id must be a string or null.")
    last_dashboard_id = dashboard.get("last_dashboard_id")
    if last_dashboard_id is not None and not isinstance(last_dashboard_id, str):
        raise PreferenceValidationError("dashboard.last_dashboard_id must be a string or null.")
    if not isinstance(dashboard.get("restore_last_dashboard"), bool):
        raise PreferenceValidationError("dashboard.restore_last_dashboard must be true or false.")

    if not isinstance(merged.get("extensions"), dict):
        raise PreferenceValidationError("extensions must be an object.")

    encoded = json.dumps(merged, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_PREFERENCE_BYTES:
        raise PreferenceValidationError("preferences exceed the 128 KiB limit.")
    return merged


def get_user_preferences(user):
    try:
        record = TecTacUserPreferences.objects.get(user=user)
    except TecTacUserPreferences.DoesNotExist:
        return deepcopy(DEFAULT_PREFERENCES), False, None
    try:
        normalized = normalize_preferences(record.preferences)
    except PreferenceValidationError:
        normalized = deepcopy(DEFAULT_PREFERENCES)
    return normalized, True, record.updated_at


def save_user_preferences(user, payload):
    normalized = normalize_preferences(payload)
    record, _ = TecTacUserPreferences.objects.update_or_create(
        user=user,
        defaults={"preferences": normalized},
    )
    return normalized, record.updated_at


def reset_user_preferences(user):
    TecTacUserPreferences.objects.filter(user=user).delete()
    return deepcopy(DEFAULT_PREFERENCES)

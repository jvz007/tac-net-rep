from django.db import migrations, models


_NATIVE = {
    "client": "client", "clients": "client",
    "site": "site", "sites": "site",
    "endpoint": "endpoint", "endpoints": "endpoint",
    "agent": "endpoint", "agents": "endpoint",
}
_ALIASES = {
    "client": ("ids", "client_ids", "client_id", "clients", "client", "id"),
    "site": ("ids", "site_ids", "site_id", "sites", "site", "id"),
    "endpoint": ("ids", "agent_ids", "agent_id", "endpoint_ids", "endpoint_id", "agents", "agent", "endpoints", "endpoint", "id"),
}


def _values(value):
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _ids(kind, values):
    out, seen = [], set()
    for value in _values(values):
        if kind in {"client", "site"}:
            if isinstance(value, bool):
                raise ValueError("boolean identifier")
            ident = int(value)
            if ident <= 0:
                raise ValueError("non-positive identifier")
            value = ident
        else:
            if isinstance(value, bool) or value in (None, ""):
                raise ValueError("empty endpoint identifier")
            value = str(value).strip()
            if not value:
                raise ValueError("empty endpoint identifier")
        marker = (type(value).__name__, str(value))
        if marker not in seen:
            seen.add(marker)
            out.append(value)
    return out


def _extract_native(obj, kind):
    present = [key for key in _ALIASES[kind] if key in obj]
    if not present:
        raise ValueError("missing target identifiers")
    # Multiple aliases are safe only when they resolve to the same set.
    resolved = [_ids(kind, obj[key]) for key in present]
    first = resolved[0]
    if any(value != first for value in resolved[1:]):
        raise ValueError("conflicting legacy target aliases")
    return first


def _legacy_normalize(targets):
    if not isinstance(targets, dict):
        raise ValueError("targets is not an object")
    target_type = str(targets.get("type") or "none").strip().lower()
    if target_type in {"", "none"}:
        return {"type": "none"}
    kind = _NATIVE.get(target_type)
    if kind:
        return {"type": target_type, "ids": _extract_native(targets, kind)}
    if target_type != "dynamic":
        return targets

    scope = targets.get("scope")
    if isinstance(scope, dict):
        explicit_type = str(scope.get("type") or "").strip().lower()
        explicit_kind = _NATIVE.get(explicit_type) if explicit_type else None
        if explicit_type and not explicit_kind:
            raise ValueError("dynamic scope type is not Tactical-native")

        found = []
        for candidate_type, candidate_kind in (("client", "client"), ("site", "site"), ("endpoint", "endpoint")):
            keys = [key for key in _ALIASES[candidate_kind] if key != "ids" and key in scope]
            if keys:
                found.append((candidate_type, candidate_kind, keys))

        if explicit_kind:
            foreign = [item for item in found if item[1] != explicit_kind]
            if foreign:
                raise ValueError("dynamic scope contains multiple Tactical scope types")
            scope_type = "endpoint" if explicit_kind == "endpoint" else explicit_kind
            scope_kind = explicit_kind
            ids = _extract_native(scope, scope_kind)
        else:
            if len(found) != 1:
                raise ValueError("dynamic scope has no unambiguous Tactical scope alias")
            scope_type, scope_kind, _ = found[0]
            ids = _extract_native(scope, scope_kind)
    else:
        found = []
        for scope_type, scope_kind in (("client", "client"), ("site", "site"), ("endpoint", "endpoint")):
            keys = [key for key in _ALIASES[scope_kind] if key != "ids" and key in targets]
            if keys:
                found.append((scope_type, scope_kind, keys))
        if len(found) != 1:
            raise ValueError("dynamic target has no unambiguous explicit scope")
        scope_type, scope_kind, _ = found[0]
        ids = _extract_native(targets, scope_kind)

    filt = targets.get("filter", {})
    if not isinstance(filt, dict):
        raise ValueError("dynamic filter is not an object")
    result = {"type": "dynamic", "scope": {"type": scope_type, "ids": ids}}
    if filt:
        result["filter"] = filt
    return result


def canonicalize_existing_targets(apps, schema_editor):
    Schedule = apps.get_model("tec_tac", "TecTacSchedule")
    Run = apps.get_model("tec_tac", "TecTacScheduleRun")

    for schedule in Schedule.objects.all().iterator():
        try:
            canonical = _legacy_normalize(schedule.targets or {})
        except Exception as exc:
            target_type = str((schedule.targets or {}).get("type") or "none").strip().lower() if isinstance(schedule.targets, dict) else "invalid"
            if target_type in set(_NATIVE) | {"dynamic", "none", ""}:
                schedule.enabled = False
                schedule.target_state = "invalid"
                schedule.target_state_detail = (f"Legacy target requires administrator review: {exc}")[:500]
                schedule.save(update_fields=["enabled", "target_state", "target_state_detail"])
            continue
        schedule.targets = canonical
        schedule.target_state = "valid"
        schedule.target_state_detail = ""
        schedule.save(update_fields=["targets", "target_state", "target_state_detail"])

    # History is immutable evidence. Canonicalize snapshots only when the old
    # shape can be converted without guessing; otherwise retain the original.
    for run in Run.objects.all().iterator():
        try:
            canonical = _legacy_normalize(run.targets_snapshot or {})
        except Exception:
            continue
        if canonical != (run.targets_snapshot or {}):
            run.targets_snapshot = canonical
            run.save(update_fields=["targets_snapshot"])


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0014_scheduler_last_queued_at")]
    operations = [
        migrations.AddField(
            model_name="tectacschedule",
            name="target_state",
            field=models.CharField(default="valid", max_length=24),
        ),
        migrations.AddField(
            model_name="tectacschedule",
            name="target_state_detail",
            field=models.CharField(blank=True, default="", max_length=500),
        ),
        migrations.RunPython(canonicalize_existing_targets, migrations.RunPython.noop),
    ]

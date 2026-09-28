from django.db import migrations


_NATIVE = {
    "endpoint": "endpoint", "endpoints": "endpoint",
    "agent": "endpoint", "agents": "endpoint",
}


def _values(value):
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _endpoint_rows(apps):
    Agent = apps.get_model("agents", "Agent")
    return list(Agent.objects.all().values_list("pk", "agent_id"))


def _canonical_endpoint_ids(values, rows):
    out = []
    for raw in _values(values):
        if isinstance(raw, bool) or raw in (None, ""):
            raise ValueError("empty endpoint identifier")
        token = str(raw).strip()
        if not token:
            raise ValueError("empty endpoint identifier")
        matches = {(int(pk), str(agent_id)) for pk, agent_id in rows if str(agent_id) == token or str(pk) == token}
        if not matches:
            raise ValueError(f"unknown endpoint identifier {token!r}")
        if len(matches) != 1:
            raise ValueError(f"ambiguous endpoint identifier {token!r}")
        agent_id = next(iter(matches))[1]
        if agent_id not in out:
            out.append(agent_id)
    return out


def _canonicalize_endpoint_identity(targets, rows):
    if not isinstance(targets, dict):
        return targets
    result = dict(targets)
    target_type = str(result.get("type") or "none").strip().lower()
    if _NATIVE.get(target_type) == "endpoint":
        result["ids"] = _canonical_endpoint_ids(result.get("ids", []), rows)
        return result
    if target_type == "dynamic":
        scope = dict(result.get("scope") or {})
        if _NATIVE.get(str(scope.get("type") or "").strip().lower()) == "endpoint":
            scope["type"] = "endpoint"
            scope["ids"] = _canonical_endpoint_ids(scope.get("ids", []), rows)
            result["scope"] = scope
    return result


def canonicalize_endpoint_identity(apps, schema_editor):
    Schedule = apps.get_model("tec_tac", "TecTacSchedule")
    rows = _endpoint_rows(apps)
    for schedule in Schedule.objects.all().iterator():
        try:
            canonical = _canonicalize_endpoint_identity(schedule.targets or {}, rows)
        except Exception as exc:
            target_type = str((schedule.targets or {}).get("type") or "none").strip().lower() if isinstance(schedule.targets, dict) else "invalid"
            if target_type in set(_NATIVE) | {"dynamic"}:
                schedule.enabled = False
                schedule.target_state = "invalid"
                schedule.target_state_detail = (f"Endpoint target requires administrator review: {exc}")[:500]
                schedule.save(update_fields=["enabled", "target_state", "target_state_detail"])
            continue
        if canonical != (schedule.targets or {}):
            schedule.targets = canonical
            schedule.target_state = "valid"
            schedule.target_state_detail = ""
            schedule.save(update_fields=["targets", "target_state", "target_state_detail"])


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0018_scheduler_history_indexes")]
    operations = [
        migrations.RunPython(canonicalize_endpoint_identity, migrations.RunPython.noop),
    ]

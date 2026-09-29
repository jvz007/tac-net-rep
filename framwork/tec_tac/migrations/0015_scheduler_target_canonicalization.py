from django.db import migrations, models
import re


_NATIVE = {
    "client": "client", "clients": "client",
    "site": "site", "sites": "site",
    "endpoint": "endpoint", "endpoints": "endpoint",
    "agent": "endpoint", "agents": "endpoint",
}
_ALIASES = {
    "client": ("client_ids", "client_id", "clients", "client"),
    "site": ("site_ids", "site_id", "sites", "site"),
    "endpoint": ("agent_ids", "agent_id", "endpoint_ids", "endpoint_id", "agents", "agent", "endpoints", "endpoint"),
}



_RESERVED_FILTER_SCOPE_KEYS = {
    "id", "ids",
    *(_ALIASES["client"]), *(_ALIASES["site"]), *(_ALIASES["endpoint"]),
}

def _scope_alias_token(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    def normalize(token):
        token = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", token)
        token = re.sub(r"[^a-zA-Z0-9]+", "_", token).strip("_").lower()
        return re.sub(r"_+", "_", token)
    whole = normalize(raw)
    if whole in _RESERVED_FILTER_SCOPE_KEYS:
        return whole
    raw_parts = [part for part in re.split(r"(?:__|[./:\[\]]+)", raw) if part]
    parts = [normalize(part) for part in raw_parts]
    lookup_suffixes = {"exact","iexact","contains","icontains","in","gt","gte","lt","lte","startswith","istartswith","endswith","iendswith","range","date","year","iso_year","month","day","week","week_day","iso_week_day","quarter","time","hour","minute","second","isnull","regex","iregex"}
    while parts and parts[-1] in lookup_suffixes:
        parts.pop()
    specific = _RESERVED_FILTER_SCOPE_KEYS - {"id","ids","client","clients","site","sites","agent","agents","endpoint","endpoints"}
    for token in parts:
        if token in specific:
            return token
    scope_nouns = {"client","clients","site","sites","agent","agents","endpoint","endpoints"}
    for left, right in zip(parts, parts[1:]):
        if left in scope_nouns and right in {"id","ids","pk"}:
            suffix = "ids" if right == "ids" else "id"
            alias = f"{left.rstrip('s')}_{suffix}"
            if alias in specific:
                return alias
    return None

def _reserved_filter_value(value):
    if isinstance(value, str):
        return _scope_alias_token(value)
    if isinstance(value, list):
        for item in value:
            found = _reserved_filter_value(item)
            if found:
                return found
        return None
    if isinstance(value, dict):
        for item in value.values():
            found = _reserved_filter_value(item)
            if found:
                return found
    return None

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
        if "ids" in targets:
            ids = _ids(kind, targets.get("ids"))
            legacy = [key for key in _ALIASES[kind] if key in targets]
            if legacy and _extract_native(targets, kind) != ids:
                raise ValueError("conflicting canonical ids and legacy target aliases")
            # Keep the submitted native target type. Existing modules may
            # declare plural/agent aliases in target_types and consume that
            # exact vocabulary at dispatch time. Singularisation is an
            # internal Core concern only.
            return {"type": target_type, "ids": ids}
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
            keys = [key for key in _ALIASES[candidate_kind] if key in scope]
            if keys:
                found.append((candidate_type, candidate_kind, keys))

        if explicit_kind:
            foreign = [item for item in found if item[1] != explicit_kind]
            if foreign:
                raise ValueError("dynamic scope contains multiple Tactical scope types")
            scope_type = "endpoint" if explicit_kind == "endpoint" else explicit_kind
            scope_kind = explicit_kind
            if "ids" in scope:
                alias_values = [key for key in _ALIASES[scope_kind] if key in scope]
                ids = _ids(scope_kind, scope.get("ids"))
                if alias_values and _extract_native(scope, scope_kind) != ids:
                    raise ValueError("dynamic scope contains conflicting ids and legacy aliases")
            else:
                ids = _extract_native(scope, scope_kind)
        else:
            if len(found) != 1:
                raise ValueError("dynamic scope has no unambiguous Tactical scope alias")
            scope_type, scope_kind, _ = found[0]
            ids = _extract_native(scope, scope_kind)
    else:
        found = []
        for scope_type, scope_kind in (("client", "client"), ("site", "site"), ("endpoint", "endpoint")):
            keys = [key for key in _ALIASES[scope_kind] if key in targets]
            if keys:
                found.append((scope_type, scope_kind, keys))
        if len(found) != 1:
            raise ValueError("dynamic target has no unambiguous explicit scope")
        scope_type, scope_kind, _ = found[0]
        ids = _extract_native(targets, scope_kind)

    filt = targets.get("filter", {})
    if not isinstance(filt, dict):
        raise ValueError("dynamic filter is not an object")
    reserved = next((str(key).strip().lower() for key in filt if str(key).strip().lower() in _RESERVED_FILTER_SCOPE_KEYS), None)
    if reserved:
        raise ValueError(f"dynamic filter contains Tactical scope key {reserved!r}")
    reserved_value = _reserved_filter_value(filt)
    if reserved_value:
        raise ValueError(f"dynamic filter uses Tactical scope alias {reserved_value!r} as a value")
    result = {"type": "dynamic", "scope": {"type": scope_type, "ids": ids}}
    if filt:
        result["filter"] = filt
    return result



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
    result = dict(targets)
    target_type = str(result.get("type") or "none").strip().lower()
    kind = _NATIVE.get(target_type)
    if kind == "endpoint":
        result["ids"] = _canonical_endpoint_ids(result.get("ids", []), rows)
        return result
    if target_type == "dynamic":
        scope = dict(result.get("scope") or {})
        scope_kind = _NATIVE.get(str(scope.get("type") or "").strip().lower())
        if scope_kind == "endpoint":
            scope["type"] = "endpoint"
            scope["ids"] = _canonical_endpoint_ids(scope.get("ids", []), rows)
            result["scope"] = scope
    return result

def canonicalize_existing_targets(apps, schema_editor):
    Schedule = apps.get_model("tec_tac", "TecTacSchedule")
    Run = apps.get_model("tec_tac", "TecTacScheduleRun")
    endpoint_rows = _endpoint_rows(apps)

    for schedule in Schedule.objects.all().iterator():
        try:
            canonical = _legacy_normalize(schedule.targets or {})
            canonical = _canonicalize_endpoint_identity(canonical, endpoint_rows)
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

    # Run history is immutable evidence. Never rewrite targets_snapshot in a migration.



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

from __future__ import annotations

import re


class SchedulerTargetShapeError(ValueError):
    pass


_NATIVE_KIND = {
    "client": "client",
    "clients": "client",
    "site": "site",
    "sites": "site",
    "endpoint": "endpoint",
    "endpoints": "endpoint",
    "agent": "endpoint",
    "agents": "endpoint",
}

_ALIASES = {
    "client": ("client_id", "client_ids", "client", "clients"),
    "site": ("site_id", "site_ids", "site", "sites"),
    "endpoint": ("agent_id", "agent_ids", "endpoint_id", "endpoint_ids", "agent", "agents", "endpoint", "endpoints"),
}

# Dynamic filters are module-owned, but Tactical scope identifiers belong in
# targets.scope. Nested objects may contain ordinary domain keys such as id/ids,
# but Tactical scope aliases may not be used as filter keys at the top level or
# as filter value tokens anywhere in the expression. Generic filter DSLs often
# encode a selected field as a value (for example {"field": "site_id"}),
# which must not become an alternate scope channel.
_RESERVED_FILTER_SCOPE_KEYS = {
    "id", "ids",
    *(_ALIASES["client"]),
    *(_ALIASES["site"]),
    *(_ALIASES["endpoint"]),
}



def _scope_alias_token(value: str):
    """Return a Tactical scope alias only for an explicit field reference.

    Dynamic filters are module-owned data.  Descriptive values such as
    ``Main Site`` or ``windows_agent`` must never be interpreted as Tactical
    scope merely because their normalized text ends with a scope noun.

    Scope-field spellings are rejected only when the complete value is an
    exact scope alias, or when an explicit path/reference encodes one (for
    example ``site.id``, ``selector/site_id`` or ``payload.clientIds``).
    Bare scope nouns inside a longer path such as ``ticket.client`` remain
    module-owned fields rather than alternate Tactical scope selectors.
    """
    raw = str(value or "").strip()
    if not raw:
        return None

    def normalize(token: str) -> str:
        token = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", token)
        token = re.sub(r"[^a-zA-Z0-9]+", "_", token).strip("_").lower()
        return re.sub(r"_+", "_", token)

    whole = normalize(raw)
    if whole in _RESERVED_FILTER_SCOPE_KEYS:
        return whole

    # Explicit field references can use path separators or Django-style
    # ``__lookup`` suffixes.  Split those syntaxes before checking aliases so
    # selectors such as ``site_id__in``, ``payload__clientIds__exact`` and
    # ``site.pk`` cannot become a second Tactical scope channel.  A bare scope
    # noun inside a module-owned path (for example ``ticket.client``) remains
    # valid because it does not identify a Tactical id field.
    raw_parts = [part for part in re.split(r"(?:__|[./:\[\]]+)", raw) if part]
    parts = [normalize(part) for part in raw_parts]
    lookup_suffixes = {
        "exact", "iexact", "contains", "icontains", "in", "gt", "gte",
        "lt", "lte", "startswith", "istartswith", "endswith", "iendswith",
        "range", "date", "year", "iso_year", "month", "day", "week",
        "week_day", "iso_week_day", "quarter", "time", "hour", "minute",
        "second", "isnull", "regex", "iregex",
    }
    while parts and parts[-1] in lookup_suffixes:
        parts.pop()

    specific = _RESERVED_FILTER_SCOPE_KEYS - {
        "id", "ids", "client", "clients", "site", "sites",
        "agent", "agents", "endpoint", "endpoints",
    }
    for token in parts:
        if token in specific:
            return token
    scope_nouns = {"client", "clients", "site", "sites", "agent", "agents", "endpoint", "endpoints"}
    for left, right in zip(parts, parts[1:]):
        if left in scope_nouns and right in {"id", "ids", "pk"}:
            suffix = "ids" if right == "ids" else "id"
            alias = f"{left.rstrip('s')}_{suffix}"
            if alias in specific:
                return alias
    return None


def _reserved_filter_value(value):
    """Return the first Tactical scope alias used as a filter value token."""
    if isinstance(value, str):
        return _scope_alias_token(value)
    if isinstance(value, list):
        for item in value:
            reserved = _reserved_filter_value(item)
            if reserved:
                return reserved
        return None
    if isinstance(value, dict):
        # Nested keys are module-owned; inspect only their values so generic
        # field/operator DSLs cannot encode Tactical scope through a value.
        for item in value.values():
            reserved = _reserved_filter_value(item)
            if reserved:
                return reserved
        return None
    return None

def _dedupe(values):
    out = []
    seen = set()
    for value in values:
        marker = (type(value).__name__, str(value))
        if marker in seen:
            continue
        seen.add(marker)
        out.append(value)
    return out


def _as_list(value):
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _canonical_ids(kind: str, values):
    if not isinstance(values, list):
        raise SchedulerTargetShapeError("Tactical-native scheduler targets.ids must be an array.")
    cleaned = []
    if kind in {"client", "site"}:
        label = "Client" if kind == "client" else "Site"
        for value in values:
            if isinstance(value, bool):
                raise SchedulerTargetShapeError(f"{label} target identifiers must be integer IDs.")
            try:
                ident = int(value)
            except (TypeError, ValueError) as exc:
                raise SchedulerTargetShapeError(f"{label} target identifiers must be integer IDs.") from exc
            if ident <= 0:
                raise SchedulerTargetShapeError(f"{label} target identifiers must be positive integers.")
            cleaned.append(ident)
    else:
        for value in values:
            if isinstance(value, bool) or value in (None, ""):
                raise SchedulerTargetShapeError("Endpoint target identifiers must be non-empty agent IDs or positive database IDs.")
            text = str(value).strip()
            if not text:
                raise SchedulerTargetShapeError("Endpoint target identifiers must be non-empty agent IDs or positive database IDs.")
            cleaned.append(text)
    return _dedupe(cleaned)


def _reject_unknown_keys(obj: dict, allowed: set[str], label: str):
    extra = sorted(str(key) for key in obj.keys() if str(key) not in allowed)
    if extra:
        raise SchedulerTargetShapeError(f"{label} contains unsupported key(s): {', '.join(extra)}.")


def _legacy_scope_candidate(obj: dict, kind: str):
    present = [key for key in _ALIASES[kind] if key in obj]
    if not present:
        return None
    resolved = [_canonical_ids(kind, _as_list(obj[key])) for key in present]
    first = resolved[0]
    if any(value != first for value in resolved[1:]):
        raise SchedulerTargetShapeError(f"Dynamic scope contains conflicting {kind} target aliases.")
    return first


def _canonical_dynamic_scope(scope: dict):
    if not isinstance(scope, dict):
        raise SchedulerTargetShapeError("Dynamic targets.scope must be an object.")

    allowed = {"type", "ids"}
    for aliases in _ALIASES.values():
        allowed.update(aliases)
    _reject_unknown_keys(scope, allowed, "Dynamic targets.scope")

    explicit_type = str(scope.get("type") or "").strip().lower()
    explicit_kind = _NATIVE_KIND.get(explicit_type) if explicit_type else None
    if explicit_type and not explicit_kind:
        raise SchedulerTargetShapeError("Dynamic targets.scope.type must be client, site, endpoint, or agent.")

    candidates = {}
    for kind in ("client", "site", "endpoint"):
        values = _legacy_scope_candidate(scope, kind)
        if values is not None:
            candidates[kind] = values

    if "ids" in scope:
        if not explicit_kind:
            raise SchedulerTargetShapeError("Dynamic targets.scope.ids requires an explicit scope type.")
        ids_values = _canonical_ids(explicit_kind, scope.get("ids"))
        previous = candidates.get(explicit_kind)
        if previous is not None and previous != ids_values:
            raise SchedulerTargetShapeError("Dynamic scope contains conflicting ids and legacy aliases.")
        candidates[explicit_kind] = ids_values

    if explicit_kind:
        foreign = [kind for kind in candidates if kind != explicit_kind]
        if foreign:
            raise SchedulerTargetShapeError("Dynamic scope contains identifiers for more than one Tactical scope type.")
        values = candidates.get(explicit_kind)
        if values is None:
            raise SchedulerTargetShapeError("Dynamic targets.scope requires target identifiers.")
        scope_type = "endpoint" if explicit_kind == "endpoint" else explicit_kind
        return {"type": scope_type, "ids": values}

    if len(candidates) != 1:
        if not candidates:
            raise SchedulerTargetShapeError("Dynamic targets.scope requires client, site, or endpoint identifiers.")
        raise SchedulerTargetShapeError("Dynamic targets.scope must identify exactly one Tactical scope type.")
    kind, values = next(iter(candidates.items()))
    scope_type = "endpoint" if kind == "endpoint" else kind
    return {"type": scope_type, "ids": values}


def _dynamic_root_scope(targets: dict):
    """Accept the documented scope object and legacy root aliases as input.

    Legacy aliases are never forwarded to handlers. They are converted to the
    canonical {type, ids} scope first. If both forms are supplied they must
    resolve to the same scope exactly.
    """
    root_allowed = {"type", "scope", "filter"}
    for aliases in _ALIASES.values():
        root_allowed.update(aliases)
    _reject_unknown_keys(targets, root_allowed, "Dynamic targets")

    canonical = None
    if "scope" in targets:
        canonical = _canonical_dynamic_scope(targets.get("scope"))

    root_scope = {key: targets[key] for aliases in _ALIASES.values() for key in aliases if key in targets}
    if root_scope:
        root_canonical = _canonical_dynamic_scope(root_scope)
        if canonical is not None and root_canonical != canonical:
            raise SchedulerTargetShapeError("Dynamic targets contain conflicting scope and legacy root scope aliases.")
        canonical = root_canonical

    if canonical is None:
        raise SchedulerTargetShapeError("Dynamic targets.scope must be an object with an explicit Tactical scope.")
    return canonical


def normalize_scheduler_targets(targets):
    """Validate and canonicalise Core-understood Tactical target shapes.

    Static Tactical-native targets are strict ``type`` + ``ids`` objects.
    Dynamic targets remain backwards-compatible with the documented legacy
    scope aliases (for example ``scope.client_id`` or ``scope.site_ids``), but
    Core converts those aliases to canonical ``scope: {type, ids}`` before the
    target reaches authorization, persistence, or a scheduled handler.

    Module-specific target types are intentionally returned unchanged because
    Core cannot safely infer their semantics.
    """
    if targets is None:
        targets = {"type": "none"}
    if not isinstance(targets, dict):
        raise SchedulerTargetShapeError("targets must be an object.")

    target_type = str(targets.get("type") or "none").strip().lower()
    if target_type in {"", "none"}:
        _reject_unknown_keys(targets, {"type"}, "targets")
        return {"type": "none"}

    kind = _NATIVE_KIND.get(target_type)
    if kind:
        _reject_unknown_keys(targets, {"type", "ids"}, "Tactical-native targets")
        if "ids" not in targets:
            raise SchedulerTargetShapeError("Tactical-native scheduler targets require an ids array.")
        # Preserve the module-declared native target vocabulary for persistence
        # and handler dispatch. Core derives the singular Tactical kind only
        # inside scope/authorization helpers via _NATIVE_KIND.
        return {"type": target_type, "ids": _canonical_ids(kind, targets.get("ids"))}

    if target_type != "dynamic":
        return dict(targets)

    scope = _dynamic_root_scope(targets)
    filt = targets.get("filter", {})
    if not isinstance(filt, dict):
        raise SchedulerTargetShapeError("Dynamic targets.filter must be an object.")
    reserved = next((str(key).strip().lower() for key in filt if str(key).strip().lower() in _RESERVED_FILTER_SCOPE_KEYS), None)
    if reserved:
        raise SchedulerTargetShapeError(
            f"Dynamic targets.filter may not contain top-level Tactical target key {reserved!r}; put client/site/endpoint scope in targets.scope."
        )
    reserved_value = _reserved_filter_value(filt)
    if reserved_value:
        raise SchedulerTargetShapeError(
            f"Dynamic targets.filter may not use Tactical target alias {reserved_value!r} as a filter value; put client/site/endpoint scope in targets.scope."
        )

    result = {"type": "dynamic", "scope": scope}
    if filt:
        result["filter"] = filt
    return result


def tactical_scope_ref(targets):
    """Return the one canonical Tactical scope reference, or None for custom types."""
    canonical = normalize_scheduler_targets(targets)
    target_type = canonical.get("type", "none")
    if target_type == "none":
        return {"kind": "none", "values": []}
    if target_type == "dynamic":
        scope = canonical["scope"]
        return {"kind": _NATIVE_KIND[scope["type"]], "values": list(scope["ids"])}
    kind = _NATIVE_KIND.get(target_type)
    if not kind:
        return {"kind": "module", "values": []}
    return {"kind": kind, "values": list(canonical["ids"])}

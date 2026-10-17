"""Core filter sets (Core 1.17.50, capability ``core.filter_sets`` 1.0.0).

One filter facility for every module's lists:

* one **operator vocabulary** (equals, not equals, contains, does not contain, starts with, ends with), owned by Core;
* **field declarations**: a module says which fields a person may filter on and how to find them. The browser sees the id,
  label, kind, operators and value source of a field, never a lookup or a key;
* a **safe validator** and two **evaluators** a module reuses (a Django ``Q`` and an in-memory twin), so a rule typed in the
  browser can never become a field name, SQL or a regular expression;
* **saved, named filter sets** with an owner, sharing and a per-view key, stored on the saved views table (no new table);
* a **distinct-values lookup** for the "Equals" pickers, answered by the module that owns the field, inside the person's scope.

Rules that matter:

* A filter only narrows. The module's own list is already role-scoped, and a filter set is ANDed onto it.
* A filter set that names a field the person may not use, or one the module no longer declares, is refused (fail closed). It is
  never silently dropped and never widened.
* Core never calls a module's provider for another module from Python. The distinct-values lookup is private to the HTTP route
  and serves the signed-in person only. A module that evaluates a set passes in its own field declarations.
* Filter sets live under the reserved saved-view key prefix ``fs-``. The saved views service refuses that prefix.
* Every create, change, share change and delete writes a strict Core audit row in the same transaction. The row never holds a
  rule value and never a reader id.

Django is imported lazily, so the pure parts (vocabulary, validator, evaluators) run without it, like ``saved_views``.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("tec_tac.filter_sets")

CAPABILITY_ID = "core.filter_sets"
CAPABILITY_VERSION = "1.0.0"
PROVIDER_CAPABILITY_SUFFIX = "filter_fields"
PROVIDER_CAPABILITY_VERSION = "1.0.0"
PROVIDER_VERSION_RANGE = ">=1.0.0,<2.0.0"

VIEW_KEY_PREFIX = "fs-"
MAX_KEY_LENGTH = 64 - len(VIEW_KEY_PREFIX)
MAX_RULES = 50
MAX_GROUPS = 20
MAX_DEPTH = 3
MAX_VALUE_LENGTH = 200
MAX_LABEL_LENGTH = 300
MAX_FIELDS = 100
MAX_STATIC_OPTIONS = 50
MAX_SETS_PER_KEY = 100
MAX_LIST_ROWS = 500
MAX_SEARCH_LENGTH = 100
MAX_PAGE = 200
PAGE_SIZE = 25
MAX_PAGE_SIZE = 50
CACHE_SECONDS = 30
CACHE_MAX_ENTRIES = 256
MAX_ID_VALUE = 2**63 - 1

# The six operators Groups has used since its first release. The ids and labels must not change meaning.
OPERATORS: dict[str, str] = {
    "equals": "Equals",
    "not_equals": "Does not equal",
    "contains": "Contains",
    "not_contains": "Does not contain",
    "starts_with": "Starts with",
    "ends_with": "Ends with",
}
ID_OPERATORS = ("equals", "not_equals")
TEXT_OPERATORS = tuple(OPERATORS)
BOOL_OPERATORS = ("equals",)
KINDS = ("text", "id", "bool")
VALUE_SOURCES = ("distinct", "static", "none")
_LOOKUP_SUFFIX = {
    "equals": "iexact", "not_equals": "iexact", "contains": "icontains", "not_contains": "icontains",
    "starts_with": "istartswith", "ends_with": "iendswith",
}
_NEGATED = ("not_equals", "not_contains")

_FIELD_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_LOOKUP_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(__[A-Za-z_][A-Za-z0-9_]*)*$")
_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,%d}$" % (MAX_KEY_LENGTH - 1))
_UNSET = object()


# --- errors -----------------------------------------------------------------------------------

class FilterSetError(Exception):
    """Base class for every filter set failure. ``status_code`` is the HTTP mapping, ``code`` a stable word."""

    status_code = 400
    code = "invalid_filter_set"


class FilterSetValidationError(FilterSetError, ValueError):
    status_code = 400


class FilterSetFieldUnavailable(FilterSetValidationError):
    """A rule names a field the person may not use, or one the module does not declare."""

    status_code = 422
    code = "field_unavailable"


class FilterSetNotFound(FilterSetError):
    status_code = 404
    code = "not_found"


class FilterSetPermissionDenied(FilterSetError):
    status_code = 403
    code = "permission_denied"


class FilterSetConflict(FilterSetError):
    status_code = 409
    code = "name_conflict"


class FilterSetAuditError(FilterSetError):
    status_code = 500
    code = "audit_failed"


class FilterSetNoProvider(FilterSetError):
    """The module offers no filter fields."""

    status_code = 404
    code = "filter_fields_unavailable"


class FilterSetProviderError(FilterSetError):
    """The module's provider failed. The text never carries the provider's own error."""

    status_code = 502
    code = "values_unavailable"


_BY_STATUS = {400: FilterSetValidationError, 403: FilterSetPermissionDenied, 404: FilterSetNotFound, 409: FilterSetConflict, 500: FilterSetAuditError}


def _saved_views():
    from . import saved_views

    return saved_views


@contextmanager
def _saved_view_errors():
    """Saved views helpers raise their own errors. Hand them on as filter set errors with the same status."""
    sv = _saved_views()
    try:
        yield sv
    except sv.SavedViewError as exc:
        raise _BY_STATUS.get(exc.status_code, FilterSetValidationError)(str(exc)) from exc


# --- vocabulary -------------------------------------------------------------------------------

def operators_for(kind: str, has_name: bool = False) -> list[dict[str, str]]:
    """The operators a field of this kind offers, each ``{id, label}``.

    ``text`` gets all six. ``bool`` gets equals only. ``id`` (client, site) gets equals and does not equal on the ID, plus the four
    text operators matched on the display name, but only when the field declares a name (``has_name``).
    """
    if kind == "text":
        ids = TEXT_OPERATORS
    elif kind == "bool":
        ids = BOOL_OPERATORS
    elif kind == "id":
        ids = ID_OPERATORS + tuple(op for op in TEXT_OPERATORS if op not in ID_OPERATORS) if has_name else ID_OPERATORS
    else:
        raise FilterSetValidationError(f"Unknown field kind {kind!r}.")
    return [{"id": op, "label": OPERATORS[op]} for op in ids]


def _operator_ids(field: dict) -> tuple[str, ...]:
    return tuple(row["id"] for row in operators_for(field["kind"], bool(field.get("name_lookup") or field.get("name_key"))))


# --- field declarations -----------------------------------------------------------------------

def _plain_text(value: Any, label: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise FilterSetValidationError(f"{label} must be text.")
    text = value.strip()
    if not text:
        raise FilterSetValidationError(f"{label} is required.")
    if len(text) > maximum:
        raise FilterSetValidationError(f"{label} may not exceed {maximum} characters.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise FilterSetValidationError(f"{label} may not contain control characters.")
    return text


def _clean_option(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FilterSetValidationError("A static option must be an object.")
    value = raw.get("value")
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise FilterSetValidationError("A static option value must be text or a whole number.")
    if isinstance(value, str):
        value = _plain_text(value, "A static option value", maximum=MAX_VALUE_LENGTH)
    label = raw.get("label")
    label = str(value) if label in (None, "") else _plain_text(label, "A static option label", maximum=MAX_LABEL_LENGTH)
    return {"value": value, "label": label}


def _clean_field(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FilterSetValidationError("A field declaration must be an object.")
    field_id = raw.get("id")
    if not isinstance(field_id, str) or not _FIELD_ID_RE.fullmatch(field_id):
        raise FilterSetValidationError("A field id must be a lowercase slug of letters, digits and '_', up to 64 characters.")
    label = _plain_text(raw.get("label"), "A field label", maximum=80)
    kind = raw.get("kind")
    if kind not in KINDS:
        raise FilterSetValidationError(f"Field {field_id!r} has an unknown kind.")
    out: dict[str, Any] = {"id": field_id, "label": label, "kind": kind, "lookup": None, "row_key": None,
                           "name_lookup": None, "name_key": None, "values": {"source": "none", "options": []}}
    for key in ("lookup", "name_lookup"):
        value = raw.get(key)
        if value is not None:
            if not isinstance(value, str) or len(value) > 100 or not _LOOKUP_RE.fullmatch(value):
                raise FilterSetValidationError(f"Field {field_id!r}: {key} must be a plain model field path.")
            out[key] = value
    for key in ("row_key", "name_key"):
        value = raw.get(key)
        if value is not None:
            out[key] = _plain_text(value, f"Field {field_id!r}: {key}", maximum=64)
    if out["lookup"] is None and out["row_key"] is None:
        raise FilterSetValidationError(f"Field {field_id!r} needs a lookup or a row_key.")
    if kind != "id" and (out["name_lookup"] or out["name_key"]):
        raise FilterSetValidationError(f"Field {field_id!r}: only an id field may declare a name.")
    values = raw.get("values")
    if values is not None:
        if not isinstance(values, dict):
            raise FilterSetValidationError(f"Field {field_id!r}: values must be an object.")
        source = values.get("source", "none")
        if source not in VALUE_SOURCES:
            raise FilterSetValidationError(f"Field {field_id!r}: unknown value source.")
        if kind == "bool" and source != "none":
            raise FilterSetValidationError(f"Field {field_id!r}: a yes/no field takes no value list.")
        options: list[dict[str, Any]] = []
        if source == "static":
            raw_options = values.get("options")
            if not isinstance(raw_options, list) or not raw_options or len(raw_options) > MAX_STATIC_OPTIONS:
                raise FilterSetValidationError(f"Field {field_id!r}: static options need 1 to {MAX_STATIC_OPTIONS} entries.")
            options = [_clean_option(item) for item in raw_options]
        out["values"] = {"source": source, "options": options}
    return out


def clean_fields(declared: Any) -> list[dict[str, Any]]:
    """Validate a module's field declarations. A bad or repeated one is dropped with a log line; the rest are kept."""
    if declared is None:
        return []
    if not isinstance(declared, (list, tuple)):
        logger.warning("Filter field declarations must be a list; none were used.")
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in list(declared)[:MAX_FIELDS]:
        try:
            field = _clean_field(raw)
        except FilterSetValidationError as exc:
            logger.warning("Filter field declaration dropped: %s", exc)
            continue
        if field["id"] in seen:
            logger.warning("Filter field declaration dropped: %r is declared twice.", field["id"])
            continue
        seen.add(field["id"])
        out.append(field)
    return out


def browser_fields(fields: Any) -> list[dict[str, Any]]:
    """What the browser may see: id, label, kind, operators and value source. Never a lookup, a row key or a name path."""
    out = []
    for field in clean_fields(fields):
        values = {"source": field["values"]["source"]}
        if values["source"] == "static":
            values["options"] = [dict(option) for option in field["values"]["options"]]
        out.append({"id": field["id"], "label": field["label"], "kind": field["kind"],
                    "operators": operators_for(field["kind"], bool(field["name_lookup"] or field["name_key"])), "values": values})
    return out


def _index(fields: Any) -> dict[str, dict[str, Any]]:
    return {field["id"]: field for field in clean_fields(fields)}


# --- validator --------------------------------------------------------------------------------

def _norm_value(field: dict, operator: str, value: Any) -> Any:
    kind = field["kind"]
    if kind == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in ("true", "false"):
            return value.strip().lower() == "true"
        raise FilterSetValidationError(f"{field['label']}: the value must be true or false.")
    if kind == "id" and operator in ID_OPERATORS:
        if isinstance(value, bool):
            raise FilterSetValidationError(f"{field['label']}: the value must be a whole number above zero.")
        if isinstance(value, str) and value.strip().isdigit() and len(value.strip()) <= 19:
            value = int(value.strip())
        if not isinstance(value, int) or value < 1 or value > MAX_ID_VALUE:
            raise FilterSetValidationError(f"{field['label']}: the value must be a whole number above zero.")
        return value
    if isinstance(value, bool) or not isinstance(value, str):
        raise FilterSetValidationError(f"{field['label']}: the value must be text.")
    return _plain_text(value, f"{field['label']}: the value", maximum=MAX_VALUE_LENGTH)


def _norm_rule(item: dict, index: dict, counter: dict) -> dict[str, Any]:
    unknown = sorted(set(item) - {"kind", "field", "operator", "value"})
    if unknown:
        raise FilterSetValidationError("Unknown rule field(s): " + ", ".join(str(k) for k in unknown))
    counter["rules"] += 1
    if counter["rules"] > MAX_RULES:
        raise FilterSetValidationError(f"A filter can hold at most {MAX_RULES} rules.")
    field_id = item.get("field")
    if not isinstance(field_id, str) or field_id not in index:
        shown = field_id if isinstance(field_id, str) and len(field_id) <= 64 and field_id.isprintable() else "?"
        raise FilterSetFieldUnavailable(f"This filter uses a field you cannot use ({shown}).")
    field = index[field_id]
    operator = item.get("operator")
    if not isinstance(operator, str) or operator not in OPERATORS:
        raise FilterSetValidationError(f"{field['label']}: choose one of the listed operators.")
    if operator not in _operator_ids(field):
        raise FilterSetValidationError(f"{field['label']}: '{OPERATORS[operator]}' is not available for this field.")
    return {"kind": "rule", "field": field_id, "operator": operator, "value": _norm_value(field, operator, item.get("value"))}


def _norm_group(match: Any, rules: Any, level: int, index: dict, counter: dict) -> dict[str, Any]:
    if match not in ("all", "any"):
        raise FilterSetValidationError("match must be 'all' or 'any'.")
    if not isinstance(rules, list):
        raise FilterSetValidationError("rules must be a list.")
    out = []
    for item in rules:
        if not isinstance(item, dict):
            raise FilterSetValidationError("Every rule must be an object.")
        kind = item.get("kind") or ("rule" if "field" in item else None)
        if kind == "rule":
            out.append(_norm_rule(item, index, counter))
        elif kind == "group":
            unknown = sorted(set(item) - {"kind", "match", "rules"})
            if unknown:
                raise FilterSetValidationError("Unknown group field(s): " + ", ".join(str(k) for k in unknown))
            if level + 1 > MAX_DEPTH:
                raise FilterSetValidationError(f"Groups can be nested {MAX_DEPTH} deep at most.")
            counter["groups"] += 1
            if counter["groups"] > MAX_GROUPS:
                raise FilterSetValidationError(f"A filter can hold at most {MAX_GROUPS} groups.")
            group = _norm_group(item.get("match", "all"), item.get("rules", []), level + 1, index, counter)
            out.append({"kind": "group", "match": group["match"], "rules": group["rules"]})
        else:
            raise FilterSetValidationError("Every entry must be a rule or a group.")
    return {"match": match, "rules": out}


def validate_filter_set(raw: Any, fields: Any) -> dict[str, Any]:
    """Check a filter against the fields a person may use. Returns ``{version: 1, match, rules}``.

    Refuses (never drops) an unknown field, an operator the field's kind does not offer, a value of the wrong type, a control
    character, more than 50 rules, more than 3 levels of groups and a value over 200 characters. Empty rules match nothing.
    """
    if not isinstance(raw, dict):
        raise FilterSetValidationError("A filter must be a JSON object.")
    unknown = sorted(set(raw) - {"kind", "version", "match", "rules"})
    if unknown:
        raise FilterSetValidationError("Unknown filter field(s): " + ", ".join(str(k) for k in unknown))
    if raw.get("kind", "filter_set") != "filter_set":
        raise FilterSetValidationError("This is not a filter set.")
    if raw.get("version", 1) != 1 or isinstance(raw.get("version", 1), bool):
        raise FilterSetValidationError("version must be 1.")
    body = _norm_group(raw.get("match", "all"), raw.get("rules", []), 0, _index(fields), {"rules": 0, "groups": 0})
    return {"version": 1, "match": body["match"], "rules": body["rules"]}


def rule_count(normalized: dict) -> int:
    total = 0
    for item in normalized.get("rules", []):
        total += rule_count(item) if item.get("kind") == "group" else 1
    return total


# --- evaluators -------------------------------------------------------------------------------

def _q_class():
    from django.db.models import Q

    return Q


def _leaf_q(Q, field: dict, operator: str, value: Any):
    kind = field["kind"]
    if kind == "bool":
        if not field["lookup"]:
            raise FilterSetValidationError(f"Field {field['id']!r} declares no lookup.")
        return Q(**{field["lookup"]: bool(value)})
    if kind == "id" and operator in ID_OPERATORS:
        if not field["lookup"]:
            raise FilterSetValidationError(f"Field {field['id']!r} declares no lookup.")
        q = Q(**{field["lookup"]: value})
    else:
        path = field["name_lookup"] if kind == "id" else field["lookup"]
        if not path:
            raise FilterSetValidationError(f"Field {field['id']!r} declares no lookup for this operator.")
        q = Q(**{f"{path}__{_LOOKUP_SUFFIX[operator]}": value})
    return ~q if operator in _NEGATED else q


def _node_q(Q, group: dict, index: dict):
    rules = group["rules"]
    if not rules:
        return Q(pk__isnull=True)  # empty matches nothing, as Groups does
    parts = []
    for item in rules:
        if item["kind"] == "group":
            parts.append(_node_q(Q, item, index))
        else:
            parts.append(_leaf_q(Q, index[item["field"]], item["operator"], item["value"]))
    expr = parts[0]
    for part in parts[1:]:
        expr = (expr & part) if group["match"] == "all" else (expr | part)
    return expr


def build_q(normalized: Any, fields: Any):
    """A Django ``Q`` for a filter. The filter is validated again, so an unchecked tree can never reach the query.

    Values go to Django as data: iexact, icontains, istartswith and iendswith escape ``%``, ``_`` and ``\\`` in the value, so a typed
    ``%`` matches only a literal ``%``. There is no raw SQL, no regular expression and no field name from the browser.
    ``not_*`` operators negate, so an empty value still matches ``not_equals``, exactly as Groups does.
    """
    tree = validate_filter_set(normalized, fields)
    return _node_q(_q_class(), tree, _index(fields))


def _text(value: Any) -> str:
    return "" if value is None else str(value).casefold()


def _row_rule(field: dict, operator: str, value: Any, row: dict) -> bool:
    kind = field["kind"]
    if kind == "bool":
        if not field["row_key"]:
            raise FilterSetValidationError(f"Field {field['id']!r} declares no row_key.")
        return bool(row.get(field["row_key"])) is bool(value)
    if kind == "id" and operator in ID_OPERATORS:
        if not field["row_key"]:
            raise FilterSetValidationError(f"Field {field['id']!r} declares no row_key.")
        actual = row.get(field["row_key"])
        try:
            actual = None if isinstance(actual, bool) else int(actual)
        except (TypeError, ValueError):
            actual = None
        same = actual == value
        return same if operator == "equals" else not same
    key = field["name_key"] if kind == "id" else field["row_key"]
    if not key:
        raise FilterSetValidationError(f"Field {field['id']!r} declares no row_key for this operator.")
    actual, wanted = _text(row.get(key)), str(value).casefold()
    if operator == "equals":
        return actual == wanted
    if operator == "not_equals":
        return actual != wanted
    if operator == "contains":
        return wanted in actual
    if operator == "not_contains":
        return wanted not in actual
    if operator == "starts_with":
        return actual.startswith(wanted)
    return actual.endswith(wanted)


def _node_matches(group: dict, row: dict, index: dict) -> bool:
    rules = group["rules"]
    if not rules:
        return False
    results = (
        _node_matches(item, row, index) if item["kind"] == "group"
        else _row_rule(index[item["field"]], item["operator"], item["value"], row)
        for item in rules
    )
    return all(results) if group["match"] == "all" else any(results)


def matches(normalized: Any, row: dict, fields: Any) -> bool:
    """In-memory twin of ``build_q`` for lists that are not model-backed. Casefolded compare; ``None`` counts as empty text."""
    if not isinstance(row, dict):
        raise FilterSetValidationError("A row must be a dict.")
    tree = validate_filter_set(normalized, fields)
    return _node_matches(tree, row, _index(fields))


# --- Groups compatibility ---------------------------------------------------------------------

def from_legacy_formula(formula: Any) -> dict[str, Any]:
    """Convert Groups' membership formula into a filter tree with identical results.

    Groups reads ``{version: 1, items: [{kind: condition|group, join: and|or, field, operator, value, items}]}`` strictly left to
    right with no precedence: ``A or B and C`` is ``(A or B) and C``. The tree nests the same way. Values are kept as they are;
    ``validate_filter_set`` checks them against the fields. Groups' own validator and resolver are not used or changed.
    """
    if not isinstance(formula, dict) or not isinstance(formula.get("items", []), list):
        raise FilterSetValidationError("A membership formula must be an object with a list of items.")

    def convert(items: list, depth: int) -> dict[str, Any]:
        if depth > 8:  # Groups allows 6; this only keeps a hostile formula from recursing
            raise FilterSetValidationError("The formula is nested too deeply.")
        acc: Any = None
        acc_match = None  # set only while acc is a group this fold made, so a converted legacy group is never merged into
        for position, item in enumerate(items):
            if not isinstance(item, dict):
                raise FilterSetValidationError("Formula items must be objects.")
            kind = str(item.get("kind", "condition")).strip().lower()
            if kind == "group":
                children = item.get("items", [])
                if not isinstance(children, list):
                    raise FilterSetValidationError("group.items must be a list.")
                inner = convert(children, depth + 1)
                node = {"kind": "group", "match": inner["match"], "rules": inner["rules"]}
            elif kind == "condition":
                node = {"kind": "rule", "field": str(item.get("field", "")).strip().lower(),
                        "operator": str(item.get("operator", "equals")).strip().lower(), "value": item.get("value")}
            else:
                raise FilterSetValidationError("kind must be 'condition' or 'group'.")
            if position == 0:
                acc = node
                continue
            join = str(item.get("join", "and")).strip().lower()
            if join not in ("and", "or"):
                raise FilterSetValidationError("join must be 'and' or 'or'.")
            match = "all" if join == "and" else "any"
            if acc_match == match:
                acc["rules"].append(node)
            else:
                acc = {"kind": "group", "match": match, "rules": [acc, node]}
                acc_match = match
        if acc is None:
            return {"match": "all", "rules": []}
        if acc_match is not None:
            return {"match": acc["match"], "rules": acc["rules"]}
        return {"match": "all", "rules": [acc]}

    body = convert(list(formula.get("items", [])), 1)
    shape = {"rules": 0, "groups": 0, "depth": 0}
    _measure(body, 0, shape)
    if shape["rules"] > MAX_RULES or shape["groups"] > MAX_GROUPS or shape["depth"] > MAX_DEPTH:
        # Left-to-right joins nest once per change of and/or, so a long mixed formula can outgrow a filter set. Refuse it plainly;
        # Groups keeps evaluating it with its own resolver.
        raise FilterSetValidationError(
            f"This formula is too complex for a filter set (at most {MAX_RULES} rules, {MAX_DEPTH} levels of groups)."
        )
    return {"version": 1, "match": body["match"], "rules": body["rules"]}


def _measure(group: dict, level: int, shape: dict) -> None:
    for item in group["rules"]:
        if item["kind"] == "group":
            shape["groups"] += 1
            shape["depth"] = max(shape["depth"], level + 1)
            _measure(item, level + 1, shape)
        else:
            shape["rules"] += 1


# --- stored filter sets -----------------------------------------------------------------------

def _stored_key(view_key: Any) -> str:
    if not isinstance(view_key, str) or not _KEY_RE.fullmatch(view_key):
        raise FilterSetValidationError(
            f"view_key must be a lowercase slug of letters, digits, '-' or '_', up to {MAX_KEY_LENGTH} characters."
        )
    return VIEW_KEY_PREFIX + view_key


def _public_key(stored: str) -> str:
    return stored[len(VIEW_KEY_PREFIX):]


def _is_filter_set(row) -> bool:
    return str(getattr(row, "view_key", "")).startswith(VIEW_KEY_PREFIX)


def _user_id(user) -> Any:
    if not getattr(user, "is_authenticated", False):
        raise FilterSetPermissionDenied("Sign in to use filter sets.")
    return user.pk


def _definition(row) -> dict[str, Any]:
    payload = row.payload if isinstance(row.payload, dict) else {}
    return {"version": 1, "match": payload.get("match", "all"), "rules": payload.get("rules", [])}


def _payload(normalized: dict) -> dict[str, Any]:
    return {"kind": "filter_set", "version": 1, "match": normalized["match"], "rules": normalized["rules"]}


def serialize_filter_set(row, viewer) -> dict[str, Any]:
    readers = list(row.readers or [])
    mine = row.owner_id == viewer.pk
    out = {
        "id": str(row.id), "module_id": row.module_id, "view_key": _public_key(row.view_key), "name": row.name,
        "definition": _definition(row), "shared": not readers, "mine": mine, "can_edit": mine,
        "owner": {"id": row.owner_id, "username": str(getattr(row.owner, "username", "") or "")},
        "created_at": row.created_at, "updated_at": row.updated_at,
    }
    if mine:
        out["readers"] = readers
    return out


def _load(user, set_id: Any):
    """A filter set the person can read, or not found (also for a private set they cannot read)."""
    _user_id(user)
    sv = _saved_views()
    try:
        wanted = uuid.UUID(str(set_id))
    except (ValueError, AttributeError, TypeError):
        raise FilterSetNotFound("Filter set not found.") from None
    row = sv.TecTacSavedView.objects.select_related("owner").filter(pk=wanted).first()
    if row is None or not _is_filter_set(row) or not sv._can_read(user, row):
        raise FilterSetNotFound("Filter set not found.")
    return row


def _audit(user, action: str, row, *, rules: int) -> None:
    """Strict Core audit row: the set's identity and counts, never a rule value and never a reader id."""
    readers = list(row.readers or [])
    try:
        from .audit import record

        record(
            actor=user, module_id="core", action=action, object_type="filter_set", object_id=str(row.id),
            message=f"Tec-Tac filter set {action.replace('custom:', '')}.",
            metadata={
                "module": row.module_id, "view_key": _public_key(row.view_key), "name": row.name, "shared": not readers,
                "rules_count": rules, "readers_count": len(readers),
            },
            strict=True,
        )
    except Exception as exc:
        raise FilterSetAuditError("A filter set change requires a persisted Core audit record.") from exc


def list_filter_sets(user, module_id: Any, view_key: Any) -> list[dict[str, Any]]:
    """The filter sets the person can read for one module and view key."""
    _user_id(user)
    with _saved_view_errors() as sv:
        module = sv._clean_module_id(module_id)
        stored = _stored_key(view_key)
        sv._check_module(user, module)
        rows = sv.TecTacSavedView.objects.select_related("owner").filter(module_id=module, view_key=stored).order_by("name", "id")
    out = []
    for row in rows:
        if sv._can_read(user, row):
            out.append(serialize_filter_set(row, user))
            if len(out) >= MAX_LIST_ROWS:
                break
    return out


def get_filter_set(user, set_id: Any) -> dict[str, Any]:
    row = _load(user, set_id)
    sv = _saved_views()
    try:
        sv._check_module(user, row.module_id, allow_unresolved=row.owner_id == user.pk)
    except sv.SavedViewValidationError:
        raise FilterSetNotFound("Filter set not found.") from None  # module removed or disabled: only the owner still sees it
    return serialize_filter_set(row, user)


def create_filter_set(user, module_id: Any, view_key: Any, name: Any, definition: Any, readers: Any = None, *, fields: Any) -> dict[str, Any]:
    """Save a named filter set. ``fields`` are the module's declarations for this person (a module passes its own)."""
    _user_id(user)
    with _saved_view_errors() as sv:
        module = sv._clean_module_id(module_id)
        stored = _stored_key(view_key)
        clean_name = sv._clean_name(name)
        normalized = validate_filter_set(definition, fields)
        payload = sv._clean_payload(_payload(normalized))
        clean_readers = sv._clean_readers(readers)
        sv._check_module(user, module)
        try:
            with sv._atomic():
                existing = sv.TecTacSavedView.objects.filter(owner_id=user.pk, module_id=module, view_key=stored)
                if any(row.name == clean_name for row in existing):
                    raise FilterSetConflict("You already have a filter set with this name.")
                if existing.count() >= MAX_SETS_PER_KEY:
                    raise FilterSetValidationError(f"You can keep at most {MAX_SETS_PER_KEY} filter sets for one module and view_key.")
                row = sv.TecTacSavedView.objects.create(
                    owner=user, module_id=module, view_key=stored, name=clean_name, payload=payload, readers=clean_readers,
                )
                _audit(user, "add", row, rules=rule_count(normalized))
        except sv._integrity_error() as exc:
            raise FilterSetConflict("You already have a filter set with this name.") from exc
    return serialize_filter_set(row, user)


def update_filter_set(user, set_id: Any, *, module_id: Any = _UNSET, view_key: Any = _UNSET, name: Any = _UNSET,
                      definition: Any = _UNSET, readers: Any = _UNSET, fields: Any = None) -> dict[str, Any]:
    """Change name, definition or readers. Owner only. module_id and view_key never change; repeating them is fine.
    ``fields`` is needed when ``definition`` is given."""
    row = _load(user, set_id)
    with _saved_view_errors() as sv:
        sv._check_module(user, row.module_id)
        if row.owner_id != user.pk:
            raise FilterSetPermissionDenied("Only the owner can change this filter set.")
        if module_id is not _UNSET and sv._clean_module_id(module_id) != row.module_id:
            raise FilterSetValidationError("module_id cannot be changed.")
        if view_key is not _UNSET and view_key != _public_key(row.view_key):
            raise FilterSetValidationError("view_key cannot be changed.")
        changes: dict[str, Any] = {}
        normalized = None
        if name is not _UNSET:
            changes["name"] = sv._clean_name(name)
        if definition is not _UNSET:
            normalized = validate_filter_set(definition, fields)
            changes["payload"] = sv._clean_payload(_payload(normalized))
        if readers is not _UNSET:
            changes["readers"] = sv._clean_readers(readers)
        content_changed = any(
            key in changes and changes[key] != getattr(row, key) for key in ("name", "payload")
        )
        share_changed = "readers" in changes and sorted(changes["readers"]) != sorted(row.readers or [])
        if not content_changed and not share_changed:
            return serialize_filter_set(row, user)
        try:
            with sv._atomic():
                if "name" in changes and sv._name_taken(user, row.module_id, row.view_key, changes["name"], exclude_id=row.id):
                    raise FilterSetConflict("You already have a filter set with this name.")
                for field, value in changes.items():
                    setattr(row, field, value)
                row.save(update_fields=[*changes, "updated_at"])
                rules = rule_count(normalized) if normalized is not None else rule_count(_definition(row))
                if content_changed:
                    _audit(user, "modify", row, rules=rules)
                if share_changed:
                    _audit(user, "custom:filter-set-share", row, rules=rules)
        except sv._integrity_error() as exc:
            raise FilterSetConflict("You already have a filter set with this name.") from exc
    return serialize_filter_set(row, user)


def delete_filter_set(user, set_id: Any) -> None:
    row = _load(user, set_id)
    with _saved_view_errors() as sv:
        if row.owner_id != user.pk:
            raise FilterSetPermissionDenied("Only the owner can delete this filter set.")
        sv._check_module(user, row.module_id, allow_unresolved=True)  # the owner may always clean up a removed module's sets
        with sv._atomic():
            _audit(user, "delete", row, rules=rule_count(_definition(row)))
            row.delete()


def resolve_filter_set(user, module_id: Any, filter_set_id: Any, fields: Any) -> dict[str, Any]:
    """The normalized tree of a stored set, for a module's list to evaluate with ``build_q`` or ``matches``.

    ``fields`` are the module's own declarations for this person. The stored definition is validated again against them: a rule
    on a field the person may no longer use, or one the module no longer declares, refuses with a plain message (fail closed,
    never dropped, never widened). The module's list is already role-scoped, so a filter can only narrow it.
    """
    row = _load(user, filter_set_id)
    with _saved_view_errors() as sv:
        module = sv._clean_module_id(module_id)
        if row.module_id != module:
            raise FilterSetNotFound("Filter set not found.")
        sv._check_module(user, module)
    try:
        return validate_filter_set(_definition(row), fields)
    except FilterSetFieldUnavailable:
        raise FilterSetFieldUnavailable("This filter set uses a field you cannot use.") from None


# --- providers (HTTP routes only) -------------------------------------------------------------

def _provider(module_id: str):
    """The module's own ``<module>.filter_fields`` provider. Private to the routes: Core calls it for the signed-in person only."""
    from .capabilities import CapabilityError, get_capability

    capability_id = f"{module_id}.{PROVIDER_CAPABILITY_SUFFIX}"
    try:
        provider = get_capability(capability_id, version=PROVIDER_VERSION_RANGE, module_id=module_id)
    except CapabilityError:
        raise FilterSetNoProvider("This module offers no filters.") from None
    return provider


def _context(user):
    from .resources import user_context

    return user_context(user)


def person_fields(user, module_id: Any) -> list[dict[str, Any]]:
    """The fields this person may filter on in one module, as the module declares them (internal form, with lookups).

    Used by the HTTP routes only. A module that reuses the evaluators declares its own fields and does not call this."""
    _user_id(user)
    with _saved_view_errors() as sv:
        module = sv._clean_module_id(module_id)
        sv._check_module(user, module)
    provider = _provider(module)
    try:
        declared = provider.describe_fields(context=_context(user))
    except Exception:
        logger.warning("Filter fields of module %r could not be read.", module, exc_info=True)
        raise FilterSetProviderError("The module's filter fields could not be read.") from None
    return clean_fields(declared)


class _TTLCache:
    """Process-local, bounded, locked. No Redis, no database: the lookup is on the request path (the lesson of 1.17.48/1.17.49)."""

    def __init__(self, seconds: float, maximum: int, clock=time.monotonic):
        self._seconds, self._maximum, self._clock = seconds, maximum, clock
        self._lock = threading.Lock()
        self._rows: OrderedDict[Any, tuple[float, Any]] = OrderedDict()

    def get(self, key):
        with self._lock:
            row = self._rows.get(key)
            if row is None:
                return None
            if self._clock() - row[0] >= self._seconds:
                del self._rows[key]
                return None
            return row[1]

    def put(self, key, value) -> None:
        with self._lock:
            self._rows.pop(key, None)
            while len(self._rows) >= self._maximum:
                self._rows.popitem(last=False)  # the oldest first
            self._rows[key] = (self._clock(), value)

    def clear(self) -> None:
        with self._lock:
            self._rows.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._rows)


_VALUES_CACHE = _TTLCache(CACHE_SECONDS, CACHE_MAX_ENTRIES)


def _scope_key(scope: Any) -> str:
    try:
        text = json.dumps(scope, sort_keys=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        text = repr(scope)
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:32]


def _clean_values(raw: Any, page_size: int) -> dict[str, Any]:
    """Cut a provider's answer to what Core allows: str or int values, no repeats, bounded text, at most page_size."""
    if not isinstance(raw, dict):
        raise FilterSetProviderError("The module's answer could not be used.")
    rows = raw.get("values")
    if not isinstance(rows, (list, tuple)):
        raise FilterSetProviderError("The module's answer could not be used.")
    seen: set[tuple[str, Any]] = set()
    values: list[dict[str, Any]] = []
    cut = False
    for item in rows:
        value = item.get("value") if isinstance(item, dict) else item
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        if isinstance(value, str) and (not value.strip() or len(value) > MAX_VALUE_LENGTH or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            continue
        identity = (type(value).__name__, value)
        if identity in seen:
            continue
        seen.add(identity)
        label = item.get("label") if isinstance(item, dict) else None
        label = str(value) if not isinstance(label, str) or not label.strip() else label.strip()
        label = "".join(ch for ch in label if ord(ch) >= 32 and ord(ch) != 127)[:MAX_LABEL_LENGTH] or str(value)
        if len(values) >= page_size:
            cut = True
            break
        values.append({"value": value, "label": label})
    return {"values": values, "has_more": bool(raw.get("has_more")) or cut}


def filter_values(user, module_id: Any, field_id: Any, search: Any = "", page: Any = 1) -> dict[str, Any]:
    """Distinct values for an "Equals" picker. Private to ``GET /api/tfd/filter-values/``: Core publishes no function that calls a
    provider on behalf of another module. The provider filters at the source inside the person's scope (``context.scope``).
    Core adds: module access, only that module's own capability, a field the person was offered, bounded input and output, no
    provider call at all when the scope is none or unreadable, and a short process-local cache keyed by person and scope."""
    _user_id(user)
    with _saved_view_errors() as sv:
        module = sv._clean_module_id(module_id)
        sv._check_module(user, module)
    if not isinstance(field_id, str) or not _FIELD_ID_RE.fullmatch(field_id):
        raise FilterSetNotFound("Field not found.")
    text = "" if search is None else search
    if not isinstance(text, str) or len(text) > MAX_SEARCH_LENGTH or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise FilterSetValidationError(f"search must be plain text of at most {MAX_SEARCH_LENGTH} characters.")
    text = text.strip()
    try:
        number = int(page) if not isinstance(page, bool) else 0
    except (TypeError, ValueError):
        number = 0
    if number < 1 or number > MAX_PAGE:
        raise FilterSetValidationError(f"page must be a whole number from 1 to {MAX_PAGE}.")
    empty = {"values": [], "has_more": False, "page": number, "page_size": PAGE_SIZE}
    context = _context(user)
    try:
        scope = context.scope
        mode = scope.get("mode") if isinstance(scope, dict) else None
    except Exception:
        mode, scope = None, None
    if mode in (None, "none"):
        return empty  # fail closed: the provider is not called for a person with no scope, or one Core cannot read
    provider = _provider(module)
    try:
        declared = clean_fields(provider.describe_fields(context=context))
    except Exception:
        logger.warning("Filter fields of module %r could not be read.", module, exc_info=True)
        raise FilterSetProviderError("The module's filter values could not be read.") from None
    field = next((f for f in declared if f["id"] == field_id), None)
    if field is None or field["values"]["source"] != "distinct":
        raise FilterSetNotFound("Field not found.")
    key = (user.pk, _scope_key(scope), module, field_id, text.casefold(), number)
    cached = _VALUES_CACHE.get(key)
    if cached is not None:
        return {**cached, "values": [dict(v) for v in cached["values"]]}
    try:
        raw = provider.distinct_values(field_id, context=context, search=text, page=number, page_size=PAGE_SIZE)
        answer = _clean_values(raw, PAGE_SIZE)
    except FilterSetProviderError:
        raise
    except Exception:
        logger.warning("Filter values of module %r field %r could not be read.", module, field_id, exc_info=True)
        raise FilterSetProviderError("The module's filter values could not be read.") from None
    answer.update(page=number, page_size=PAGE_SIZE)
    _VALUES_CACHE.put(key, {**answer, "values": [dict(v) for v in answer["values"]]})
    return answer


# --- capability -------------------------------------------------------------------------------

OPERATIONS = (
    "operators_for", "validate_filter_set", "build_q", "matches", "from_legacy_formula", "list_filter_sets", "get_filter_set",
    "create_filter_set", "update_filter_set", "delete_filter_set", "resolve_filter_set",
)


class _FilterSetsProvider:
    operators_for = staticmethod(operators_for)
    validate_filter_set = staticmethod(validate_filter_set)
    build_q = staticmethod(build_q)
    matches = staticmethod(matches)
    from_legacy_formula = staticmethod(from_legacy_formula)
    list_filter_sets = staticmethod(list_filter_sets)
    get_filter_set = staticmethod(get_filter_set)
    create_filter_set = staticmethod(create_filter_set)
    update_filter_set = staticmethod(update_filter_set)
    delete_filter_set = staticmethod(delete_filter_set)
    resolve_filter_set = staticmethod(resolve_filter_set)


_PROVIDER = _FilterSetsProvider()


def filter_sets_contract_metadata() -> dict[str, Any]:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": list(OPERATIONS),
        "operators": dict(OPERATORS),
        "field_kinds": list(KINDS),
        "value_sources": list(VALUE_SOURCES),
        "limits": {
            "rules": MAX_RULES, "groups": MAX_GROUPS, "depth": MAX_DEPTH, "value_length": MAX_VALUE_LENGTH,
            "label_length": MAX_LABEL_LENGTH, "sets_per_owner_module_and_key": MAX_SETS_PER_KEY, "view_key_length": MAX_KEY_LENGTH,
            "search_length": MAX_SEARCH_LENGTH, "page_size": PAGE_SIZE, "pages": MAX_PAGE, "cache_seconds": CACHE_SECONDS,
        },
        "provider_capability": f"<module id>.{PROVIDER_CAPABILITY_SUFFIX} {PROVIDER_CAPABILITY_VERSION}",
        "provider_operations": ["describe_fields(*, context)", "distinct_values(field_id, *, context, search, page, page_size)"],
        "stored_as": f"tec_tac saved views table, view_key prefix {VIEW_KEY_PREFIX!r} (reserved)",
        "audit_actions": ["add", "modify", "custom:filter-set-share", "delete"],
        "requires_framework": ">=1.17.50",
    }


def register_core_filter_sets_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Universal filters: one operator vocabulary, a safe validator, evaluators and saved, shareable filter sets that a module's lists reuse.",
        operations=OPERATIONS,
        metadata=filter_sets_contract_metadata(),
    )

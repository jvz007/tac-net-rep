#!/usr/bin/env python3
"""Core 1.17.50: universal filters, Core half (core.filter_sets 1.0.0).

Runs the real tec_tac.filter_sets, filter_set_views, saved_views, audit, registry, capabilities and contracts tables. Only the
Django/DRF boundary is faked (tests/filter_sets_boundary_1_17_50.py): an in-memory TecTacSavedView model with a transaction that
really rolls back, users, the Tactical AuditLog and a recording Q. Django is not installed on the PC that prepares a release.

Covered: the six operator ids equal Groups'; operators_for by kind; an id field offers the text operators only when it declares a name;
every limit is refused (51st rule, depth 4, 201 characters, control character, bad id, unknown field, operator not allowed for a
yes/no field); build_q for every operator including negation, ANY inside ALL and a % or _ passed as data; matches() truth table
(None, case); from_legacy_formula equals a re-implementation of Groups' left-to-right Q on mixed and/or nested formulas; the browser
descriptor never carries a lookup; stored sets (owner, shared, private, conflict, quota, audit rows with no rule value and no reader
id, share change, rollback, a field the person lost refuses on resolve, key isolation from saved views, saved views unchanged); the
HTTP views; and the contract section (python rows resolve, URLs are in urls.py and HTTP_CONTRACT_DETAILS, the capability registers).
"""
from __future__ import annotations

import ast
import json
import logging
import re
import sys
import uuid
from pathlib import Path

logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import filter_sets_boundary_1_17_50 as boundary  # noqa: E402

ns = boundary.install(real_capabilities=True)
fs = ns.filter_sets
Q = ns.Q
alice, bob, carol, dave, root = ns.alice, ns.bob, ns.carol, ns.dave, ns.root
AUDIT, STORE = ns.AUDIT, ns.STORE


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def refused(call, exc=fs.FilterSetValidationError, text=None):
    try:
        call()
    except exc as error:
        if text is not None:
            must(text.lower() in str(error).lower(), f"{text!r} not in {str(error)!r}")
        return error
    raise AssertionError("expected a refusal")


# --- fields used by the tests --------------------------------------------------------------------
FIELDS = [
    {"id": "hostname", "label": "Hostname", "kind": "text", "lookup": "hostname", "row_key": "hostname"},
    {"id": "operating_system", "label": "Operating system", "kind": "text", "lookup": "operating_system",
     "row_key": "operating_system", "values": {"source": "distinct"}},
    {"id": "client", "label": "Client", "kind": "id", "lookup": "site__client_id", "row_key": "client_id",
     "name_lookup": "site__client__name", "name_key": "client_name", "values": {"source": "distinct"}},
    {"id": "site", "label": "Site", "kind": "id", "lookup": "site_id", "row_key": "site_id"},
    {"id": "needs_reboot", "label": "Needs reboot", "kind": "bool", "lookup": "needs_reboot", "row_key": "needs_reboot"},
    {"id": "type", "label": "Type", "kind": "text", "lookup": "monitoring_type", "row_key": "monitoring_type",
     "values": {"source": "static", "options": [{"value": "server", "label": "Server"}, {"value": "workstation"}]}},
]


def rule(field, operator, value):
    return {"kind": "rule", "field": field, "operator": operator, "value": value}


def group(match, *rules):
    return {"kind": "group", "match": match, "rules": list(rules)}


def flt(match, *rules):
    return {"version": 1, "match": match, "rules": list(rules)}


# === 1. the vocabulary ============================================================================
GROUPS_IDS = ["equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with"]
GROUPS_LABELS = ["Equals", "Does not equal", "Contains", "Does not contain", "Starts with", "Ends with"]
must(list(fs.OPERATORS) == GROUPS_IDS and list(fs.OPERATORS.values()) == GROUPS_LABELS, fs.OPERATORS)
groups_service = ROOT.parent.parent / "modules" / "groups" / "package" / "extensions" / "groups" / "tec_tac_groups" / "service.py"
if groups_service.is_file():  # when the workspace sits beside modules/, read Groups' own table
    tree = ast.parse(groups_service.read_text(encoding="utf-8"))
    node = next((n for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "STRING_OPERATORS" for t in n.targets)), None)
    if node is not None:
        legacy_ops = ast.literal_eval(node.value)
        must(list(legacy_ops) == list(zip(GROUPS_IDS, GROUPS_LABELS)), "Groups' STRING_OPERATORS and Core's vocabulary are the same")
    else:  # 1.17.87: Groups dropped the table from service.py; its evaluator is where the six ids live now
        evaluator = (groups_service.parent / "evaluator.py").read_text(encoding="utf-8")
        must(all(f'"{op}"' in evaluator for op in GROUPS_IDS), "Groups' evaluator still handles Core's six operator ids")

ids = lambda rows: [r["id"] for r in rows]  # noqa: E731
must(ids(fs.operators_for("text")) == GROUPS_IDS, "text gets all six")
must(ids(fs.operators_for("bool")) == ["equals"], "bool gets equals only")
must(ids(fs.operators_for("id")) == ["equals", "not_equals"], "id without a name gets the two ID operators")
must(ids(fs.operators_for("id", True)) == GROUPS_IDS, "id with a name also gets the four text operators")
must(all(r["label"] == fs.OPERATORS[r["id"]] for r in fs.operators_for("text")), "labels")
refused(lambda: fs.operators_for("money"))

# an id field offers the text operators only when it declares a name field
described = {f["id"]: f for f in fs.browser_fields(FIELDS)}
must(ids(described["client"]["operators"]) == GROUPS_IDS, "client declares a name")
must(ids(described["site"]["operators"]) == ["equals", "not_equals"], "site declares no name")
refused(lambda: fs.validate_filter_set(flt("all", rule("site", "contains", "x")), FIELDS), text="not available for this field")
must(fs.validate_filter_set(flt("all", rule("client", "contains", "Acme")), FIELDS)["rules"][0]["value"] == "Acme")
must(fs.validate_filter_set(flt("all", rule("client", "equals", "12")), FIELDS)["rules"][0]["value"] == 12, "an ID is a whole number")

# === 2. field declarations: bad ones dropped, lookups never reach the browser ======================
LOG = []


class _Capture:
    def warning(self, msg, *args, **kwargs):
        LOG.append(msg % args if args else msg)


fs.logger = _Capture()
declared = fs.clean_fields([
    FIELDS[0],
    {"id": "Bad Id", "label": "x", "kind": "text", "lookup": "a"},
    {"id": "nokind", "label": "x", "kind": "money", "lookup": "a"},
    {"id": "nolookup", "label": "x", "kind": "text"},
    {"id": "hostname", "label": "again", "kind": "text", "lookup": "hostname"},
    {"id": "evil", "label": "x", "kind": "text", "lookup": "a; DROP TABLE x"},
    {"id": "suffix", "label": "x", "kind": "text", "lookup": "name__regex__x y"},
    {"id": "badsrc", "label": "x", "kind": "text", "lookup": "a", "values": {"source": "everything"}},
    {"id": "boolpick", "label": "x", "kind": "bool", "lookup": "a", "values": {"source": "distinct"}},
    {"id": "textname", "label": "x", "kind": "text", "lookup": "a", "name_lookup": "b"},
    {"id": "tooMany", "label": "x", "kind": "text", "lookup": "a"},
    {"id": "opts", "label": "x", "kind": "text", "lookup": "a", "values": {"source": "static", "options": [{"value": str(i)} for i in range(51)]}},
    "not a dict",
])
must([f["id"] for f in declared] == ["hostname"], [f["id"] for f in declared])
must(len(LOG) == 12, LOG)
must(fs.clean_fields("nope") == [] and fs.clean_fields(None) == [], "a non-list declares nothing")
sent = json.dumps(fs.browser_fields(FIELDS))
for secret in ("site__client__name", "site__client_id", "site_id", "row_key", "name_key", "lookup", "client_name", "monitoring_type"):
    must(secret not in sent, f"the browser descriptor leaks {secret!r}")
must(set(described["type"]["values"]) == {"source", "options"} and described["type"]["values"]["options"][1] == {"value": "workstation", "label": "workstation"})
must(described["operating_system"]["values"] == {"source": "distinct"}, "distinct sends the source only")
must(set(described["hostname"]) == {"id", "label", "kind", "operators", "values"}, described["hostname"].keys())

# === 3. the validator and its limits ================================================================
ok = fs.validate_filter_set(flt("any", rule("hostname", "equals", "  SRV1  "), group("all", rule("needs_reboot", "equals", "TRUE"))), FIELDS)
must(ok == {"version": 1, "match": "any", "rules": [rule("hostname", "equals", "SRV1"), group("all", rule("needs_reboot", "equals", True))]}, ok)
must(fs.validate_filter_set({"rules": []}, FIELDS) == {"version": 1, "match": "all", "rules": []}, "empty is valid and matches nothing")
refused(lambda: fs.validate_filter_set([], FIELDS))
refused(lambda: fs.validate_filter_set({"match": "all", "rules": [], "extra": 1}, FIELDS), text="unknown filter field")
refused(lambda: fs.validate_filter_set({"version": 2, "rules": []}, FIELDS), text="version")
refused(lambda: fs.validate_filter_set({"match": "most", "rules": []}, FIELDS), text="match")
refused(lambda: fs.validate_filter_set({"rules": "x"}, FIELDS), text="list")
refused(lambda: fs.validate_filter_set(flt("all", "x"), FIELDS), text="object")
refused(lambda: fs.validate_filter_set(flt("all", {"kind": "mystery"}), FIELDS), text="rule or a group")
refused(lambda: fs.validate_filter_set(flt("all", dict(rule("hostname", "equals", "a"), sql="1=1")), FIELDS), text="unknown rule field")
# 50 rules pass, the 51st is refused
fifty = [rule("hostname", "equals", f"h{i}") for i in range(50)]
must(len(fs.validate_filter_set(flt("any", *fifty), FIELDS)["rules"]) == 50)
refused(lambda: fs.validate_filter_set(flt("any", *fifty, rule("hostname", "equals", "x")), FIELDS), text="at most 50 rules")
refused(lambda: fs.validate_filter_set(flt("all", *[group("all") for _ in range(21)]), FIELDS), text="at most 20 groups")
# depth 3 passes, depth 4 is refused
d3 = flt("all", group("all", group("all", group("all", rule("hostname", "equals", "x")))))
must(fs.validate_filter_set(d3, FIELDS)["rules"][0]["rules"][0]["rules"][0]["rules"][0]["field"] == "hostname")
d4 = flt("all", group("all", group("all", group("all", group("all", rule("hostname", "equals", "x"))))))
refused(lambda: fs.validate_filter_set(d4, FIELDS), text="nested 3 deep")
# values
must(len(fs.validate_filter_set(flt("all", rule("hostname", "equals", "x" * 200)), FIELDS)["rules"][0]["value"]) == 200)
refused(lambda: fs.validate_filter_set(flt("all", rule("hostname", "equals", "x" * 201)), FIELDS), text="200 characters")
for bad in ("a\x00b", "a\nb", "a\tb", "a\x7fb"):
    refused(lambda bad=bad: fs.validate_filter_set(flt("all", rule("hostname", "equals", bad)), FIELDS), text="control characters")
refused(lambda: fs.validate_filter_set(flt("all", rule("hostname", "equals", "")), FIELDS), text="required")
refused(lambda: fs.validate_filter_set(flt("all", rule("hostname", "equals", 5)), FIELDS), text="text")
refused(lambda: fs.validate_filter_set(flt("all", rule("hostname", "equals", None)), FIELDS), text="text")
for bad_id in (0, -4, "abc", "1.5", True, 2**63, "9" * 25, None, [3]):
    refused(lambda bad_id=bad_id: fs.validate_filter_set(flt("all", rule("site", "equals", bad_id)), FIELDS), text="whole number above zero")
must(fs.validate_filter_set(flt("all", rule("site", "not_equals", "7")), FIELDS)["rules"][0]["value"] == 7)
for bad_bool in ("yes", 1, 0, None, "maybe"):
    refused(lambda bad_bool=bad_bool: fs.validate_filter_set(flt("all", rule("needs_reboot", "equals", bad_bool)), FIELDS), text="true or false")
# an unknown field, and a field the person may not use, is refused (never dropped)
err = refused(lambda: fs.validate_filter_set(flt("all", rule("secret_field", "equals", "x")), FIELDS), fs.FilterSetFieldUnavailable, "field you cannot use")
must(err.status_code == 422 and err.code == "field_unavailable" and isinstance(err, fs.FilterSetValidationError))
refused(lambda: fs.validate_filter_set(flt("all", rule("hostname", "equals", "x"), rule("../etc", "equals", "x")), FIELDS), fs.FilterSetFieldUnavailable)
refused(lambda: fs.validate_filter_set(flt("all", {"kind": "rule", "operator": "equals", "value": "x"}), FIELDS), fs.FilterSetFieldUnavailable)
refused(lambda: fs.validate_filter_set(flt("all", rule("needs_reboot", "contains", "x")), FIELDS), text="not available for this field")
refused(lambda: fs.validate_filter_set(flt("all", rule("hostname", "matches_regex", "x")), FIELDS), text="listed operators")
refused(lambda: fs.validate_filter_set(flt("all", rule("hostname", ["equals"], "x")), FIELDS), text="listed operators")
refused(lambda: fs.validate_filter_set(flt("all", rule("hostname", "equals", "x")), []), fs.FilterSetFieldUnavailable)

# === 4. build_q ======================================================================================
ROWS = [
    {"hostname": "SRV-01", "operating_system": "Windows Server 2022", "client_id": 1, "client_name": "Acme", "site_id": 10, "needs_reboot": True, "monitoring_type": "server"},
    {"hostname": "srv-02", "operating_system": "Ubuntu 22.04", "client_id": 1, "client_name": "Acme", "site_id": 11, "needs_reboot": False, "monitoring_type": "server"},
    {"hostname": "PC-100%", "operating_system": "Windows 11 Pro", "client_id": 2, "client_name": "Beta_Co", "site_id": 20, "needs_reboot": False, "monitoring_type": "workstation"},
    {"hostname": "PC-1000", "operating_system": "Windows 11 Pro", "client_id": 2, "client_name": "BetaXCo", "site_id": 20, "needs_reboot": True, "monitoring_type": "workstation"},
    {"hostname": "KIOSK", "operating_system": None, "client_id": 3, "client_name": "Gamma", "site_id": 30, "needs_reboot": None, "monitoring_type": "workstation"},
]
for _row in ROWS:  # the recording Q reads a row by the declared lookup path, matches() by the row_key
    _row["site__client_id"], _row["site__client__name"] = _row["client_id"], _row["client_name"]
SUFFIX = {"equals": "iexact", "not_equals": "iexact", "contains": "icontains", "not_contains": "icontains", "starts_with": "istartswith", "ends_with": "iendswith"}
for operator, suffix in SUFFIX.items():
    q = fs.build_q(flt("all", rule("hostname", operator, "srv")), FIELDS)
    if operator.startswith("not_"):
        must(q.kind == "not" and q.parts[0].kwargs == {f"hostname__{suffix}": "srv"}, repr(q))
    else:
        must(q.kind == "leaf" and q.kwargs == {f"hostname__{suffix}": "srv"}, repr(q))
# an id on the ID, and on the display name
must(fs.build_q(flt("all", rule("client", "equals", 5)), FIELDS).kwargs == {"site__client_id": 5})
q = fs.build_q(flt("all", rule("client", "not_equals", 5)), FIELDS)
must(q.kind == "not" and q.parts[0].kwargs == {"site__client_id": 5})
must(fs.build_q(flt("all", rule("client", "contains", "Acm")), FIELDS).kwargs == {"site__client__name__icontains": "Acm"})
must(fs.build_q(flt("all", rule("needs_reboot", "equals", True)), FIELDS).kwargs == {"needs_reboot": True})
must(fs.build_q(flt("all", rule("needs_reboot", "equals", "false")), FIELDS).kwargs == {"needs_reboot": False})
# ANY inside ALL, and the operators on a nested tree
tree = flt("all", rule("operating_system", "contains", "windows"), group("any", rule("hostname", "starts_with", "srv"), rule("client", "equals", 2)))
q = fs.build_q(tree, FIELDS)
must(q.kind == "and" and q.parts[1].kind == "or", repr(q))
must([r["hostname"] for r in ROWS if q.evaluate(r)] == ["SRV-01", "PC-100%", "PC-1000"], [r["hostname"] for r in ROWS if q.evaluate(r)])
# a % or _ is data: the lookup keeps the typed text, Django escapes it
q = fs.build_q(flt("all", rule("hostname", "contains", "100%")), FIELDS)
must(q.kwargs == {"hostname__icontains": "100%"}, "the % reaches Django untouched, as data")
must([r["hostname"] for r in ROWS if q.evaluate(r)] == ["PC-100%"])
q = fs.build_q(flt("all", rule("client", "starts_with", "beta_")), FIELDS)
must(q.kwargs == {"site__client__name__istartswith": "beta_"})
for hostile in ("' OR 1=1 --", "a__regex", "%", "_", "\\", "(?i).*", "x; DROP TABLE y"):
    q = fs.build_q(flt("all", rule("hostname", "contains", hostile)), FIELDS)
    must(q.kwargs == {"hostname__icontains": hostile}, "a hostile value stays a value")
# empty matches nothing; not_* matches an empty (None) value, as Groups does
must(fs.build_q(flt("all"), FIELDS).kwargs == {"pk__isnull": True})
must(fs.build_q(flt("all", group("any")), FIELDS).parts == [] or fs.build_q(flt("all", group("any")), FIELDS).kwargs == {"pk__isnull": True})
q = fs.build_q(flt("all", rule("operating_system", "not_equals", "ubuntu 22.04")), FIELDS)
must([r["hostname"] for r in ROWS if q.evaluate(r)] == ["SRV-01", "PC-100%", "PC-1000", "KIOSK"], "None matches not_equals")
# build_q refuses an unchecked tree, and a field with no lookup
refused(lambda: fs.build_q({"match": "all", "rules": [rule("nope", "equals", "x")]}, FIELDS), fs.FilterSetFieldUnavailable)
refused(lambda: fs.build_q(flt("all", rule("hostname", "equals", "x" * 300)), FIELDS))
refused(lambda: fs.build_q(flt("all", rule("hostname", "equals", "x")), [{"id": "hostname", "label": "H", "kind": "text", "row_key": "hostname"}]), text="no lookup")

# === 5. matches() truth table =========================================================================
M = lambda f, row: fs.matches(f, row, FIELDS)  # noqa: E731
row = ROWS[0]
TABLE = [
    (rule("hostname", "equals", "srv-01"), True), (rule("hostname", "equals", "srv"), False),
    (rule("hostname", "not_equals", "SRV-01"), False), (rule("hostname", "not_equals", "x"), True),
    (rule("hostname", "contains", "RV-0"), True), (rule("hostname", "contains", "zzz"), False),
    (rule("hostname", "not_contains", "RV-0"), False), (rule("hostname", "not_contains", "zzz"), True),
    (rule("hostname", "starts_with", "srv"), True), (rule("hostname", "starts_with", "rv"), False),
    (rule("hostname", "ends_with", "-01"), True), (rule("hostname", "ends_with", "-0"), False),
    (rule("client", "equals", 1), True), (rule("client", "equals", 2), False), (rule("client", "not_equals", 2), True),
    (rule("client", "contains", "cm"), True), (rule("client", "not_contains", "cm"), False), (rule("client", "ends_with", "ME"), True),
    (rule("needs_reboot", "equals", True), True), (rule("needs_reboot", "equals", False), False),
]
for item, expected in TABLE:
    must(M(flt("all", item), row) is expected, (item, expected))
kiosk = ROWS[4]
refused(lambda: M(flt("all", rule("operating_system", "equals", "")), kiosk), text="required")
must(M(flt("all", rule("operating_system", "not_equals", "windows")), kiosk) is True, "None is empty text: not_equals matches")
must(M(flt("all", rule("operating_system", "contains", "win")), kiosk) is False, "None is empty text: contains does not match")
must(M(flt("all", rule("operating_system", "not_contains", "win")), kiosk) is True)
must(M(flt("all", rule("needs_reboot", "equals", False)), kiosk) is True, "None is false")
must(M(flt("all", rule("client", "equals", 3)), {"client_id": "3"}) is True, "a numeric string row value still compares as a number")
must(M(flt("all", rule("client", "equals", 3)), {"client_id": None}) is False and M(flt("all", rule("client", "not_equals", 3)), {}) is True)
must(M(flt("all", rule("client", "equals", 1)), {"client_id": True}) is False, "a bool is not an ID")
# ALL, ANY, nesting, empty
a, b = rule("hostname", "starts_with", "srv"), rule("client", "equals", 9)
must(M(flt("all", a, b), row) is False and M(flt("any", a, b), row) is True)
must(M(flt("all", a, group("any", b, rule("needs_reboot", "equals", True))), row) is True)
must(M(flt("any", b, group("all", a, b)), row) is False)
must(M(flt("all"), row) is False and M(flt("all", a, group("all")), row) is False and M(flt("any", a, group("all")), row) is True)
refused(lambda: M(flt("all", a), "not a dict"))
refused(lambda: fs.matches(flt("all", rule("hostname", "equals", "x")), {}, [{"id": "hostname", "label": "H", "kind": "text", "lookup": "hostname"}]), text="row_key")
# matches and build_q agree on every row for every operator and a nested tree
for operator in GROUPS_IDS:
    for needle in ("srv", "WINDOWS", "100%", "0", "ac"):
        for field in ("hostname", "operating_system", "client"):
            if field == "client" and operator in ("equals", "not_equals"):
                continue
            f = flt("all", rule(field, operator, needle))
            q = fs.build_q(f, FIELDS)
            for r in ROWS:
                if field != "client" or r["client_name"] is not None:
                    must(q.evaluate(r) is M(f, r), (operator, needle, field, r["hostname"]))
for f in (tree, flt("any", rule("client", "equals", 3), group("all", rule("needs_reboot", "equals", True), rule("hostname", "ends_with", "1")))):
    q = fs.build_q(f, FIELDS)
    for r in ROWS:
        must(q.evaluate(r) is M(f, r), (f, r["hostname"]))

# === 6. from_legacy_formula equals Groups' left-to-right Q ===========================================
LEGACY_DEFS = {
    "client": {"lookup": "site__client_id", "kind": "int"}, "site": {"lookup": "site_id", "kind": "int"},
    "hostname": {"lookup": "hostname", "kind": "str"}, "operating_system": {"lookup": "operating_system", "kind": "str"},
    "agent_type": {"lookup": "monitoring_type", "kind": "str"},
}


def legacy_condition_q(item):  # the body of Groups' _condition_q, on the recording Q
    field, operator, value = item["field"], item["operator"], item["value"]
    lookup = LEGACY_DEFS[field]["lookup"]
    if LEGACY_DEFS[field]["kind"] == "int":
        q = Q(**{lookup: value})
    else:
        suffix = {"equals": "iexact", "not_equals": "iexact", "contains": "icontains", "not_contains": "icontains",
                  "starts_with": "istartswith", "ends_with": "iendswith"}[operator]
        q = Q(**{f"{lookup}__{suffix}": value})
    return ~q if operator in {"not_equals", "not_contains"} else q


def legacy_node_q(node):  # Groups' _node_q
    if node["kind"] == "condition":
        return legacy_condition_q(node)
    items = node.get("items", [])
    if not items:
        return Q(pk__isnull=True)
    expr = legacy_node_q(items[0])
    for item in items[1:]:
        child = legacy_node_q(item)
        expr = (expr | child) if item.get("join") == "or" else (expr & child)
    return expr


def cond(field, operator, value, join="and"):
    return {"kind": "condition", "join": join, "field": field, "operator": operator, "value": value}


def lgroup(join, *items):
    return {"kind": "group", "join": join, "items": list(items)}


LEGACY_FORMULAS = {
    "single": [cond("hostname", "contains", "srv")],
    "and chain": [cond("hostname", "contains", "pc"), cond("client", "equals", 2, "and"), cond("operating_system", "not_equals", "x", "and")],
    "or chain": [cond("hostname", "starts_with", "srv"), cond("hostname", "starts_with", "kiosk", "or"), cond("client", "equals", 2, "or")],
    "mixed, no precedence": [cond("hostname", "starts_with", "srv"), cond("client", "equals", 2, "or"), cond("operating_system", "contains", "11", "and")],
    "mixed 2": [cond("client", "equals", 1), cond("operating_system", "contains", "ubuntu", "and"), cond("hostname", "equals", "kiosk", "or"),
                cond("site", "equals", 30, "and")],
    "nested": [cond("operating_system", "contains", "windows"),
               lgroup("and", cond("hostname", "starts_with", "srv"), cond("client", "equals", 2, "or"), cond("agent_type", "equals", "workstation", "and")),
               cond("site", "not_equals", 20, "or")],
    "group first": [lgroup("and", cond("client", "equals", 1), cond("client", "equals", 3, "or")), cond("hostname", "ends_with", "1", "and")],
    "empty group in and": [cond("client", "equals", 1), lgroup("and")],
    "empty group in or": [cond("client", "equals", 1), lgroup("or")],
    "empty": [],
    "negations": [cond("hostname", "not_contains", "srv"), cond("operating_system", "not_equals", "ubuntu 22.04", "and")],
}
LEGACY_FIELDS = [
    {"id": "client", "label": "Client", "kind": "id", "lookup": "site__client_id", "row_key": "client_id"},
    {"id": "site", "label": "Site", "kind": "id", "lookup": "site_id", "row_key": "site_id"},
    {"id": "hostname", "label": "Hostname", "kind": "text", "lookup": "hostname", "row_key": "hostname"},
    {"id": "operating_system", "label": "OS", "kind": "text", "lookup": "operating_system", "row_key": "operating_system"},
    {"id": "agent_type", "label": "Type", "kind": "text", "lookup": "monitoring_type", "row_key": "monitoring_type"},
]
for name, items in LEGACY_FORMULAS.items():
    legacy = {"version": 1, "items": items}
    converted = fs.from_legacy_formula(legacy)
    valid = fs.validate_filter_set(converted, LEGACY_FIELDS)
    expected = legacy_node_q({"kind": "group", "join": "and", "items": items})
    q = fs.build_q(valid, LEGACY_FIELDS)
    for r in ROWS:
        must(expected.evaluate(r) is q.evaluate(r), (name, r["hostname"], repr(expected), repr(q)))
        must(fs.matches(valid, r, LEGACY_FIELDS) is expected.evaluate(r), (name, "matches", r["hostname"]))
# the shape of the tree: A or B and C is (A or B) and C
shape = fs.from_legacy_formula({"items": LEGACY_FORMULAS["mixed, no precedence"]})
must(shape["match"] == "all" and shape["rules"][0]["kind"] == "group" and shape["rules"][0]["match"] == "any" and len(shape["rules"][0]["rules"]) == 2, shape)
chain = fs.from_legacy_formula({"items": LEGACY_FORMULAS["and chain"]})
must(chain["match"] == "all" and len(chain["rules"]) == 3 and all(r["kind"] == "rule" for r in chain["rules"]), "an and chain stays flat")
must(fs.from_legacy_formula({"items": []}) == {"version": 1, "match": "all", "rules": []})
must(fs.from_legacy_formula({}) == {"version": 1, "match": "all", "rules": []})
refused(lambda: fs.from_legacy_formula("x"))
refused(lambda: fs.from_legacy_formula({"items": [{"kind": "wat"}]}))
refused(lambda: fs.from_legacy_formula({"items": [cond("a", "equals", "b"), dict(cond("a", "equals", "b"), join="xor")]}))
alternating = [cond("hostname", "equals", "a")] + [cond("hostname", "equals", f"h{i}", "or" if i % 2 else "and") for i in range(8)]
refused(lambda: fs.from_legacy_formula({"items": alternating}), text="too complex")
deep = {"items": []}
cursor = deep
for _ in range(12):
    inner = {"kind": "group", "join": "and", "items": []}
    cursor["items"].append(inner)
    cursor = inner
refused(lambda: fs.from_legacy_formula(deep), text="too deeply")
# Groups itself is not touched: no import of filter_sets from the module
if groups_service.is_file():
    print("       Groups uses filter_sets:", "filter_sets" in groups_service.read_text(encoding="utf-8"), "(adoption, not a failure; 1.17.87)")

# === 7. stored filter sets ============================================================================
GRANTS = ns.GRANTS


class Provider:
    """The module's own filter_fields provider: all fields, no values."""

    calls = []

    def describe_fields(self, *, context):
        self.calls.append(("describe", context.user.pk))
        hidden = getattr(self, "hidden", {}).get(context.user.pk, ())
        return [f for f in FIELDS if f["id"] not in hidden]

    def distinct_values(self, field_id, *, context, search, page, page_size):
        raise AssertionError("not used here")


PROVIDER = Provider()
ns.capabilities._core_module_may_register = lambda owner, capability_id: True
ns.capabilities.register_capability(id="demo-open.filter_fields", module_id="demo-open", version="1.0.0", provider=PROVIDER,
                                    operations=("describe_fields", "distinct_values"))


def post(user, name="Mine", *, module="demo-open", key="endpoints", definition=None, readers=None, expect=201):
    body = {"module_id": module, "view_key": key, "name": name,
            "definition": flt("all", rule("hostname", "contains", "SECRET-VALUE")) if definition is None else definition}
    if readers is not None:
        body["readers"] = readers
    response = ns.views.FilterSetListCreateView().post(ns.Request(user, body))
    must(response.status_code == expect, (name, response.status_code, response.data))
    return response.data


def listing(user, module="demo-open", key="endpoints"):
    query = {"module": module}
    if key is not None:
        query["view_key"] = key
    return ns.views.FilterSetListCreateView().get(ns.Request(user, query=query))


def detail(method, user, set_id, data=None):
    return getattr(ns.views.FilterSetDetailView(), method)(ns.Request(user, data), uuid.UUID(str(set_id)))


ns.reset()
created = post(alice, "Night shift")
must(set(created) >= {"id", "module_id", "view_key", "name", "definition", "shared", "mine", "can_edit", "owner", "readers", "created_at", "updated_at"}, created.keys())
must(created["shared"] is True and created["mine"] is True and created["can_edit"] is True and created["readers"] == [])
must(created["view_key"] == "endpoints" and created["module_id"] == "demo-open", "the public key has no prefix")
must(created["definition"] == {"version": 1, "match": "all", "rules": [rule("hostname", "contains", "SECRET-VALUE")]}, created["definition"])
stored_row = next(iter(STORE.values()))
must(stored_row.view_key == "fs-endpoints" and stored_row.payload["kind"] == "filter_set" and stored_row.owner_id == 1, "stored under the reserved key")
must(len(AUDIT) == 1, AUDIT)


def audit_actions():
    return [(r["action"], r["object_type"]) for r in AUDIT]


must(audit_actions() == [("add", "filter_set")], audit_actions())
row0 = AUDIT[0]
must(row0["debug_info"]["object_id"] == created["id"] and row0["debug_info"]["module_id"] == "core", row0)
dump = json.dumps(AUDIT, default=str)
must("SECRET-VALUE" not in dump, "no rule value in the audit row")

# a name is trimmed; a second set; a conflict is 409
must(post(alice, "  Trimmed  ")["name"] == "Trimmed")
post(alice, "Night shift", expect=409)
post(bob, "Night shift")  # another owner may reuse the name
# shared: readable by others, readers hidden, not editable
shared_row = listing(bob).data["filter_sets"]
must(len(shared_row) == 3 and {r["name"] for r in shared_row} == {"Night shift", "Trimmed"}, shared_row)
alice_set = next(r for r in shared_row if r["owner"]["id"] == 1 and r["name"] == "Night shift")
must(alice_set["shared"] is True and alice_set["mine"] is False and alice_set["can_edit"] is False and "readers" not in alice_set)
must(detail("get", carol, alice_set["id"]).status_code == 200)
must(detail("put", bob, alice_set["id"], {"name": "Mine now"}).status_code == 403, "a reader cannot edit")
must(detail("delete", bob, alice_set["id"]).status_code == 403, "a reader cannot delete")
must(detail("put", root, alice_set["id"], {"name": "Admin edit"}).status_code == 403, "no administrator override")
before = len(AUDIT)
# a set private to the owner and one more person
ns.reset()
private = post(alice, "Private", readers=[2, 1])
must(private["shared"] is False and private["readers"] == [1, 2])
must(listing(carol).data["count"] == 0, "not listed")
must(detail("get", carol, private["id"]).status_code == 404 and detail("put", carol, private["id"], {"name": "X"}).status_code == 404, "no leak")
must(detail("delete", carol, private["id"]).status_code == 404)
must(detail("get", bob, private["id"]).status_code == 200 and detail("put", bob, private["id"], {"name": "X"}).status_code == 403)
must("readers" not in detail("get", bob, private["id"]).data)
post(alice, "Bad reader", readers=[99], expect=400)
post(alice, "Inactive reader", readers=[4], expect=400)

# update: name, definition, readers; audit rows per action
ns.reset()
made = post(alice, "Servers")
del AUDIT[:]
response = detail("put", alice, made["id"], {"name": "All servers"})
must(response.status_code == 200 and response.data["name"] == "All servers")
must(audit_actions() == [("modify", "filter_set")], audit_actions())
response = detail("put", alice, made["id"], {"definition": flt("any", rule("hostname", "starts_with", "srv"), rule("client", "equals", 4), rule("needs_reboot", "equals", True))})
must(response.status_code == 200 and len(response.data["definition"]["rules"]) == 3, response.data)
must(audit_actions() == [("modify", "filter_set")] * 2, audit_actions())
must(AUDIT[-1]["debug_info"]["metadata"]["rules_count"] == 3, AUDIT[-1]["debug_info"]["metadata"])
del AUDIT[:]
response = detail("put", alice, made["id"], {"readers": [3, 2]})
must(response.status_code == 200 and response.data["shared"] is False and response.data["readers"] == [2, 3])
must(audit_actions() == [("custom:filter-set-share", "filter_set")], audit_actions())
meta = AUDIT[-1]["debug_info"]["metadata"]
must(meta["shared"] is False and meta["readers_count"] == 2 and meta["rules_count"] == 3 and set(meta) == {"module", "view_key", "name", "shared", "rules_count", "readers_count"}, meta)
del AUDIT[:]
response = detail("put", alice, made["id"], {"name": "Renamed", "readers": []})
must(audit_actions() == [("modify", "filter_set"), ("custom:filter-set-share", "filter_set")], audit_actions())
del AUDIT[:]
response = detail("put", alice, made["id"], {"name": "Renamed", "readers": []})
must(response.status_code == 200 and AUDIT == [], "nothing changed: no row")
must(detail("put", alice, made["id"], {"module_id": "demo-open", "view_key": "endpoints"}).status_code == 200)
must(detail("put", alice, made["id"], {"module_id": "demo-locked"}).status_code == 400 and detail("put", alice, made["id"], {"view_key": "other"}).status_code == 400)
must(detail("put", alice, made["id"], {"bogus": 1}).status_code == 400, "unknown body fields are refused")
must(detail("put", alice, made["id"], {"definition": flt("all", rule("hostname", "equals", "x" * 300))}).status_code == 400)
post(alice, "Other")
must(detail("put", alice, made["id"], {"name": "Other"}).status_code == 409, "a rename onto an existing name conflicts")
del AUDIT[:]
must(detail("delete", alice, made["id"]).status_code == 204 and made["id"] not in STORE)
must(audit_actions() == [("delete", "filter_set")], audit_actions())
must(detail("get", alice, made["id"]).status_code == 404)

# no rule value and no reader id in any audit row
ns.reset()
x = post(alice, "Audited", definition=flt("all", rule("hostname", "equals", "TOP-SECRET-NAME"), rule("client", "equals", 4242)), readers=[2, 3])
detail("put", alice, x["id"], {"definition": flt("all", rule("hostname", "equals", "OTHER-SECRET")), "readers": [3]})
detail("delete", alice, x["id"])
dump = json.dumps(AUDIT, default=str)
for secret in ("TOP-SECRET-NAME", "4242", "OTHER-SECRET", "readers\":", "'readers'"):
    must(secret not in dump, f"{secret!r} in an audit row")
for audit_row in AUDIT:
    must("readers" not in audit_row["debug_info"]["metadata"] and "definition" not in audit_row["debug_info"]["metadata"], audit_row)

# quota: 100 per owner, module and key
ns.reset()
for i in range(100):
    post(alice, f"Set {i}", definition=flt("all", rule("hostname", "equals", f"h{i}")))
post(alice, "One too many", expect=400)
post(alice, "Other key is fine", key="other")
post(bob, "Another owner is fine")
must(len(STORE) == 102)

# audit failure rolls back
ns.reset()
ns.FakeAuditLog.objects.fail = True
post(alice, "Will fail", expect=500)
must(len(STORE) == 0, "an audit failure rolls the create back")
ns.FakeAuditLog.objects.fail = False
kept = post(alice, "Kept")
ns.FakeAuditLog.objects.fail = True
must(detail("put", alice, kept["id"], {"name": "Changed"}).status_code == 500)
must(next(iter(STORE.values())).name == "Kept", "rolled back")
must(detail("put", alice, kept["id"], {"readers": [2]}).status_code == 500 and next(iter(STORE.values())).readers == [])
must(detail("delete", alice, kept["id"]).status_code == 500 and len(STORE) == 1, "a failed delete audit keeps the set")
ns.FakeAuditLog.objects.fail = False

# module access: locked and disabled and unknown modules, core, legacy
ns.reset()
post(alice, "x", module="demo-locked", expect=403)
post(alice, "x", module="demo-disabled", expect=400)
post(alice, "x", module="demo-legacy", expect=400)
post(alice, "x", module="demo-unknown", expect=400)
post(alice, "x", module="core", expect=404)  # core offers no filter provider
post(alice, "x", module="demo-open", key="Bad Key", expect=400)
post(alice, "x", module="demo-open", key="k" * 62, expect=400)
post(alice, "x", module="demo-open", key="k" * 61, expect=201)
post(alice, "", expect=400)
must(listing(alice, module="demo-locked").status_code == 403 and listing(alice, key=None).status_code == 400, "list needs the module and a key")
must(ns.views.FilterSetListCreateView().post(ns.Request(alice, ["not", "a", "dict"])).status_code == 400)
must(ns.views.FilterSetListCreateView().post(ns.Request(alice, {"module_id": "demo-open", "view_key": "k", "name": "n", "definition": flt("all"), "fields": []})).status_code == 400, "fields is not a body field")
refused(lambda: fs.get_filter_set(alice, "not-a-uuid"), fs.FilterSetNotFound)
anonymous = type("Anonymous", (), {"is_authenticated": False, "pk": None})()
must(ns.views.FilterSetListCreateView().get(ns.Request(anonymous, query={"module": "demo-open", "view_key": "k"})).status_code == 403)
GRANTS[bob.pk] = {"demo-locked.use"}
ns.reset()
GRANTS[bob.pk] = {"demo-locked.use"}
post(bob, "Allowed", module="demo-locked", expect=404)  # may use the module, which offers no provider

# a module that offers no filters: the fields route says so
response = ns.views.FilterSetFieldsView().get(ns.Request(alice, query={"module": "demo-locked"}))
must(response.status_code == 403)
GRANTS[alice.pk] = {"demo-locked.use"}
response = ns.views.FilterSetFieldsView().get(ns.Request(alice, query={"module": "demo-locked"}))
must(response.status_code == 200 and response.data["available"] is False and response.data["fields"] == [], response.data)

# the fields route
response = ns.views.FilterSetFieldsView().get(ns.Request(alice, query={"module": "demo-open"}))
must(response.status_code == 200 and response.data["available"] is True and [f["id"] for f in response.data["fields"]] == [f["id"] for f in FIELDS])
must([o["id"] for o in response.data["operators"]] == GROUPS_IDS and response.data["limits"]["rules"] == 50 and response.data["limits"]["depth"] == 3)
sent = json.dumps(response.data)
for secret in ("site__client__name", "site__client_id", "row_key", "name_key", "lookup", "client_name"):
    must(secret not in sent, f"the fields route leaks {secret!r}")
must(ns.views.FilterSetFieldsView().get(ns.Request(alice, query={})).status_code == 400)

# a person who may not use a field cannot save a set on it (422), and a set whose field is gone refuses on resolve
ns.reset()
PROVIDER.hidden = {2: ("needs_reboot", "client")}
must(post(bob, "On a hidden field", definition=flt("all", rule("needs_reboot", "equals", True)), expect=422).get("code") == "field_unavailable")
as_alice = post(alice, "Uses client", definition=flt("all", rule("client", "equals", 7), rule("hostname", "contains", "srv")))
visible = [f for f in FIELDS if f["id"] not in ("needs_reboot", "client")]
resolved = fs.resolve_filter_set(alice, "demo-open", as_alice["id"], FIELDS)
must(resolved["rules"][0] == rule("client", "equals", 7), resolved)
err = refused(lambda: fs.resolve_filter_set(bob, "demo-open", as_alice["id"], visible), fs.FilterSetFieldUnavailable)
must(str(err) == "This filter set uses a field you cannot use." and err.status_code == 422, str(err))
refused(lambda: fs.resolve_filter_set(alice, "demo-open", as_alice["id"], []), fs.FilterSetFieldUnavailable)
must(fs.resolve_filter_set(bob, "demo-open", as_alice["id"], FIELDS)["rules"][1]["value"] == "srv", "with the field, the same set resolves")
refused(lambda: fs.resolve_filter_set(alice, "demo-locked", as_alice["id"], FIELDS), fs.FilterSetNotFound)
refused(lambda: fs.resolve_filter_set(carol, "demo-open", str(uuid.uuid4()), FIELDS), fs.FilterSetNotFound)
refused(lambda: fs.resolve_filter_set(carol, "demo-open", "nope", FIELDS), fs.FilterSetNotFound)
# an owner editing a set on a field they lost: refused (422), never silently dropped
must(detail("put", bob, as_alice["id"], {"definition": flt("all", rule("hostname", "equals", "x"))}).status_code == 403)
mine = post(bob, "Bob's", definition=flt("all", rule("hostname", "equals", "x")))
must(detail("put", bob, mine["id"], {"definition": flt("all", rule("client", "equals", 1))}).status_code == 422)
PROVIDER.hidden = {}
# a stored payload tampered with directly (outside Core) fails closed on resolve
row_obj = STORE[as_alice["id"]]
row_obj.payload = {"kind": "filter_set", "version": 1, "match": "all", "rules": [rule("hostname", "regex", "x")]}
refused(lambda: fs.resolve_filter_set(alice, "demo-open", as_alice["id"], FIELDS))
row_obj.payload = {"kind": "filter_set", "version": 1, "match": "all", "rules": [rule("hostname", "contains", "x"), {"kind": "rule", "field": "evil__field", "operator": "equals", "value": "x"}]}
refused(lambda: fs.resolve_filter_set(alice, "demo-open", as_alice["id"], FIELDS), fs.FilterSetFieldUnavailable)

# provider failures on the routes: no provider text, status 502
ns.reset()


class Boom(Provider):
    def describe_fields(self, *, context):
        raise RuntimeError("secret provider detail /srv/x.py line 3")


real_provider = PROVIDER
ns.capabilities._CAPABILITIES["demo-open.filter_fields"] = ns.capabilities.CapabilityRegistration(
    id="demo-open.filter_fields", module_id="demo-open", version="1.0.0", provider=Boom(), operations=("describe_fields",))
response = ns.views.FilterSetListCreateView().post(ns.Request(alice, {"module_id": "demo-open", "view_key": "k", "name": "n", "definition": flt("all")}))
must(response.status_code == 502 and "secret provider" not in json.dumps(response.data) and len(STORE) == 0, response.data)
must(ns.views.FilterSetFieldsView().get(ns.Request(alice, query={"module": "demo-open"})).status_code == 502)
ns.capabilities._CAPABILITIES["demo-open.filter_fields"] = ns.capabilities.CapabilityRegistration(
    id="demo-open.filter_fields", module_id="demo-open", version="1.0.0", provider=real_provider, operations=("describe_fields",))

# a provider with a wrong major version is not used
ns.capabilities._CAPABILITIES["demo-open.filter_fields"] = ns.capabilities.CapabilityRegistration(
    id="demo-open.filter_fields", module_id="demo-open", version="2.0.0", provider=real_provider, operations=("describe_fields",))
post(alice, "x", expect=404)
ns.capabilities._CAPABILITIES["demo-open.filter_fields"] = ns.capabilities.CapabilityRegistration(
    id="demo-open.filter_fields", module_id="demo-open", version="1.3.0", provider=real_provider, operations=("describe_fields",))
post(alice, "minor ok")

# === 8. keys are isolated from saved views, and saved views are unchanged ===========================
ns.reset()
sv = ns.saved_views
made = post(alice, "Filter set under endpoints", key="endpoints")
must(sv.list_views(alice, "demo-open", "endpoints") == [], "a set saved under 'endpoints' is invisible to saved_views.list_views")
must(sv.list_views(alice, "demo-open") == [], "and to a list with no key")
refused(lambda: sv.get_view(alice, made["id"]), sv.SavedViewNotFound)
refused(lambda: sv.update_view(alice, made["id"], name="hijack"), sv.SavedViewNotFound)
refused(lambda: sv.delete_view(alice, made["id"]), sv.SavedViewNotFound)
refused(lambda: sv.create_view(alice, "demo-open", "fs-endpoints", "sneaky", {"a": 1}), sv.SavedViewValidationError, "reserved")
refused(lambda: sv.list_views(alice, "demo-open", "fs-endpoints"), sv.SavedViewValidationError, "reserved")
must(fs.get_filter_set(alice, made["id"])["name"] == "Filter set under endpoints", "still reachable through its own contract")
# the saved views HTTP routes answer the same
saved = ns.saved_view_views.SavedViewDetailView()
must(saved.get(ns.Request(alice), uuid.UUID(made["id"])).status_code == 404 and saved.delete(ns.Request(alice), uuid.UUID(made["id"])).status_code == 404)
# a saved view under the same key, and 'fsx' (not the prefix) behave as before
view = sv.create_view(alice, "demo-open", "endpoints", "My view", {"filter": "x"})
must([v["name"] for v in sv.list_views(alice, "demo-open", "endpoints")] == ["My view"])
must([v["name"] for v in sv.list_views(alice, "demo-open")] == ["My view"])
must(sv.create_view(alice, "demo-open", "fsx", "ok", {"a": 1})["view_key"] == "fsx" and sv.create_view(alice, "demo-open", "f-s", "ok", {})["view_key"] == "f-s")
must(fs.list_filter_sets(alice, "demo-open", "endpoints")[0]["name"] == "Filter set under endpoints" and len(fs.list_filter_sets(alice, "demo-open", "endpoints")) == 1)
refused(lambda: fs.get_filter_set(alice, view["id"]), fs.FilterSetNotFound)  # a plain saved view is not a filter set
refused(lambda: fs.update_filter_set(alice, view["id"], name="x"), fs.FilterSetNotFound)
refused(lambda: fs.delete_filter_set(alice, view["id"]), fs.FilterSetNotFound)
must(view["id"] in STORE, "a saved view is untouched")
# deleting the owner's module: the owner may still clean up, others cannot read
ns.PLUGINS.remove(ns.OPEN)
must(detail("get", bob, made["id"]).status_code == 404, "module removed: only the owner still sees it")
must(detail("get", alice, made["id"]).status_code == 200 and detail("delete", alice, made["id"]).status_code == 204)
ns.PLUGINS.insert(0, ns.OPEN)

# python contract surface
must(set(fs.OPERATIONS) == {"operators_for", "validate_filter_set", "build_q", "matches", "from_legacy_formula", "list_filter_sets",
                            "get_filter_set", "create_filter_set", "update_filter_set", "delete_filter_set", "resolve_filter_set"})
must(all(callable(getattr(fs._PROVIDER, name)) for name in fs.OPERATIONS), "the provider object has every operation")
must(not any(name in fs.OPERATIONS for name in ("filter_values", "person_fields")), "no function that calls a provider is published")
refused(lambda: fs.create_filter_set(anonymous, "demo-open", "k", "n", flt("all"), fields=FIELDS), fs.FilterSetPermissionDenied)

# === 9. the contract section ==================================================================================
SRC = ROOT / "framwork" / "tec_tac"
contracts_tree = ast.parse((SRC / "contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in contracts_tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == name for t in (n.targets if isinstance(n, ast.Assign) else [n.target])))
    return ast.literal_eval(node.value)


CORE = literal("CORE_CONTRACTS")
DETAILS = literal("HTTP_CONTRACT_DETAILS")
RULES = literal("RULES")
rows = [r for r in CORE if r.get("area") == "filter-sets"]
must([r["name"] for r in rows] == [*fs.OPERATIONS[:0], "operators_for", "validate_filter_set", "build_q", "matches", "from_legacy_formula",
                                  "list_filter_sets", "get_filter_set", "create_filter_set", "update_filter_set", "delete_filter_set",
                                  "resolve_filter_set", "PROVIDER_CAPABILITY_SUFFIX"], [r["name"] for r in rows])
for r in rows:
    must(r["import_path"] == "tec_tac.filter_sets" and r["kind"] == "python" and r["purpose"].strip() and r["audience"], r)
    must(hasattr(fs, r["name"]), f"{r['name']} resolves")
provider_row = rows[-1]
for needle in ("<module id>.filter_fields", "describe_fields(*, context)", "distinct_values(field_id, *, context, search, page, page_size)",
               "context.scope", "page_size + 1", "framework >=1.17.50", "publishes no Python function that calls a provider"):
    must(needle in provider_row["purpose"], f"the provider row names {needle!r}")
must(fs.PROVIDER_CAPABILITY_SUFFIX == "filter_fields")
text_of = " ".join(r["purpose"] for r in rows)
for needle in ("equals, not_equals, contains, not_contains, starts_with, ends_with", "50 rules", "3 deep", "FilterSetFieldUnavailable", "custom:filter-set-share",
               "left to right", "no raw SQL", "Core calls no provider"):
    must(needle in text_of, f"the python rows name {needle!r}")

urls_src = (SRC / "urls.py").read_text(encoding="utf-8")
ROUTES = {
    "/api/tfd/filter-sets/": 'path("filter-sets/",',
    "/api/tfd/filter-sets/<uuid:set_id>/": 'path("filter-sets/<uuid:set_id>/",',
    "/api/tfd/filter-sets/fields/": 'path("filter-sets/fields/",',
    "/api/tfd/filter-values/": 'path("filter-values/",',
}
for route, needle in ROUTES.items():
    must(needle in urls_src, f"{route} is in urls.py")
    must(route in DETAILS, f"{route} is in HTTP_CONTRACT_DETAILS")
must(set(DETAILS["/api/tfd/filter-sets/"]) == {"GET", "POST"} and set(DETAILS["/api/tfd/filter-sets/<uuid:set_id>/"]) == {"GET", "PUT", "DELETE"})
must(set(DETAILS["/api/tfd/filter-sets/fields/"]) == {"GET"} and set(DETAILS["/api/tfd/filter-values/"]) == {"GET"})
values_contract = json.dumps(DETAILS["/api/tfd/filter-values/"])
for status in ('"400"', '"403"', '"404"', '"429"', '"502"'):
    must(status in values_contract, f"filter-values documents {status}")
for needle in ("context.scope", "scope mode is none", "without calling the provider", "30 seconds", "256 entries", "no fallback", "240/min", "25"):
    must(needle in values_contract, f"filter-values names {needle!r}")
sets_contract = json.dumps(DETAILS["/api/tfd/filter-sets/"]) + json.dumps(DETAILS["/api/tfd/filter-sets/<uuid:set_id>/"])
for status in ('"201"', '"204"', '"400"', '"403"', '"404"', '"409"', '"422"', '"429"', '"500"', '"502"'):
    must(status in sets_contract, f"filter-sets documents {status}")
for needle in ("never a rule value or a reader id", "custom:filter-set-share", "60/min and 2000/day", "owner only", "withheld: true"):  # 1.17.51: the visible-to-everyone sentence became the withholding rule
    must(needle in sets_contract, f"filter-sets names {needle!r}")
must(any("Filter sets and value pickers belong to Core's filter-sets service" in r and "never takes field names, lookups, SQL or regular expressions" in r for r in RULES), "the RULES line")
saved_post = DETAILS["/api/tfd/saved-views/"]["POST"]["request"]["view_key"]
must("fs-" in saved_post and "reserved" in saved_post, saved_post)

# the capability registers with the listed operations and version
registration = fs.register_core_filter_sets_capability()
must(registration.id == "core.filter_sets" and registration.version == "1.1.0" and registration.module_id == "core", registration)
must(list(registration.operations) == list(fs.OPERATIONS))
meta = registration.metadata
must(meta["requires_framework"] == ">=1.17.50" and meta["operators"] == fs.OPERATORS and meta["limits"]["rules"] == 50 and meta["audit_actions"] == ["add", "modify", "custom:filter-set-share", "delete"])
must(ns.capabilities.has_capability("core.filter_sets", version=">=1.0.0,<2.0.0"), "available")
must(fs.register_core_filter_sets_capability() is registration, "registering twice is idempotent")
must(json.dumps(meta), "metadata is plain JSON")
apps_src = (SRC / "apps.py").read_text(encoding="utf-8")
must("register_core_filter_sets_capability" in apps_src and "core.filter_sets capability registration failed" in apps_src, "apps.py registers it, guarded")
must(apps_src.index("register_core_filter_sets_capability") < apps_src.index("install_tactical_account_guard()"))

# throttles, openapi and the version
throttles_src = (SRC / "throttles.py").read_text(encoding="utf-8")
for cls, rate in (("FilterValuesMinThrottle", "240/min"), ("FilterSetWriteMinThrottle", "60/min"), ("FilterSetWriteDayThrottle", "2000/day")):
    must(re.search(rf"class {cls}\(.*?rate = \"{re.escape(rate)}\"", throttles_src, re.S), cls)
openapi_src = (SRC / "openapi.py").read_text(encoding="utf-8")
must('"tec_tac.filter_set_views": "Tec-Tac · Filter Sets"' in openapi_src and '("/api/tfd/filter-sets/", "Tec-Tac · Filter Sets")' in openapi_src and '("/api/tfd/filter-values/", "Tec-Tac · Filter Sets")' in openapi_src)
must(tuple(int(p) for p in (ROOT / "VERSION").read_text(encoding="utf-8").strip().split("-")[0].split(".")) >= (1, 17, 50))  # 1.17.51: at least 1.17.50
must(tuple(int(p) for p in json.loads((ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))["version"].split("-")[0].split(".")) >= (1, 17, 50))
NOTES_50 = ROOT / "RELEASE_NOTES_1.17.50.md"
if not NOTES_50.is_file():
    NOTES_50 = ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.50.md"  # moved there by 1.17.51
must(NOTES_50.is_file() and (ROOT / "docs" / "filter-sets.md").is_file())
notes = NOTES_50.read_text(encoding="utf-8")
must("Module-facing changes" in notes and "Requests closed" in notes)
docs = (ROOT / "docs" / "filter-sets.md").read_text(encoding="utf-8")
for needle in ("Not in this release", "scope duty", "from_legacy_formula", "custom:filter-set-share", "What a reader sees of a shared set's values",
               "Never a rule value, never a reader id", "`fs-`", ">=1.17.50"):
    must(needle in docs, f"docs/filter-sets.md names {needle!r}")

# the bounded cache is not imported from the request path
fs_src = (SRC / "filter_sets.py").read_text(encoding="utf-8")
def imported(source):
    names = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(("." * node.level) + (node.module or ""))
    return names


for source in (fs_src, (SRC / "filter_set_views.py").read_text(encoding="utf-8")):
    for name in imported(source):
        must(not any(word in name.lower() for word in ("cache", "redis", "celery", "tasks")), f"no cache, Redis or Celery import: {name}")

print("filter-sets 1.17.50 ok")

#!/usr/bin/env python3
"""Core 1.17.52: date and number operators for filter sets (core.filter_sets 1.1.0).

Runs the real tec_tac.filter_sets and filter_set_views on the 1.17.50 boundary (tests/filter_sets_boundary_1_17_50.py), with the
recording Q. Django is not installed on the PC that prepares a release.

Covered: operators_for by kind and the six text, bool and id answers unchanged; declaration cleaning (stored_as, integer, minimum,
maximum, wrong-kind keys, values.source must be none); every validator refusal; matches and build_q at the day edges with an injected
now, and the two agree on every probe; relative operators across minutes, hours and days; NULL and unreadable row values; naive and
aware datetimes; stored_as date; number operators; a non-owner sees date and number values while an id field with no scope_kind is
still withheld; a saved set round-trips the relative form; the route answer; the metadata; Groups' from_legacy_formula unchanged.
"""
from __future__ import annotations

import datetime as dt
import decimal
import json
import logging
import sys
from pathlib import Path

logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import filter_sets_boundary_1_17_50 as boundary  # noqa: E402

ns = boundary.install(real_capabilities=True)
fs = ns.filter_sets
alice, bob = ns.alice, ns.bob
SCOPES = ns.SCOPES
UTC = dt.timezone.utc


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def refused(call, text=None):
    try:
        call()
    except fs.FilterSetValidationError as error:
        if text is not None:
            must(text.lower() in str(error).lower(), f"{text!r} not in {str(error)!r}")
        return error
    raise AssertionError("expected a refusal")


def rule(field, operator, value):
    return {"kind": "rule", "field": field, "operator": operator, "value": value}


def flt(match, *rules):
    return {"version": 1, "match": match, "rules": list(rules)}


FIELDS = [
    {"id": "hostname", "label": "Hostname", "kind": "text", "lookup": "hostname", "row_key": "hostname"},
    {"id": "last_seen", "label": "Last seen", "kind": "date", "lookup": "last_seen", "row_key": "last_seen"},
    {"id": "installed", "label": "Installed on", "kind": "date", "stored_as": "date", "lookup": "installed", "row_key": "installed"},
    {"id": "pending", "label": "Pending actions", "kind": "number", "integer": True, "minimum": 0, "maximum": 100000,
     "lookup": "pending_actions_count", "row_key": "pending_actions_count"},
    {"id": "score", "label": "Score", "kind": "number", "lookup": "score", "row_key": "score"},
    {"id": "other", "label": "Other id", "kind": "id", "lookup": "other_id", "row_key": "other_id"},
]
ids = lambda rows: [r["id"] for r in rows]  # noqa: E731
labels = lambda rows: {r["id"]: r["label"] for r in rows}  # noqa: E731

# === 1. vocabulary ===============================================================================
SIX = ["equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with"]
must(list(fs.OPERATORS) == SIX, "the six stay the six")
must(ids(fs.operators_for("text")) == SIX and ids(fs.operators_for("bool")) == ["equals"], "text and bool unchanged")
must(ids(fs.operators_for("id")) == ["equals", "not_equals"] and ids(fs.operators_for("id", True)) == SIX, "id unchanged")
must(ids(fs.operators_for("date")) == ["equals", "not_equals", "before", "after", "on_or_before", "on_or_after", "between", "in_the_last", "not_in_the_last"])
must(ids(fs.operators_for("number")) == ["equals", "not_equals", "greater_than", "less_than", "at_least", "at_most", "between"])
must(labels(fs.operators_for("date"))["equals"] == "Is" and labels(fs.operators_for("date"))["not_equals"] == "Is not")
must(labels(fs.operators_for("number"))["equals"] == "Equals" and labels(fs.operators_for("number"))["not_equals"] == "Does not equal")
must(labels(fs.operators_for("date"))["in_the_last"] == "In the last" and labels(fs.operators_for("number"))["at_least"] == "At least")
refused(lambda: fs.operators_for("money"))
must("before" not in fs.OPERATORS and "greater_than" not in fs.OPERATORS, "OPERATORS is not extended")
must(fs.KINDS == ("text", "id", "bool", "date", "number"))

# === 2. declarations =============================================================================
cleaned = {f["id"]: f for f in fs.clean_fields(FIELDS)}
must(set(cleaned) == {"hostname", "last_seen", "installed", "pending", "score", "other"}, set(cleaned))
must(cleaned["last_seen"]["stored_as"] == "datetime" and cleaned["installed"]["stored_as"] == "date")
must(cleaned["pending"]["integer"] is True and cleaned["pending"]["minimum"] == 0 and cleaned["pending"]["maximum"] == 100000)
must(cleaned["score"]["integer"] is False and cleaned["score"]["minimum"] is None)
BAD = [
    {"id": "a", "label": "A", "kind": "date", "lookup": "a", "stored_as": "epoch"},
    {"id": "a", "label": "A", "kind": "date", "lookup": "a", "integer": True},
    {"id": "a", "label": "A", "kind": "date", "lookup": "a", "minimum": 1},
    {"id": "a", "label": "A", "kind": "date", "lookup": "a", "values": {"source": "distinct"}},
    {"id": "a", "label": "A", "kind": "date", "lookup": "a", "name_lookup": "x"},
    {"id": "a", "label": "A", "kind": "date", "lookup": "a", "scope_kind": "client"},
    {"id": "a", "label": "A", "kind": "number", "lookup": "a", "stored_as": "date"},
    {"id": "a", "label": "A", "kind": "number", "lookup": "a", "integer": "yes"},
    {"id": "a", "label": "A", "kind": "number", "lookup": "a", "minimum": True},
    {"id": "a", "label": "A", "kind": "number", "lookup": "a", "minimum": float("nan")},
    {"id": "a", "label": "A", "kind": "number", "lookup": "a", "maximum": float("inf")},
    {"id": "a", "label": "A", "kind": "number", "lookup": "a", "minimum": 5, "maximum": 1},
    {"id": "a", "label": "A", "kind": "number", "lookup": "a", "minimum": "1"},
    {"id": "a", "label": "A", "kind": "number", "lookup": "a", "values": {"source": "static", "options": [{"value": 1}]}},
    {"id": "a", "label": "A", "kind": "number", "lookup": "a", "name_key": "n"},
    {"id": "a", "label": "A", "kind": "number", "lookup": "a", "integer": True, "minimum": 0.5},
    {"id": "a", "label": "A", "kind": "text", "lookup": "a", "stored_as": "date"},
    {"id": "a", "label": "A", "kind": "bool", "lookup": "a", "integer": True},
    {"id": "a", "label": "A", "kind": "id", "lookup": "a", "maximum": 3},
]
for raw in BAD:
    must(fs.clean_fields([raw]) == [], f"dropped: {raw}")
must(fs.clean_fields([{"id": "a", "label": "A", "kind": "number", "lookup": "a", "values": {"source": "none"}}]) != [])
browser = {f["id"]: f for f in fs.browser_fields(FIELDS)}
must(browser["last_seen"]["constraints"] == {"stored_as": "datetime"} and browser["installed"]["constraints"] == {"stored_as": "date"})
must(browser["pending"]["constraints"] == {"integer": True, "minimum": 0, "maximum": 100000}, browser["pending"])
must("constraints" not in browser["hostname"], "text keeps its old shape")
must(ids(browser["pending"]["operators"]) == ids(fs.operators_for("number")))
must("lookup" not in json.dumps(browser) and "pending_actions_count" not in json.dumps(browser), "no lookup or key reaches the browser")

# === 3. validator ================================================================================
def check(*rules):
    return fs.validate_filter_set(flt("all", *rules), FIELDS)


good = check(
    rule("last_seen", "equals", "2026-10-17"), rule("last_seen", "between", {"from": "2026-10-01", "to": "2026-10-17"}),
    rule("last_seen", "in_the_last", {"amount": 7, "unit": "days"}), rule("pending", "greater_than", 3),
    rule("score", "between", {"from": 1.5, "to": 9}),
)
must(good["rules"][2]["value"] == {"amount": 7, "unit": "days"}, "the relative form is kept")
for value, text in [
    (True, "date"), ("2026-02-30", "real date"), ("2026-13-01", "real date"), ("٢٠٢٦-١٠-١٧", "YYYY-MM-DD"), ("2026-1-7", "YYYY-MM-DD"),
    ("2026-10-17\n", "YYYY-MM-DD"), ("2026-10-17T10:00:00", "YYYY-MM-DD"), ("1969-12-31", "from 1970"), ("2101-01-01", "from 1970"),
    (20261017, "YYYY-MM-DD"), (None, "YYYY-MM-DD"), ({"from": "2026-10-01", "to": "2026-10-02"}, "YYYY-MM-DD"),
]:
    refused(lambda value=value: check(rule("last_seen", "before", value)), text)
must(check(rule("last_seen", "after", "1970-01-01"), rule("last_seen", "before", "2100-12-31")))
refused(lambda: check(rule("last_seen", "between", {"from": "2026-10-18", "to": "2026-10-17"})), "may not be after")
refused(lambda: check(rule("last_seen", "between", {"from": "2026-10-17"})), "exactly")
refused(lambda: check(rule("last_seen", "between", {"from": "2026-10-17", "to": "2026-10-18", "extra": 1})), "exactly")
refused(lambda: check(rule("last_seen", "between", "2026-10-17")), "exactly")
must(check(rule("last_seen", "between", {"from": "2026-10-17", "to": "2026-10-17"})), "from equal to to is fine")
for value in [
    {"amount": 7, "unit": "weeks"}, {"amount": 0, "unit": "days"}, {"amount": -1, "unit": "days"}, {"amount": 3651, "unit": "days"},
    {"amount": 8761, "unit": "hours"}, {"amount": 525601, "unit": "minutes"}, {"amount": 1.5, "unit": "days"}, {"amount": 7.0, "unit": "days"},
    {"amount": "7", "unit": "days"}, {"amount": True, "unit": "days"}, {"amount": 7, "unit": "days", "extra": 1}, {"amount": 7},
    {"unit": "days"}, 7, "7 days", {"amount": 7, "unit": None},
]:
    refused(lambda value=value: check(rule("last_seen", "in_the_last", value)))
    refused(lambda value=value: check(rule("last_seen", "not_in_the_last", value)))
for unit, most in (("minutes", 525600), ("hours", 8760), ("days", 3650)):
    must(check(rule("last_seen", "in_the_last", {"amount": most, "unit": unit})) and check(rule("last_seen", "in_the_last", {"amount": 1, "unit": unit})))
refused(lambda: check(rule("last_seen", "contains", "2026")), "not available")
refused(lambda: check(rule("last_seen", "greater_than", "2026-10-17")), "not available")
refused(lambda: check(rule("pending", "before", 3)), "not available")
refused(lambda: check(rule("pending", "contains", "3")), "not available")
refused(lambda: check(rule("hostname", "between", {"from": "a", "to": "b"})), "not available")
refused(lambda: check(rule("last_seen", "starts_with", "2026")), "not available")
for value in [True, False, float("nan"), float("inf"), float("-inf"), "5", "", None, [1], 10**15 + 1, -(10**15) - 1, 1e16, {"from": 1}]:
    refused(lambda value=value: check(rule("score", "equals", value)))
must(check(rule("score", "equals", 10**15)) and check(rule("score", "equals", -(10**15))) and check(rule("score", "equals", 0.25)))
refused(lambda: check(rule("score", "between", {"from": 5, "to": 1})), "may not be above")
refused(lambda: check(rule("score", "between", {"from": 1, "to": "2"})), "number")
refused(lambda: check(rule("score", "between", {"from": 1, "to": 2, "x": 3})), "exactly")
refused(lambda: check(rule("score", "between", 5)), "exactly")
must(check(rule("score", "between", {"from": 2, "to": 2})))
refused(lambda: check(rule("pending", "equals", -1)), "outside")
refused(lambda: check(rule("pending", "at_most", 100001)), "outside")
refused(lambda: check(rule("pending", "equals", 2.5)), "whole number")
refused(lambda: check(rule("pending", "between", {"from": -1, "to": 5})), "outside")
must(check(rule("pending", "equals", 3.0))["rules"][0]["value"] == 3 and isinstance(check(rule("pending", "equals", 3.0))["rules"][0]["value"], int), "3.0 becomes 3 on an integer field")
must(check(rule("pending", "equals", 0)) and check(rule("pending", "equals", 100000)))
for rules in ([rule("last_seen", "equals", "2026-10-17"), rule("nope", "equals", 1)],):
    refused(lambda rules=rules: check(*rules), "cannot use")

# === 4. evaluators: matches and build_q agree =====================================================
NOW = dt.datetime(2026, 10, 17, 12, 0, 0, tzinfo=UTC)


def both(rules, row, now=NOW, fields=FIELDS):
    """matches() and build_q().evaluate() must give the same answer. Returns it."""
    tree = flt("all", *rules)
    a = fs.matches(tree, row, fields, now=now)
    if all(v is None or (isinstance(v, (dt.datetime, dt.date, int, float, decimal.Decimal)) and not isinstance(v, bool) and v == v and v not in (float('inf'), float('-inf'))) for v in row.values()):
        try:
            b = fs.build_q(tree, fields, now=now).evaluate(row)  # only a value a database column could hold
        except TypeError:
            return a  # an epoch number in a date field is not a database value
        must(a == b, f"matches {a} and build_q {b} disagree on {rules} for {row}")
    return a


def seen(operator, value, at, field="last_seen", now=NOW):
    return both([rule(field, operator, value)], {field: at}, now)


D = lambda day, *rest: dt.datetime(2026, 10, day, *rest, tzinfo=UTC)  # noqa: E731
# equals: the half-open day [17th 00:00, 18th 00:00)
must(seen("equals", "2026-10-17", D(17, 0, 0, 0)) and seen("equals", "2026-10-17", D(17, 23, 59, 59)))
must(not seen("equals", "2026-10-17", D(18, 0, 0, 0)) and not seen("equals", "2026-10-17", D(16, 23, 59, 59)))
must(not seen("not_equals", "2026-10-17", D(17, 0, 0, 0)) and seen("not_equals", "2026-10-17", D(18, 0, 0, 0)) and seen("not_equals", "2026-10-17", D(16, 23, 59, 59)))
# before < D 00:00 ; on_or_before < D+1 ; after >= D+1 ; on_or_after >= D
must(seen("before", "2026-10-17", D(16, 23, 59, 59)) and not seen("before", "2026-10-17", D(17, 0, 0, 0)))
must(seen("on_or_before", "2026-10-17", D(17, 23, 59, 59)) and not seen("on_or_before", "2026-10-17", D(18, 0, 0, 0)))
must(not seen("after", "2026-10-17", D(17, 23, 59, 59)) and seen("after", "2026-10-17", D(18, 0, 0, 0)))
must(not seen("on_or_after", "2026-10-17", D(16, 23, 59, 59)) and seen("on_or_after", "2026-10-17", D(17, 0, 0, 0)))
# between, both ends inclusive
BETWEEN = {"from": "2026-10-10", "to": "2026-10-12"}
must(seen("between", BETWEEN, D(10, 0, 0, 0)) and seen("between", BETWEEN, D(12, 23, 59, 59)))
must(not seen("between", BETWEEN, D(9, 23, 59, 59)) and not seen("between", BETWEEN, D(13, 0, 0, 0)))
# the first and last supported days
must(seen("equals", "1970-01-01", dt.datetime(1970, 1, 1, 5, tzinfo=UTC)) and seen("equals", "2100-12-31", dt.datetime(2100, 12, 31, 23, tzinfo=UTC)))
must(seen("between", {"from": "2100-12-31", "to": "2100-12-31"}, dt.datetime(2100, 12, 31, 23, 59, tzinfo=UTC)))
# a non-UTC aware datetime is read as the moment it is: 18th 01:00 +02:00 is the 17th 23:00 UTC
plus2 = dt.timezone(dt.timedelta(hours=2))
must(seen("equals", "2026-10-17", dt.datetime(2026, 10, 18, 1, 0, tzinfo=plus2)))
# naive datetime counts as UTC; ISO strings, dates and epoch numbers are read
must(seen("equals", "2026-10-17", dt.datetime(2026, 10, 17, 23, 0)) and not seen("equals", "2026-10-17", dt.datetime(2026, 10, 18, 0, 0)))
must(seen("equals", "2026-10-17", "2026-10-17T10:00:00Z") and seen("equals", "2026-10-17", "2026-10-17T10:00:00+00:00"))
must(seen("equals", "2026-10-17", "2026-10-17") and seen("equals", "2026-10-17", dt.date(2026, 10, 17)))
must(seen("equals", "2026-10-17", int(D(17, 5).timestamp())) and seen("equals", "2026-10-17", float(D(17, 5).timestamp())))
must(seen("equals", "2026-10-17", decimal.Decimal(int(D(17, 5).timestamp()))))
# NULL, bool and unreadable: never a positive match, always a negative match
for operator, value in [("equals", "2026-10-17"), ("before", "2026-10-17"), ("after", "2026-10-17"), ("on_or_before", "2026-10-17"),
                        ("on_or_after", "2026-10-17"), ("between", BETWEEN), ("in_the_last", {"amount": 7, "unit": "days"})]:
    for nothing in (None, "not a date", "", True, False, [], {}, float("nan"), 10**30):
        must(not seen(operator, value, nothing), (operator, nothing))
    must(not both([rule("last_seen", operator, value)], {}), "a missing key is NULL")
for operator, value in [("not_equals", "2026-10-17"), ("not_in_the_last", {"amount": 7, "unit": "days"})]:
    for nothing in (None, "not a date", "", True, [], float("inf"), 10**30):
        must(seen(operator, value, nothing), (operator, nothing))
    must(both([rule("last_seen", operator, value)], {}), "a missing key satisfies the negative")
# relative, now = 17 Oct 12:00
LAST = {"minutes": {"amount": 30, "unit": "minutes"}, "hours": {"amount": 3, "unit": "hours"}, "days": {"amount": 7, "unit": "days"}}
must(seen("in_the_last", LAST["minutes"], NOW) and seen("in_the_last", LAST["minutes"], NOW - dt.timedelta(minutes=30)))
must(not seen("in_the_last", LAST["minutes"], NOW - dt.timedelta(minutes=30, seconds=1)))
must(seen("in_the_last", LAST["hours"], NOW - dt.timedelta(hours=3)) and not seen("in_the_last", LAST["hours"], NOW - dt.timedelta(hours=3, seconds=1)))
must(seen("in_the_last", LAST["days"], NOW - dt.timedelta(days=7)) and not seen("in_the_last", LAST["days"], NOW - dt.timedelta(days=7, seconds=1)))
must(not seen("in_the_last", LAST["days"], NOW + dt.timedelta(seconds=1)), "a future value does not match")
must(seen("not_in_the_last", LAST["days"], NOW + dt.timedelta(seconds=1)), "the exact negation")
must(not seen("not_in_the_last", LAST["days"], NOW - dt.timedelta(days=1)) and seen("not_in_the_last", LAST["days"], NOW - dt.timedelta(days=8)))
for unit in LAST:
    for probe in (-90000, -3601, -3600, -1800, -1799, -60, -1, 0, 1, 60, 3600):
        at = NOW + dt.timedelta(seconds=probe)
        must(seen("in_the_last", LAST[unit], at) != seen("not_in_the_last", LAST[unit], at), "exact opposites")
# the stored tree keeps the relative form, and a later now moves the window
tree = fs.validate_filter_set(flt("all", rule("last_seen", "in_the_last", {"amount": 1, "unit": "days"})), FIELDS)
row = {"last_seen": D(17, 6)}
must(fs.matches(tree, row, FIELDS, now=D(17, 12)) and not fs.matches(tree, row, FIELDS, now=D(19, 12)), "a saved 'last day' stays live")
must(fs.matches(tree, row, FIELDS, now=dt.datetime(2026, 10, 17, 12)), "a naive now counts as UTC")
# the real clock is the default
must(fs.matches(tree, {"last_seen": dt.datetime.now(UTC)}, FIELDS) and not fs.matches(tree, {"last_seen": dt.datetime(2020, 1, 1, tzinfo=UTC)}, FIELDS))
must(fs.build_q(tree, FIELDS).evaluate({"last_seen": dt.datetime.now(UTC)}))
refused(lambda: fs.matches(tree, row, FIELDS, now="yesterday"))
# now is read once per call: one tree with two relative rules asks the clock once, in build_q and in matches
reads = []
real_now = fs._utc_now
fs._utc_now = lambda now=None: (reads.append(1), real_now(now))[1]
try:
    two = flt("all", rule("last_seen", "in_the_last", {"amount": 1, "unit": "minutes"}), rule("last_seen", "not_in_the_last", {"amount": 2, "unit": "minutes"}))
    fs.build_q(two, FIELDS)
    must(len(reads) == 1, reads)
    del reads[:]
    fs.matches(two, {"last_seen": NOW}, FIELDS)
    must(len(reads) == 1, reads)
finally:
    fs._utc_now = real_now
must(fs.matches(two, {"last_seen": NOW - dt.timedelta(minutes=1, seconds=30)}, FIELDS, now=NOW) is False, "inside the last 2 minutes but not the last 1")
# build_q emits only the allowed comparisons
def lookups(q):
    if q.kind == "leaf":
        return [next(iter(q.kwargs))]
    return [name for part in q.parts for name in lookups(part)]


emitted = set()
for operator, value in [("equals", "2026-10-17"), ("not_equals", "2026-10-17"), ("before", "2026-10-17"), ("after", "2026-10-17"),
                        ("on_or_before", "2026-10-17"), ("on_or_after", "2026-10-17"), ("between", BETWEEN), ("in_the_last", LAST["days"]),
                        ("not_in_the_last", LAST["days"])]:
    for field in ("last_seen", "installed"):
        emitted.update(lookups(fs.build_q(flt("all", rule(field, operator, value)), FIELDS, now=NOW)))
must(emitted <= {"last_seen__gte", "last_seen__lt", "last_seen__lte", "installed", "installed__gte", "installed__lt", "installed__lte"}, emitted)
for operator, value in [("equals", 1), ("not_equals", 1), ("greater_than", 1), ("less_than", 1), ("at_least", 1), ("at_most", 1), ("between", {"from": 1, "to": 2})]:
    emitted.update(lookups(fs.build_q(flt("all", rule("score", operator, value)), FIELDS)))
must({"score", "score__gt", "score__lt", "score__gte", "score__lte"} <= emitted, emitted)
for name in emitted:
    must(not any(word in name for word in ("iexact", "icontains", "regex", "raw", "extra")), name)
# the datetime bounds are aware UTC
q = fs.build_q(flt("all", rule("last_seen", "equals", "2026-10-17")), FIELDS, now=NOW)
bounds = [part.kwargs for part in q.parts]
must(bounds == [{"last_seen__gte": D(17)}, {"last_seen__lt": D(18)}], bounds)
must(all(value.tzinfo is not None and value.utcoffset() == dt.timedelta(0) for part in bounds for value in part.values()))
q = fs.build_q(flt("all", rule("last_seen", "in_the_last", {"amount": 2, "unit": "hours"})), FIELDS, now=NOW)
must([part.kwargs for part in q.parts] == [{"last_seen__gte": NOW - dt.timedelta(hours=2)}, {"last_seen__lte": NOW}])

# stored_as date: plain dates, same answers
IN = lambda operator, value, at: both([rule("installed", operator, value)], {"installed": at})  # noqa: E731
day = dt.date(2026, 10, 17)
must(IN("equals", "2026-10-17", day) and not IN("equals", "2026-10-17", dt.date(2026, 10, 18)) and not IN("equals", "2026-10-17", dt.date(2026, 10, 16)))
must(IN("before", "2026-10-17", dt.date(2026, 10, 16)) and not IN("before", "2026-10-17", day))
must(IN("on_or_before", "2026-10-17", day) and not IN("on_or_before", "2026-10-17", dt.date(2026, 10, 18)))
must(IN("after", "2026-10-17", dt.date(2026, 10, 18)) and not IN("after", "2026-10-17", day))
must(IN("on_or_after", "2026-10-17", day) and not IN("on_or_after", "2026-10-17", dt.date(2026, 10, 16)))
must(IN("between", BETWEEN, dt.date(2026, 10, 10)) and IN("between", BETWEEN, dt.date(2026, 10, 12)) and not IN("between", BETWEEN, dt.date(2026, 10, 13)))
must(not IN("equals", "2026-10-17", None) and IN("not_equals", "2026-10-17", None))
qd = fs.build_q(flt("all", rule("installed", "equals", "2026-10-17")), FIELDS)
must(qd.kwargs == {"installed": day}, qd)
qd = fs.build_q(flt("all", rule("installed", "between", BETWEEN)), FIELDS)
must([p.kwargs for p in qd.parts] == [{"installed__gte": dt.date(2026, 10, 10)}, {"installed__lt": dt.date(2026, 10, 13)}], qd)
# in the last 7 days on a date column, now 17 Oct 12:00: cutoff 10 Oct 12:00, so the 10th (00:00) is out and the 11th is in; today is in, tomorrow is not
for offset, expected in ((-7, False), (-6, True), (0, True), (1, False)):
    must(IN("in_the_last", {"amount": 7, "unit": "days"}, dt.date(2026, 10, 17) + dt.timedelta(days=offset)) is expected, offset)
midnight = dt.datetime(2026, 10, 17, 0, 0, tzinfo=UTC)
must(IN("in_the_last", {"amount": 7, "unit": "days"}, dt.date(2026, 10, 10)) is False)
must(both([rule("installed", "in_the_last", {"amount": 7, "unit": "days"})], {"installed": dt.date(2026, 10, 10)}, now=midnight) is True, "exactly on the cutoff counts")
must(IN("not_in_the_last", {"amount": 7, "unit": "days"}, dt.date(2026, 10, 10)) is True)

# numbers
def num(operator, value, at, field="score"):
    return both([rule(field, operator, value)], {field: at})


must(num("equals", 5, 5) and num("equals", 5, 5.0) and not num("equals", 5, 6) and num("equals", 0.1, 0.1) and num("equals", 5, decimal.Decimal("5.00")))
must(num("not_equals", 5, 6) and not num("not_equals", 5, 5))
must(num("greater_than", 5, 6) and not num("greater_than", 5, 5) and num("less_than", 5, 4) and not num("less_than", 5, 5))
must(num("at_least", 5, 5) and not num("at_least", 5, 4.99) and num("at_most", 5, 5) and not num("at_most", 5, 5.01))
BN = {"from": 2, "to": 4}
must(num("between", BN, 2) and num("between", BN, 4) and num("between", BN, 3.5) and not num("between", BN, 1.99) and not num("between", BN, 4.01))
must(num("equals", 0, 0) and num("less_than", 0, -1) and num("greater_than", -5, -4))
must(num("equals", 1, "1") and num("equals", 1.5, "1.5"), "numeric text in a row is read")
for nothing in (None, True, False, "abc", "", [], {}, float("nan"), float("inf"), "nan", "inf"):
    for operator, value in [("equals", 5), ("greater_than", 5), ("less_than", 5), ("at_least", 5), ("at_most", 5), ("between", BN)]:
        must(not num(operator, value, nothing), (operator, nothing))
    must(num("not_equals", 5, nothing), ("not_equals", nothing))
must(not both([rule("score", "less_than", 5)], {}) and both([rule("score", "not_equals", 5)], {}), "a missing key is NULL")
must(both([rule("pending", "greater_than", 3)], {"pending_actions_count": 4}) and not both([rule("pending", "greater_than", 3)], {"pending_actions_count": 3}))
# a float that would round at the boundary compares exactly
must(not num("greater_than", 0.1, 0.1) and num("at_least", 0.1, 0.1) and num("less_than", 0.30000000000000004, 0.3))
# groups: any inside all, mixed kinds
mixed = [{"kind": "group", "match": "any", "rules": [rule("pending", "greater_than", 5), rule("last_seen", "before", "2026-01-01")]}, rule("hostname", "contains", "srv")]
must(both(mixed, {"pending_actions_count": 9, "last_seen": D(17), "hostname": "SRV-1"}) and not both(mixed, {"pending_actions_count": 1, "last_seen": D(17), "hostname": "SRV-1"}))
must(both(mixed, {"pending_actions_count": None, "last_seen": dt.datetime(2025, 1, 1, tzinfo=UTC), "hostname": "srv"}))

# === 5. sharing: a non-owner sees date and number values ==========================================
class Provider:
    def describe_fields(self, *, context):
        return [dict(f) for f in FIELDS]

    def distinct_values(self, field_id, *, context, search, page, page_size):
        raise AssertionError("not used here")


ns.capabilities._core_module_may_register = lambda owner, capability_id: True
ns.capabilities.register_capability(id="demo-open.filter_fields", module_id="demo-open", version="1.0.0", provider=Provider(),
                                    operations=("describe_fields", "distinct_values"))
SCOPES[bob.pk] = {"mode": "sites", "unrestricted": False, "whole_client_ids": [], "site_ids": [5]}
rules_in = [
    rule("last_seen", "in_the_last", {"amount": 7, "unit": "days"}), rule("last_seen", "between", BETWEEN), rule("installed", "equals", "2026-10-17"),
    rule("pending", "at_least", 3), rule("score", "between", {"from": 1.5, "to": 2.5}), rule("score", "equals", 0.5), rule("hostname", "contains", "srv"),
]
saved = ns.filter_sets.create_filter_set(alice, "demo-open", "endpoints", "Recent", flt("all", *rules_in), None, fields=FIELDS)
must(saved["definition"]["rules"] == rules_in, "the relative form is stored and returned as typed")
reloaded = fs.get_filter_set(alice, saved["id"], fields=FIELDS)
must(reloaded["definition"]["rules"] == rules_in and reloaded["values_withheld"] == 0)
as_bob = fs.get_filter_set(bob, saved["id"], fields=FIELDS)
must(as_bob["definition"]["rules"] == rules_in and as_bob["values_withheld"] == 0, as_bob)
listed = fs.list_filter_sets(bob, "demo-open", "endpoints", fields=FIELDS)
must(listed[0]["definition"]["rules"] == rules_in and listed[0]["values_withheld"] == 0)
resolved = fs.resolve_filter_set(alice, "demo-open", saved["id"], FIELDS)
must(resolved["rules"] == rules_in and fs.matches(resolved, {"last_seen": D(16), "installed": dt.date(2026, 10, 17), "pending_actions_count": 4,
                                                           "score": 2, "hostname": "srv1"}, FIELDS, now=NOW) is False, "0.5 does not match 2")
# an id field with no scope_kind is still withheld
other = fs.create_filter_set(alice, "demo-open", "endpoints", "Other", flt("all", rule("other", "equals", 5)), None, fields=FIELDS)
seen_other = fs.get_filter_set(bob, other["id"], fields=FIELDS)
must(seen_other["definition"]["rules"][0]["withheld"] is True and seen_other["values_withheld"] == 1, seen_other)
# fail closed: a stored value that does not validate for the reader's fields is withheld, and no fields withholds everything
must(fs.get_filter_set(bob, saved["id"], fields=None)["values_withheld"] == len(rules_in))
narrow = [dict(f) for f in FIELDS]
narrow[3] = dict(narrow[3], maximum=2)  # the reader's own declaration rejects "at least 3"
withheld = fs.get_filter_set(bob, saved["id"], fields=narrow)
must(withheld["values_withheld"] == 1 and withheld["definition"]["rules"][3]["withheld"] is True, withheld)
must(all(r.get("withheld") is None for i, r in enumerate(withheld["definition"]["rules"]) if i != 3))
# the reader's _value_visible directly: dict forms, floats and junk
checker = fs._ScopeChecker(bob)
index = fs._index(FIELDS)
vis = lambda r: fs._value_visible(r, index, checker)  # noqa: E731
must(vis(rule("score", "equals", 1.25)) and vis(rule("score", "between", {"from": 1, "to": 2.5})) and vis(rule("last_seen", "in_the_last", {"amount": 5, "unit": "hours"})))
must(not vis(rule("score", "equals", True)) and not vis(rule("score", "equals", float("nan"))) and not vis(rule("score", "between", {"from": 3, "to": 1})))
must(not vis(rule("last_seen", "equals", "2026-02-30")) and not vis(rule("last_seen", "in_the_last", {"amount": 0, "unit": "days"})) and not vis(rule("last_seen", "contains", "x")))
must(not vis(rule("last_seen", None, "2026-10-17")) and not vis(rule("last_seen", "equals", None)) and not vis({"field": "last_seen"}))
must(not vis(rule("gone", "equals", 1)), "an unknown field")

# === 6. route answer and metadata =================================================================
response = ns.views.FilterSetFieldsView().get(ns.Request(alice, query={"module": "demo-open"}))
must(response.status_code == 200, response.data)
data = response.data
must(data["operators"] == [{"id": k, "label": v} for k, v in fs.OPERATORS.items()] and len(data["operators"]) == 6, "operators stays the six")
must(ids(data["date_operators"]) == ids(fs.operators_for("date")) and ids(data["number_operators"]) == ids(fs.operators_for("number")))
must({u["id"]: u["max_amount"] for u in data["relative_units"]} == {"minutes": 525600, "hours": 8760, "days": 3650})
fields_by_id = {f["id"]: f for f in data["fields"]}
must(fields_by_id["pending"]["constraints"] == {"integer": True, "minimum": 0, "maximum": 100000} and fields_by_id["last_seen"]["kind"] == "date")
must("pending_actions_count" not in json.dumps(data), "no lookup or row key in the route answer")
meta = fs.filter_sets_contract_metadata()
must(meta["version"] == "1.1.0" == fs.CAPABILITY_VERSION and meta["operators"] == fs.OPERATORS and list(meta["operators"]) == SIX)
must(meta["field_kinds"] == ["text", "id", "bool", "date", "number"] and meta["requires_framework"] == ">=1.17.50")
must(meta["date_and_number_requires_framework"] == ">=1.17.52" and "UTC" in meta["day_boundary"])
must(ids(meta["date_operators"]) == ids(fs.operators_for("date")) and ids(meta["number_operators"]) == ids(fs.operators_for("number")))
must(set(meta["all_operators"]) == set(SIX) | {"before", "after", "on_or_before", "on_or_after", "between", "in_the_last", "not_in_the_last",
                                              "greater_than", "less_than", "at_least", "at_most"})
must(meta["relative_units"] == {"minutes": 525600, "hours": 8760, "days": 3650} and meta["limits"]["number_magnitude"] == 10**15)
keys = " ".join(meta["field_declaration_keys"])
must("stored_as" in keys and "integer" in keys and "minimum, maximum" in keys, keys)
registration = fs.register_core_filter_sets_capability()
must(registration.version == "1.1.0", registration)
must(ns.capabilities.has_capability("core.filter_sets", version=">=1.1.0,<2.0.0") and ns.capabilities.has_capability("core.filter_sets", version=">=1.0.0,<2.0.0"))

# === 7. Groups' conversion is untouched ============================================================
legacy = {"version": 1, "items": [
    {"kind": "condition", "field": "hostname", "operator": "contains", "value": "srv"},
    {"kind": "condition", "join": "or", "field": "hostname", "operator": "equals", "value": "x"},
    {"kind": "condition", "join": "and", "field": "hostname", "operator": "not_equals", "value": "y"},
]}
converted = fs.from_legacy_formula(legacy)
must(converted == {"version": 1, "match": "all", "rules": [
    {"kind": "group", "match": "any", "rules": [rule("hostname", "contains", "srv"), rule("hostname", "equals", "x")]},
    rule("hostname", "not_equals", "y")]}, converted)
must(fs.validate_filter_set(converted, FIELDS)["rules"][1] == rule("hostname", "not_equals", "y"))
# a legacy formula may not reach the new operators through a text field
refused(lambda: fs.validate_filter_set(fs.from_legacy_formula({"items": [{"kind": "condition", "field": "hostname", "operator": "greater_than", "value": "1"}]}), FIELDS))

# === 8. source and docs ============================================================================
src = (ROOT / "framwork" / "tec_tac" / "filter_sets.py").read_text(encoding="utf-8")
head = src.split("logger = ", 1)[0]
must("import django" not in head and "from django" not in head, "the pure parts import no Django")
must(src.count("def _q_class") == 1 and "from django.db.models import Q" in src.split("def _q_class", 1)[1].split("def ", 1)[0], "Q stays lazy")
docs = (ROOT / "docs" / "filter-sets.md").read_text(encoding="utf-8")
for needle in ("in_the_last", "not_in_the_last", "on_or_before", "stored_as", "UTC", "NULL", "annotation", "1.1.0", ">=1.17.52", "minimum", "integer"):
    must(needle in docs, f"docs/filter-sets.md names {needle!r}")
must("no greater than" not in docs.lower() and "date ranges" not in docs.lower().split("not in this release", 1)[-1], "the old 'not in this release' lines are gone")
print("filter-sets date and number 1.17.52 ok")

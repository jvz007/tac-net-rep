#!/usr/bin/env python3
"""Core 1.17.58, held Low from the 1.17.52 review: a decimal rule value on an integer column.

Core cannot know a column's type, so it does not change how a decimal is compared. A number field whose lookup is an integer column or a
Count annotation declares ``integer: true``; then a decimal rule value is refused (a whole-valued 2.0 is stored as 2), so build_q and
matches cannot disagree. This test pins that rule, that a field without it still takes a decimal, and that the declaration text says so.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import filter_sets_boundary_1_17_50 as boundary  # noqa: E402

fs = boundary.install(real_capabilities=True).filter_sets


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def rule(field, operator, value):
    return {"kind": "rule", "field": field, "operator": operator, "value": value}


def flt(*rules):
    return {"version": 1, "match": "all", "rules": list(rules)}


FIELDS = [
    {"id": "pending", "label": "Pending actions", "kind": "number", "integer": True, "lookup": "pending_actions_count", "row_key": "pending"},
    {"id": "score", "label": "Score", "kind": "number", "lookup": "score", "row_key": "score"},
]


def refused(call):
    try:
        call()
    except fs.FilterSetValidationError as error:
        return str(error)
    raise AssertionError("expected a refusal")


for operator in ("equals", "not_equals", "greater_than", "at_least"):
    tree = flt(rule("pending", operator, 2.5))
    texts = {
        refused(lambda tree=tree: fs.validate_filter_set(tree, FIELDS)),
        refused(lambda tree=tree: fs.build_q(tree, FIELDS)),
        refused(lambda tree=tree: fs.matches(tree, {"pending": 2}, FIELDS)),
    }
    must(len(texts) == 1 and "whole number" in next(iter(texts)), texts)
must(refused(lambda: fs.validate_filter_set(flt(rule("pending", "between", {"from": 1, "to": 2.5})), FIELDS)), "between")

# 2.0 is stored as 2, and the database side and the in-memory side agree on every row
stored = fs.validate_filter_set(flt(rule("pending", "equals", 2.0)), FIELDS)
value = stored["rules"][0]["value"]
must(value == 2 and isinstance(value, int), stored)
for row_value, expected in ((2, True), (3, False), (1, False), (None, False)):
    row = {"pending": row_value, "pending_actions_count": row_value}
    a = fs.matches(stored, row, FIELDS)
    b = fs.build_q(stored, FIELDS).evaluate(row)
    must(a == b == expected, (row_value, a, b))

# a field that does not declare integer still takes a decimal: Core did not change how decimals are compared
ok = fs.validate_filter_set(flt(rule("score", "equals", 2.5)), FIELDS)
must(ok["rules"][0]["value"] == 2.5, ok)
must(fs.matches(ok, {"score": 2.5}, FIELDS) and not fs.matches(ok, {"score": 2.0}, FIELDS), "decimal column")

# the declaration text names the rule
text = json.dumps(fs.filter_sets_contract_metadata()["field_declaration_keys"])
must("declare integer true" in text and "Count annotation" in text, text)
docs = (HERE.parent / "docs" / "filter-sets.md").read_text(encoding="utf-8")
must("Declare `integer: True` on every number field" in docs, "docs")
print("[TEST] PASS filter sets integer number 1.17.58")

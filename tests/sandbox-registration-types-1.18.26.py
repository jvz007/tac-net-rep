#!/usr/bin/env python3
"""1.18.26 regression (AD-65 Patch C, item 5): type checks on a runner parameter, and no ``pattern`` field.

Runs the real registry.py (no Django needed) and the real root helper. Covered:

* max_length, minimum and maximum: a string, a bool, a float and a None are refused with a plain message by BOTH validators and never end in an
  uncaught TypeError; max_length 0, a negative max_length and 65537 are refused; minimum above maximum is refused; valid whole numbers pass;
* ``pattern`` is refused at registration by both, with the same plain text, whatever it holds (valid or not a regular expression);
* a schema entry that is not an object is a RuntimeError in the helper (it was a TypeError);
* validate_run_parameters: a stored row with a pattern or a malformed limit is a Refusal runtime_unverified (never a crash), a clean row still
  checks enum, integer range and string length, and no pattern is ever applied;
* server_maintenance_actions keep their own rules: the shared ``_sm_parameters`` still accepts a pattern there.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
from tec_tac import registry


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


spec = importlib.util.spec_from_file_location("sandbox_helper_types", ROOT / "scripts" / "sandbox-helper.py")
sh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sh)


def reg(schema):
    try:
        registry._sandbox_parameter_limits(schema, "label")
        return None
    except registry.RegistryError as exc:
        return str(exc)


def helper(schema):
    try:
        sh._check_parameters(schema, "label")
        return None
    except RuntimeError as exc:
        return str(exc)
    except Exception as exc:
        raise AssertionError(("the helper crashed instead of refusing", schema, type(exc).__name__)) from exc


BAD = []
for key in ("max_length", "minimum", "maximum"):
    base = {"type": "string"} if key == "max_length" else {"type": "integer"}
    for label, value in (("string", "5"), ("bool", True), ("float", 5.5), ("none", None), ("list", [5])):
        BAD.append((f"{key} {label}", {"p": {**base, key: value}}))
BAD += [
    ("max_length 0", {"p": {"type": "string", "max_length": 0}}), ("max_length negative", {"p": {"type": "string", "max_length": -1}}),
    ("max_length 65537", {"p": {"type": "string", "max_length": 65537}}), ("minimum huge", {"p": {"type": "integer", "minimum": 2 ** 40}}),
    ("minimum above maximum", {"p": {"type": "integer", "minimum": 9, "maximum": 1}}),
    ("pattern", {"p": {"type": "string", "pattern": "^[a-z]+$"}}), ("pattern that is not a regex", {"p": {"type": "string", "pattern": "("}}),
    ("empty pattern", {"p": {"type": "string", "pattern": ""}}),
]
for label, schema in BAD:
    why_reg, why_helper = reg(schema), helper(schema)
    must(why_reg and why_helper, ("accepted", label, why_reg, why_helper))
    must("Traceback" not in why_reg + why_helper, label)
for label, schema in BAD:
    if "pattern" in label:
        must("pattern is not supported; use enum choices or max_length" in reg(schema) and "pattern is not supported; use enum choices or max_length" in helper(schema), label)
must(helper({"p": "not an object"}) and "must be an object" in helper({"p": "not an object"}), "a schema entry that is not an object is a plain RuntimeError")

GOOD = [{"p": {"type": "string", "max_length": 1}}, {"p": {"type": "string", "max_length": 65536}}, {"p": {"type": "integer", "minimum": -5, "maximum": 5}},
        {"p": {"type": "integer", "minimum": 0}}, {"p": {"type": "enum", "choices": ["a", "b"]}}, {"p": {"type": "boolean"}}, {}]
for schema in GOOD:
    must(reg(schema) is None and helper(schema) is None, ("refused a good schema", schema, reg(schema), helper(schema)))
must(reg("not a dict") is None, "a non-object is left to _sm_parameters, which gives its own message")

# the run: a stored row is checked again
def run(schema, raw):
    try:
        return sh.validate_run_parameters(schema, raw)
    except sh.Refusal as exc:
        return exc.code


must(run({"p": {"type": "string", "pattern": "^a$"}}, {"p": "a"}) == "runtime_unverified", "a stored pattern is refused at run")
must(run({"p": {"type": "string", "max_length": "5"}}, {"p": "a"}) == "runtime_unverified", "a stored string limit is refused at run")
must(run({"p": {"type": "integer", "maximum": True}}, {"p": 1}) == "runtime_unverified", "a stored bool limit is refused at run")
must(run({"p": "junk"}, {"p": 1}) == "runtime_unverified", "a stored row that is not an object is refused at run, not a crash")
must(run({"p": {"type": "string", "max_length": 3}}, {"p": "abcd"}) == "invalid_input", "length still checked")
must(run({"p": {"type": "string", "max_length": 3}}, {"p": "abc"}) == {"p": "abc"}, "a valid string passes")
must(run({"p": {"type": "integer", "minimum": 1, "maximum": 3}}, {"p": 4}) == "invalid_input" and run({"p": {"type": "integer", "minimum": 1, "maximum": 3}}, {"p": 2}) == {"p": 2}, "range still checked")
must(run({"p": {"type": "enum", "choices": ["a"]}}, {"p": "b"}) == "invalid_input", "enum still checked")
must("pattern" not in (ROOT / "scripts" / "sandbox-helper.py").read_text(encoding="utf-8").split("def validate_run_parameters")[1].split("def decode_credentials")[0].replace("1.18.26: there is no\n    pattern", "").replace("a stored row that carries one", "").replace("pattern; ", ""), "no pattern branch is left in validate_run_parameters")

# server maintenance keeps its own rules (a shared function, a different list of keys)
must(registry._sm_parameters({"p": {"type": "string", "pattern": "^a$"}}, "sm") == {"p": {"type": "string", "pattern": "^a$"}}, "server_maintenance_actions still accept a pattern")
print("[TEST] PASS sandbox registration types 1.18.26")

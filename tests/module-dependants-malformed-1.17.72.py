#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.72 regression (LOW held from the 1.17.71 review): one malformed dependency entry no longer drops every pair of its key.

The REAL registry.py and module_dependants.py on the harness of tests/module-dependants-1.17.71.py (its first part is executed from it, so the two cannot
drift). Covered. (A) a ``dependencies`` object with a blank id beside two good entries keeps both good pairs, sorted, and flags the spec
(``dependencies_incomplete``); the same for ``optional_dependencies``; a key that is a list instead of an object gives () and is flagged; a missing key and
None are not flagged; a non-text constraint with a good id still reads as '*'; {' ': '*'} alone still gives () (and is flagged); equality and repr ignore the
new field; PluginSpec(...) built the old way has it False; the registry never raises. (B) dependants(): a manifest with a blank id beside the caller's id is
still listed as a dependant of the caller; ``complete`` is False when any other installed extension is flagged, with one warning that names module ids only;
a clean registry answers complete True with exactly the 1.17.71 keys; a flagged caller or a flagged legacy module or reportset does not make the answer
incomplete; the row keys are unchanged.
"""
from __future__ import annotations

import logging
from pathlib import Path

BASE = Path(__file__).resolve().parent / "module-dependants-1.17.71.py"
_source = BASE.read_text(encoding="utf-8")
_cut = _source.index('reset_world()\nadd("groups")\nadd("patchmanagement"')
__file__ = str(BASE)
exec(compile(_source[:_cut], str(BASE), "exec"), globals())  # noqa: S102 - the shared test file of 1.17.71, not user input
logging.disable(logging.NOTSET)

# ---- (A) the registry
mixed = manifest({"dependencies": {" ": "*", "groups": ">=1.0.0", "alpha": "*"}}, plugin_id="mixed")
must(mixed.dependencies == (("alpha", "*"), ("groups", ">=1.0.0")), mixed.dependencies)
must(mixed.dependencies_incomplete is True, "a skipped entry flags the spec")
bad_optional = manifest({"optional_dependencies": {"": "*", "beta": ">=0.2.0", "alpha": ""}}, plugin_id="mixedopt")
must(bad_optional.optional_dependencies == (("alpha", "*"), ("beta", ">=0.2.0")) and bad_optional.dependencies_incomplete is True, bad_optional.optional_dependencies)
must(reg._dependency_pairs({"dependencies": {5: "*", "groups": "*"}}, "dependencies") == (("groups", "*"),), "a non-text id is skipped, the good pair kept")
must(reg._dependency_pairs_checked({"dependencies": {5: "*", "groups": "*"}}, "dependencies") == ((("groups", "*"),), True), "and flagged")
listed = manifest({"dependencies": ["groups"]}, plugin_id="listed")
must(listed.dependencies == () and listed.dependencies_incomplete is True, "a list instead of an object gives () and is flagged")
must(manifest({"optional_dependencies": "nope"}, plugin_id="strkey").dependencies_incomplete is True, "an optional key that is not an object is flagged")
for clean in ({}, {"dependencies": None}, {"dependencies": {}}, {"dependencies": {"groups": "*"}, "optional_dependencies": {"beta": ">=1.0.0"}}):
    must(manifest(clean, plugin_id="clean").dependencies_incomplete is False, f"{clean} is complete")
must(manifest({"dependencies": {"groups": 5}}, plugin_id="nontext").dependencies == (("groups", "*"),), "a non-text constraint with a good id reads as '*'")
must(manifest({"dependencies": {"groups": 5}}, plugin_id="nontext").dependencies_incomplete is False, "and is not flagged")
alone = manifest({"dependencies": {" ": "*"}}, plugin_id="alone")
must(alone.dependencies == () and alone.dependencies_incomplete is True, "a blank id alone still gives () and is flagged")
must(reg._dependency_pairs({" ": "*"}, "dependencies") == () and reg._dependency_pairs({"dependencies": {" ": "*"}}, "dependencies") == (), "the old function and signature are kept")
must(reg._dependency_pairs({"dependencies": None}, "dependencies") == () and reg._dependency_pairs({}, "dependencies") == (), "None and missing give ()")
plain_spec = reg.PluginSpec(plugin_id="a", plugin_type="extension", root=Path("."))
must(plain_spec.dependencies_incomplete is False, "the default is False")
flagged_spec = reg.PluginSpec(plugin_id="a", plugin_type="extension", root=Path("."), dependencies_incomplete=True)
must(flagged_spec == plain_spec and "incomplete" not in repr(flagged_spec) and hash(flagged_spec) == hash(plain_spec), "equality, hash and repr ignore the field")
print("       a bad entry skips only itself, flags the spec, and every good pair is kept and sorted")

# ---- (B) dependants()
reset_world()
add("groups")
add("both", deps=dict(mixed.dependencies), name="Both")  # the manifest above: a blank id beside the caller's id
PLUGINS["both"].dependencies_incomplete = mixed.dependencies_incomplete
out = asker("groups")["ask"]()
must([r["id"] for r in out["dependants"]] == ["both"] and out["dependants"][0]["constraint"] == ">=1.0.0", out)
must(out["complete"] is False, "another module's manifest was not read in full, so the answer is incomplete")
must(set(out) == {"module", "dependants", "complete"} and all(set(r) == set(md.ROW_KEYS) for r in out["dependants"]), "the documented keys are unchanged")

records = []


class Catch(logging.Handler):
    def emit(self, record):
        records.append(record)


handler = Catch()
md.logger.addHandler(handler)
md.logger.setLevel(logging.DEBUG)
logging.disable(logging.NOTSET)
add("listed2", name="Listed")
PLUGINS["listed2"].dependencies_incomplete = True
records.clear()
out = asker("groups")["ask"]()
warnings = [r for r in records if r.levelno == logging.WARNING]
must(len(warnings) == 1, f"one warning, got {len(warnings)}")
message = warnings[0].getMessage()
must("both" in message and "listed2" in message, message)
must("alpha" not in message and ">=1.0.0" not in message, "the warning names module ids only, no constraints or other data")
md.logger.removeHandler(handler)

# a flagged module that is not an extension, is legacy, or is the caller does not matter
reset_world()
add("groups")
add("oldmod", legacy=True)
add("sets", kind="reportset")
for name in ("oldmod", "sets", "groups"):
    PLUGINS[name].dependencies_incomplete = True
out = asker("groups")["ask"]()
must(out == {"module": "groups", "dependants": [], "complete": True}, out)

# a clean registry answers exactly as in 1.17.71
reset_world()
add("groups")
add("patchmanagement", deps={"groups": ">=0.4.0"}, name="Advanced Patch Management", version="0.13.0")
add("reportmanager", optional={"groups": "*"}, name="Report Manager", version="1.1.0")
out = asker("groups")["ask"]()
must(out["complete"] is True and [r["id"] for r in out["dependants"]] == ["patchmanagement", "reportmanager"], out)
# the cap still decides complete on its own
for i in range(205):
    add(f"m{i:03d}", deps={"groups": "*"})
out = asker("groups")["ask"]()
must(len(out["dependants"]) == 200 and out["complete"] is False, "the 200-row cap still gives complete False")
# a spec from an older stub that has no such attribute is complete
reset_world()
add("groups")
add("legacystub", deps={"groups": "*"})
getattr(PLUGINS["legacystub"], "__dict__", {}).pop("dependencies_incomplete", None)
must(asker("groups")["ask"]()["complete"] is True, "a spec without the field reads as complete")
print("       dependants lists a dependant beside a bad entry, answers complete False once, warns by module id only, and a clean registry is unchanged")
print("module-dependants-malformed-1.17.72: PASS")

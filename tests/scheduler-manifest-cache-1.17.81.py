#!/usr/bin/env python3
# ruff: noqa: F821
"""1.17.81 regression: the person-action manifest lookup is cached, and the manifest key needs requires.framework >= 1.17.80.

(1) discover_plugins is called once for 50 module schedules (and 50 more), not three times per run; (2) the answer follows the manifest files:
a changed, removed or added manifest is read again; (3) a broken manifest fails closed (False), keeps its reason in the cache and logs one
warning per refused schedule; (4) the registry parser refuses scheduler_person_actions without requires.framework >= 1.17.80 and accepts it with
one; (5) APM's real manifest still parses.
"""
from __future__ import annotations

import ast
import json
import logging
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

tmp = Path(tempfile.mkdtemp())
EXT, REP = tmp / "extensions", tmp / "reportsets"
EXT.mkdir()
REP.mkdir()
CALLS = [0]


def write(module_id, actions):
    d = EXT / module_id
    d.mkdir(exist_ok=True)
    (d / "tec_tac.json").write_text(json.dumps({"id": module_id, "scheduler_person_actions": list(actions)}), encoding="utf-8")


def discover():
    CALLS[0] += 1
    out = []
    for d in sorted(EXT.iterdir()):
        payload = json.loads((d / "tec_tac.json").read_text(encoding="utf-8"))  # a broken file raises, as the real parser does
        out.append(SimpleNamespace(plugin_id=payload["id"], plugin_type="extension", legacy=False, scheduler_person_actions=tuple(payload["scheduler_person_actions"])))
    return tuple(out)


reg = sys.modules["tec_tac.registry"]
reg.EXTENSIONS_ROOT, reg.REPORTSETS_ROOT, reg.MANIFEST_NAME, reg.discover_plugins = EXT, REP, "tec_tac.json", discover
sched._MANIFEST_CACHE.update(signature=None, actions={}, error="")


class Sched:
    owner_type = "module"
    pk = 1


def lookups(n):
    for i in range(n):
        sched._manifest_person_actions(f"mod{i % 50}")


# ---- (1) constant discover_plugins calls across 50 module schedules
for i in range(50):
    write(f"mod{i}", [f"mod{i}.notice"])
lookups(50)
must(CALLS[0] == 1, CALLS)
lookups(200)
must(CALLS[0] == 1, CALLS)
must(sched._manifest_person_actions("mod7") == ("mod7.notice",) and sched._manifest_person_actions("nope") == ())
print("       50 module lookups, 200 more: discover_plugins ran once")

# ---- (2) invalidation: change, add, remove
write("mod7", ["mod7.notice", "mod7.reboot"])
must(sched._manifest_person_actions("mod7") == ("mod7.notice", "mod7.reboot") and CALLS[0] == 2, CALLS)
write("mod99", ["mod99.notice"])
must(sched._manifest_person_actions("mod99") == ("mod99.notice",) and CALLS[0] == 3, CALLS)
(EXT / "mod99" / "tec_tac.json").unlink()
(EXT / "mod99").rmdir()
must(sched._manifest_person_actions("mod99") == () and CALLS[0] == 4, CALLS)
lookups(20)
must(CALLS[0] == 4, CALLS)
print("       a changed, added or removed manifest is read again; unchanged ones are not")

# ---- (3) a broken manifest fails closed, keeps a reason, then recovers
(EXT / "mod3" / "tec_tac.json").write_text("{not json", encoding="utf-8")
must(sched._manifest_person_actions("mod7") == () and sched._MANIFEST_CACHE["error"] == "manifest_unreadable", sched._MANIFEST_CACHE)
before = CALLS[0]
lookups(20)
must(CALLS[0] == before, "a broken manifest is not rescanned on every run")
records = []
handler = type("H", (logging.Handler,), {"emit": lambda self, r: records.append(r.getMessage())})()
logging.getLogger("tec_tac.scheduler").addHandler(handler)
sched.get_scheduled_action = lambda action_id: SimpleNamespace(id="mod7.notice", module_id="mod7")
sched.TecTacSchedule.OwnerType = SimpleNamespace(MODULE="module")
sched.is_one_off_schedule = lambda s: False
s = Sched()
s.owner_module, s.action_id = "mod7", "mod7.notice"
logging.disable(logging.NOTSET)
must(sched.scheduled_person_action(s) is False and any("manifest_unreadable" in m for m in records), records)
write("mod3", ["mod3.notice"])
must(sched._manifest_person_actions("mod7") == ("mod7.notice", "mod7.reboot") and sched._MANIFEST_CACHE["error"] == "", sched._MANIFEST_CACHE)
print("       a broken manifest answers False with a logged reason, is not rescanned, and recovers when fixed")

# ---- (4)/(5) the registry parser (the real functions read from registry.py)
APP = Path(__file__).resolve().parent.parent / "framwork" / "tec_tac"
tree = ast.parse((APP / "registry.py").read_text(encoding="utf-8"))
want = {"_requires_framework_floor", "_scheduler_person_actions"}
body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in want]
body.insert(0, ast.parse("_PERSON_ACTIONS_MIN_FRAMEWORK = (1, 17, 80)").body[0])
ns = {"RegistryError": type("RegistryError", (Exception,), {}), "SYSTEM_ACTIONS_MAX": 20, "re": re, "_SYSTEM_ACTION_NAME_RE": re.compile(r"[a-z0-9][a-z0-9_-]*")}
exec(compile(ast.Module(body=body, type_ignores=[]), "registry.py", "exec"), ns)  # noqa: S102 - Core's own source
parse = ns["_scheduler_person_actions"]
ids = ["patchmanagement.notice"]
for requires in (None, {}, {"framework": ">=1.17.79,<2.0.0"}, {"framework": "<2.0.0"}, {"framework": ">=1.16.200"}, "x"):
    payload = {"scheduler_person_actions": ids} | ({} if requires is None else {"requires": requires})
    try:
        parse(payload, "extension", "patchmanagement")
    except ns["RegistryError"] as exc:
        must("1.17.80" in str(exc), exc)
        continue
    raise AssertionError(("accepted without the floor", requires))
for floor in (">=1.17.80,<2.0.0", ">=1.17.81", ">=1.18.0", ">=2.0.0", ">= 1.17.80"):
    must(parse({"scheduler_person_actions": ids, "requires": {"framework": floor}}, "extension", "patchmanagement") == tuple(ids), floor)
must(parse({"scheduler_person_actions": []}, "extension", "patchmanagement") == () and parse({}, "extension", "patchmanagement") == ())
apm = Path(__file__).resolve().parents[3] / "modules" / "patchmanagement" / "package" / "extensions" / "patchmanagement" / "tec_tac.json"
if apm.is_file():
    manifest = json.loads(apm.read_text(encoding="utf-8"))
    must(parse(manifest, "extension", "patchmanagement") == tuple(manifest["scheduler_person_actions"]), "APM's manifest parses")
print("       the key needs requires.framework >= 1.17.80; APM's manifest still parses")
print("PASS scheduler manifest cache 1.17.81")

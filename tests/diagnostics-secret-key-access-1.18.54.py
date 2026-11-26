#!/usr/bin/env python3
"""Regression: Core 1.18.54 check core.secret_store.service-access (no Django needed). The key file is only stat-ed, never opened."""
import ast
import builtins
import importlib
import logging
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "framwork" / "tec_tac"
package_stub = types.ModuleType("tec_tac")
package_stub.__path__ = [str(PKG_DIR)]
sys.modules["tec_tac"] = package_stub
di = importlib.import_module("tec_tac.diagnostics_install")

KEYS = {"id", "label", "status", "summary", "details", "help_id", "metadata"}
GID = 1001
SERVICES = ("rmm", "daphne", "celery", "celerybeat")


class KeyInfo:
    st_gid = GID


def make(pids, statuses):
    return (lambda unit: pids[unit.split(".")[0]] if not isinstance(pids[unit.split(".")[0]], Exception) else (_ for _ in ()).throw(pids[unit.split(".")[0]]),
            lambda pid: statuses[pid] if not isinstance(statuses[pid], Exception) else (_ for _ in ()).throw(statuses[pid]))


def run(pids, statuses, key_stat=lambda p: KeyInfo()):
    pid_reader, status_reader = make(pids, statuses)
    return di.secret_key_service_access_check(key_stat=key_stat, pid_reader=pid_reader, status_reader=status_reader)


WITH = "Name:\tx\nGroups:\t33 27 1001 \nUmask:\t0022\n"
WITHOUT = "Name:\tx\nGroups:\t33 \nUmask:\t0022\n"
pids = {"rmm": "11", "daphne": "12", "celery": "13", "celerybeat": "14"}

# the file is never opened: a fake open that raises must not be reached
real_open = builtins.open
builtins.open = lambda *a, **k: (_ for _ in ()).throw(AssertionError("the key file must never be opened"))
try:
    r = run(pids, {11: WITH, 12: WITH, 13: WITH, 14: WITH})
    assert set(r) == KEYS and r["id"] == "core.secret_store.service-access" and r["status"] == "pass", r
    assert [s["state"] for s in r["details"]["services"]] == ["ok"] * 4 and r["details"]["key_group_id"] == GID

    r = run(pids, {11: WITH, 12: WITHOUT, 13: WITH, 14: WITH})
    assert r["status"] == "fail" and "daphne.service" in r["summary"] and "rmm.service" not in r["summary"], r
    assert "installer" in r["summary"] and "restart" in r["summary"]
    assert {s["service"]: s["state"] for s in r["details"]["services"]}["daphne"] == "missing_group"

    r = run({**pids, "celerybeat": "0"}, {11: WITH, 12: WITH, 13: WITH})
    assert r["status"] == "pass" and r["metadata"]["services"]["celerybeat"] == "not_running", r

    r = run({k: "0" for k in pids}, {})
    assert r["status"] == "unknown", "nothing running is not a pass"

    r = run(pids, {11: WITH, 12: PermissionError(13, "denied"), 13: WITH, 14: WITH})
    assert r["status"] == "unknown" and "daphne" in r["summary"], r
    r = run(pids, {11: WITH, 12: "Name:\tx\n", 13: WITH, 14: WITH})
    assert r["status"] == "unknown", r
    r = run({**pids, "celery": OSError("no systemctl")}, {11: WITH, 12: WITH, 14: WITH})
    assert r["status"] == "unknown", r

    def broken_stat(path):
        raise FileNotFoundError(path)
    r = run(pids, {}, key_stat=broken_stat)
    assert r["status"] == "unknown" and "could not be inspected" in r["summary"], r
    r = di.secret_key_service_access_check(key_stat=lambda p: KeyInfo())
    assert r["status"] == "unknown", "no readers means unknown"
finally:
    builtins.open = real_open

text = repr(r) + repr(run(pids, {11: WITH, 12: WITHOUT, 13: WITH, 14: WITH}))
assert "master.key" not in text.replace("master key", ""), "no key path or content in the answer"

# containment: diagnostics.py wraps the check; a raising reader gives the 'could not run' row
source = (PKG_DIR / "diagnostics.py").read_text(encoding="utf-8")
tree = ast.parse(source)
wanted = {"_check", "_could_not_run", "_secret_key_access_check"}
funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted]
assert {f.name for f in funcs} == wanted
assert "_secret_key_access_check()" in source.split('_section("runtime"')[1].split("\n")[0], "wired into the runtime section"
log = logging.getLogger("t")
stub = types.ModuleType("tec_tac.diagnostics_install")


def boom(**kwargs):
    raise RuntimeError("secret path /x")


stub.secret_key_service_access_check = boom
sys.modules["tec_tac.diagnostics_install"] = stub
package_stub.diagnostics_install = stub
status_node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "STATUS_ORDER" for t in n.targets))
g = {"logger": log, "Any": object, "HELP_ID": "core.troubleshooting-diagnostics", "STATUS_ORDER": ast.literal_eval(status_node.value),
     "__name__": "tec_tac.diagnostics", "__package__": "tec_tac"}
exec(compile(ast.Module(body=funcs, type_ignores=[]), "diagnostics.py", "exec"), g)  # noqa: S102
row = g["_secret_key_access_check"]()
assert row["status"] == "unknown" and "could not run" in row["summary"] and "RuntimeError" in row["summary"] and "/x" not in row["summary"], row

print("diagnostics secret key access 1.18.54: PASS")

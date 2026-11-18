#!/usr/bin/env python3
"""Regression: Core 1.18.10 contains an unexpected error in the two install checks (no Django needed).

diagnostics.py imports Django, so the test parses it with ast and runs only the three small functions it needs."""
import ast
import logging
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "framwork" / "tec_tac" / "diagnostics.py").read_text(encoding="utf-8")
tree = ast.parse(SOURCE)
KEYS = {"id", "label", "status", "summary", "details", "help_id", "metadata"}
WANTED = {"_check", "_could_not_run", "_source_ownership_check", "_ui_module_sync_check"}
funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in WANTED]
assert {f.name for f in funcs} == WANTED
status_node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "STATUS_ORDER" for t in n.targets))
status_order = ast.literal_eval(status_node.value)
assert status_order["unknown"] == 1 and status_order["pass"] == 0 and status_order["fail"] == 2

records = []


class Capture(logging.Handler):
    def emit(self, record):
        records.append(record.getMessage())


log = logging.getLogger("diagnostics-test")
log.addHandler(Capture())
log.propagate = False

stub_config = types.ModuleType("tec_tac.config")
stub_install = types.ModuleType("tec_tac.diagnostics_install")
package = types.ModuleType("tec_tac")
package.__path__ = []
package.config, package.diagnostics_install = stub_config, stub_install
sys.modules.update({"tec_tac": package, "tec_tac.config": stub_config, "tec_tac.diagnostics_install": stub_install})


def namespace():
    module = ast.Module(body=funcs, type_ignores=[])
    ns = {"__name__": "tec_tac.diagnostics", "__package__": "tec_tac", "STATUS_ORDER": status_order, "logger": log, "Any": object}
    code = "from __future__ import annotations\n"
    exec(code, ns)
    exec(compile(ast.fix_missing_locations(module), "diagnostics.py", "exec", flags=0x0), ns)
    return ns


ns = namespace()


def check_row(row, check_id, label):
    assert isinstance(row, dict) and set(row) == KEYS, row
    assert row["id"] == check_id and row["label"] == label and row["status"] == "unknown", row
    assert row["help_id"] == "core.troubleshooting-diagnostics" and row["metadata"] == {} and row["details"] is None
    return row


def boom(exc):
    def raiser(*args, **kwargs):
        raise exc
    return raiser


SOURCE_ID, SOURCE_LABEL = "core.install.source-ownership", "Source folder ownership"
UI_ID, UI_LABEL = "core.ui.module-sync", "UI module sync"
failures = (ValueError("embedded null byte"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"), OSError("denied /secret/path"),
            RuntimeError("boom"))

for exc in failures:
    stub_config.load_layout = lambda: {}
    stub_install.source_ownership_check = boom(exc)
    records.clear()
    row = check_row(ns["_source_ownership_check"](), SOURCE_ID, SOURCE_LABEL)
    name = exc.__class__.__name__
    assert f"({name})" in row["summary"] and row["summary"].endswith("The rest of the report is unaffected."), row["summary"]
    assert str(exc) not in row["summary"] and "/secret/path" not in row["summary"]
    assert len(records) == 1 and name in records[0] and "/secret/path" not in records[0] and "null byte" not in records[0], records

    stub_install.ui_module_sync_check = boom(exc)
    records.clear()
    row = check_row(ns["_ui_module_sync_check"](), UI_ID, UI_LABEL)
    assert f"({name})" in row["summary"] and "/secret/path" not in row["summary"]
    assert len(records) == 1 and "/secret/path" not in records[0]

# an error inside load_layout (the local import's callee) or in the systemctl runner is contained too
stub_install.source_ownership_check = lambda load: load()
stub_config.load_layout = boom(ValueError("embedded null byte"))
check_row(ns["_source_ownership_check"](), SOURCE_ID, SOURCE_LABEL)


def ui_with_runner(load, systemctl_runner):
    return systemctl_runner("tec-tac-ui-sync-publish.path")


stub_install.ui_module_sync_check = ui_with_runner
stub_config.load_layout = lambda: {}
import subprocess  # noqa: E402

real_run = subprocess.run
subprocess.run = boom(UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"))
try:
    row = check_row(ns["_ui_module_sync_check"](), UI_ID, UI_LABEL)
    assert "(UnicodeDecodeError)" in row["summary"]
finally:
    subprocess.run = real_run

# a missing import is contained as well (the local imports sit inside the try)
del stub_install.source_ownership_check
row = check_row(ns["_source_ownership_check"](), SOURCE_ID, SOURCE_LABEL)
assert "(ImportError)" in row["summary"]
stub_install.source_ownership_check = lambda load: None

# healthy stubs pass their own row through unchanged
real_row = {"id": SOURCE_ID, "label": SOURCE_LABEL, "status": "pass", "summary": "fine", "details": [1], "help_id": "x", "metadata": {"a": 1}}
stub_install.source_ownership_check = lambda load: real_row
stub_install.ui_module_sync_check = lambda load, systemctl_runner: dict(real_row, id=UI_ID, label=UI_LABEL)
assert ns["_source_ownership_check"]() is real_row
assert ns["_ui_module_sync_check"]()["id"] == UI_ID and ns["_ui_module_sync_check"]()["status"] == "pass"

# a KeyboardInterrupt or SystemExit is not swallowed (only Exception)
stub_install.source_ownership_check = boom(KeyboardInterrupt())
try:
    ns["_source_ownership_check"]()
    raise AssertionError("KeyboardInterrupt was swallowed")
except KeyboardInterrupt:
    pass

# the real constants of diagnostics_install match the ids and labels used by the wrappers
install_text = (ROOT / "framwork" / "tec_tac" / "diagnostics_install.py").read_text(encoding="utf-8")
assert f'SOURCE_OWNERSHIP_ID = "{SOURCE_ID}"' in install_text and f'UI_SYNC_ID = "{UI_ID}"' in install_text
assert f'label = "{SOURCE_LABEL}"' in install_text and f'label = "{UI_LABEL}"' in install_text

# diagnostic_report still lists both wrappers in the runtime section, with the call line unchanged
assert "_helper_check(), _source_ownership_check(), _ui_module_sync_check()" in SOURCE
assert "import logging" in SOURCE and "logger = logging.getLogger(__name__)" in SOURCE
print("diagnostics containment 1.18.10: PASS")

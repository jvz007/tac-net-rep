#!/usr/bin/env python3
"""Regression: Core 1.18.9 install checks core.install.source-ownership and core.ui.module-sync (no Django needed)."""
import importlib
import re
import stat
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "framwork" / "tec_tac"
package_stub = types.ModuleType("tec_tac")
package_stub.__path__ = [str(PKG_DIR)]
sys.modules["tec_tac"] = package_stub
di = importlib.import_module("tec_tac.diagnostics_install")

DIR, REG, LNK = stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK
KEYS = {"id", "label", "status", "summary", "details", "help_id", "metadata"}


class Info:
    def __init__(self, kind, mode, uid=0, mtime=100.0):
        self.st_mode, self.st_uid, self.st_mtime = kind | mode, uid, mtime


def table(extra=None, drop=()):
    rows = {"/": Info(DIR, 0o755), "/opt": Info(DIR, 0o755), "/opt/tec-tac-src": Info(DIR, 0o755),
            "/opt/tec-tac-src/framework": Info(DIR, 0o755, 1000), "/opt/tec-tac-src/ui": Info(DIR, 0o755, 1000)}
    rows.update(extra or {})
    for key in drop:
        rows.pop(key, None)
    return rows


class Lstat:
    def __init__(self, rows, errors=None):
        self.rows, self.errors, self.calls = rows, errors or {}, []

    def __call__(self, path):
        self.calls.append(path)
        if path in self.errors:
            raise self.errors[path]
        if path not in self.rows:
            raise FileNotFoundError(path)
        return self.rows[path]


def own(rows, errors=None, layout=None):
    ls = Lstat(rows, errors)
    return di.source_ownership_check(lambda: layout or {}, ls), ls


r, ls = own(table())
assert set(r) == KEYS and r["id"] == "core.install.source-ownership" and r["status"] == "pass", r
assert r["help_id"] and isinstance(r["metadata"], dict)
assert ls.calls.count("/") == 1 and ls.calls.count("/opt") == 1, "folders are deduplicated"
r, _ = own(table({"/opt": Info(DIR, 0o755, 1000)}))
assert r["status"] == "fail" and r["summary"].startswith("/opt is not root-owned"), r
assert "sudo chown root:root /opt && sudo chmod 0755 /opt" in r["summary"], r
r, _ = own(table({"/opt/tec-tac-src": Info(DIR, 0o775)}))
assert r["status"] == "fail" and r["summary"].startswith("/opt/tec-tac-src is group or world writable"), r
r, _ = own(table({"/opt": Info(LNK, 0o777)}))
assert r["status"] == "fail" and "symbolic link" in r["summary"], r
r, _ = own(table(drop=("/opt/tec-tac-src/framework", "/opt/tec-tac-src/ui")))
assert r["status"] == "pass" and r["details"]["notes"], r
r, _ = own(table(), errors={"/opt": PermissionError(13, "Permission denied")})
assert r["status"] == "unknown" and "Permission denied" in r["summary"], r
r, _ = own(table({"/opt/tec-tac-src": Info(DIR, 0o775)}), errors={"/": PermissionError(13, "Permission denied")})
assert r["status"] == "fail", "a definite fail beats an unknown"
r, ls = own(table({"/srv": Info(DIR, 0o755), "/srv/x": Info(DIR, 0o755)}), layout={"TEC_TAC_UI_SOURCE": "/srv/x/ui"})
assert r["status"] == "pass" and "/srv/x" in ls.calls and "/srv" in ls.calls, "a custom checkout is checked too"
r, _ = own(table({"/srv": Info(DIR, 0o777)}), layout={"TEC_TAC_UI_SOURCE": "/srv/x/ui"})
assert r["status"] == "fail" and r["summary"].startswith("/srv is group or world writable"), r
r, _ = own(table({"/opt/tec-tac-src/ui": Info(LNK, 0o777, 1000)}))
assert r["status"] == "fail" and "/opt/tec-tac-src/ui" in r["summary"], "a linked checkout fails"


def broken_layout():
    raise OSError("no config")


r = di.source_ownership_check(broken_layout, Lstat(table()))
assert r["status"] == "unknown" and "no config" in r["summary"]

# --- UI module sync ---
SCRIPT = "/usr/local/lib/tec-tac-ui-sync/scripts/sync-modules.sh"
READER = "/usr/local/lib/tec-tac-ui-sync/scripts/tec-tac-config.sh"
VERSION = "/var/lib/tec-tac/ui/tec-tac/VERSION"


def sync_rows(extra=None):
    rows = {"/": Info(DIR, 0o755), "/usr": Info(DIR, 0o755), "/usr/local": Info(DIR, 0o755), "/usr/local/lib": Info(DIR, 0o755),
            "/usr/local/lib/tec-tac-ui-sync": Info(DIR, 0o755), "/usr/local/lib/tec-tac-ui-sync/scripts": Info(DIR, 0o755),
            SCRIPT: Info(REG, 0o755, 0, 200.0), READER: Info(REG, 0o644, 0, 200.0), VERSION: Info(REG, 0o644, 1000, 100.0)}
    rows.update(extra or {})
    return rows


def sync(rows=None, unit="enabled", errors=None, use_runner=True, layout=None):
    ls = Lstat(rows if rows is not None else sync_rows(), errors)
    calls = []

    def run(name):
        calls.append(name)
        if isinstance(unit, Exception):
            raise unit
        return {"state": unit}

    result = di.ui_module_sync_check(lambda: layout or {}, ls, run if use_runner else None, ls)
    return result, calls


r, calls = sync()
assert set(r) == KEYS and r["id"] == "core.ui.module-sync" and r["status"] == "pass", r
assert calls == ["tec-tac-ui-sync-publish.path"]
rows = sync_rows()
del rows[SCRIPT]
r, _ = sync(rows)
assert r["status"] == "fail" and "not published" in r["summary"], r
for bad in (Info(REG, 0o755, 1000, 200.0), Info(REG, 0o775, 0, 200.0), Info(LNK, 0o777, 0, 200.0), Info(REG, 0o644, 0, 200.0)):
    r, _ = sync(sync_rows({SCRIPT: bad}))
    assert r["status"] == "fail", bad.st_mode
r, _ = sync(sync_rows({"/usr/local/lib/tec-tac-ui-sync": Info(DIR, 0o775)}))
assert r["status"] == "fail" and "tec-tac-ui-sync" in r["summary"]
r, _ = sync(sync_rows({SCRIPT: Info(REG, 0o755, 0, 50.0)}))
assert r["status"] == "fail" and "older than the installed UI" in r["summary"], r
rows = sync_rows()
del rows[VERSION]
r, _ = sync(rows)
assert r["status"] == "unknown", r
for state in ("disabled", "masked", "not-found"):
    r, _ = sync(unit=state)
    assert r["status"] == "fail" and "not enabled" in r["summary"], state
r, _ = sync(unit=FileNotFoundError("systemctl"))
assert r["status"] == "unknown" and "FileNotFoundError" in r["summary"]
r, _ = sync(unit=TimeoutError("slow"))
assert r["status"] == "unknown"
r, _ = sync(use_runner=False)
assert r["status"] == "unknown"
r, _ = sync(unit="disabled", errors={"/usr": PermissionError(13, "denied")})
assert r["status"] == "fail", "one fail plus one unknown is fail"
r, _ = sync(layout={"UI_SYNC_SCRIPT": "/srv/sync/sync-modules.sh"})
assert r["status"] == "fail" and r["details"]["script"] == "/srv/sync/sync-modules.sh"
assert {p["part"] for p in r["details"]["parts"]} == {"published", "current", "path-unit"}

# --- source-text guards ---
src = (PKG_DIR / "diagnostics_install.py").read_text(encoding="utf-8")
assert "import subprocess" not in src and "os.system" not in src and "Popen" not in src and "sudoers" not in src
assert not re.search(r'\[\s*"sudo"', src), "the checks never run sudo"
helper = (ROOT / "scripts" / "system-update-helper.py").read_text(encoding="utf-8")
rule = "info.st_uid != 0 or info.st_mode & 0o022"
assert rule in helper and rule in src, "same rule text as open_source_checkout"
diag = (PKG_DIR / "diagnostics.py").read_text(encoding="utf-8")
assert "_helper_check(), _source_ownership_check(), _ui_module_sync_check()" in diag
assert diag.count('_section("runtime"') == 1
assert 'STATUS_ORDER = {"pass": 0, "warning": 1, "fail": 2, "unknown": 1}' in diag
assert '["systemctl", "is-enabled", unit]' in diag and "timeout=3" in diag and "sudo" not in diag
print("diagnostics install checks 1.18.9: PASS")

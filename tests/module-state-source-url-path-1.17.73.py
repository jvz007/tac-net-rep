#!/usr/bin/env python3
"""1.17.73 regression (external audit closure report, H2 follow-up): what module-state.json keeps of a repository address.

1.17.72 dropped the query, fragment, ';params' and user info. The path is kept. A token in the path therefore still reaches module-state.json,
which stays 0o644. That is the documented limit (docs/module-repositories.md), not a defect to fix in this release; Q-CORE-H2A and Q-CORE-H2B
are open for Johan. This test pins the limit across all four copies so nobody claims more than the code does, and checks the docstrings say so.

No Django, no root. What cannot run here: the helpers as root and a real state file owned by root.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


for _name, _attrs in {"fcntl": {"LOCK_EX": 2, "LOCK_SH": 1, "LOCK_UN": 8, "LOCK_NB": 4, "flock": lambda *a: None},
                      "pwd": {"getpwnam": lambda name: types.SimpleNamespace(pw_gid=0)}}.items():
    _module = types.ModuleType(_name)
    _module.__dict__.update(_attrs)
    sys.modules.setdefault(_name, _module)
for _shim in ("chown", "fchown", "fchmod"):
    if not hasattr(os, _shim):
        setattr(os, _shim, lambda *a, **k: None)
if not hasattr(os, "geteuid"):
    os.geteuid = lambda: 0

from tec_tac import module_repository as mrepo
from tec_tac import module_state as ms

LOOKUP = "TRUSTED_BASH = _resolve_trusted_bash()"


def load_helper(name):
    path = ROOT / "scripts" / name
    source = path.read_text(encoding="utf-8")
    must(source.count(LOOKUP) == 1, f"the trusted-bash line of {name} moved; update this test")
    module = types.ModuleType(name.replace("-", "_").replace(".py", ""))
    module.__file__ = str(path)
    exec(compile(source.replace(LOOKUP, 'TRUSTED_BASH = "/bin/bash"'), str(path), "exec"), module.__dict__)  # noqa: S102 - the helper under test
    return module


v1 = load_helper("module-job-helper.py")
v2 = load_helper("module-v2-job-helper.py")
v2.development_server = lambda: True


LIMIT = [
    # The documented limit: the path is kept, so a path token is kept. Not a defect to fix in this release.
    ("https://repo.example.com/t/SECRET/index.json?token=x#f", "https://repo.example.com/t/SECRET/index.json"),
    ("https://u:pw@repo.example.com/a/SECRET?x=1", "https://repo.example.com/a/SECRET"),
    ("https://repo.example.com/t/SECRET/index.json;p=1", "https://repo.example.com/t/SECRET/index.json"),
]
COPIES = {"core": ms.strip_repository_url, "repository": mrepo.strip_repository_url, "v1": v1.strip_repository_url, "v2": v2.strip_repository_url}
for given, expected in LIMIT:
    for label, function in COPIES.items():
        got = function(given)
        must(got == expected, f"{label}({given!r}) gave {got!r}, expected {expected!r}")
print("       all four copies keep a path token and drop query, fragment, params and user info")

PATH_URL = "https://repo.example.com/t/SECRET/index.json?token=x#f"
KEPT = "https://repo.example.com/t/SECRET/index.json"


def planted():
    return {"schema": 1, "modules": {"m": {"enabled": True, "version": "1.0.0", "source": {"repository_url": PATH_URL}}}}


TMP = Path(tempfile.mkdtemp(prefix="tectac-src-path-"))
MODES = []
folder = TMP / "core"
folder.mkdir()
ms.STATE_FILE, ms.STATE_LOCK = folder / "module-state.json", folder / "module-state.lock"
ms.STATE_LOCK.write_text("", encoding="utf-8")


def core_atomic(target, payload, *, mode=0o660, default=None):
    MODES.append(("core", mode))
    Path(target).write_text(json.dumps(payload, indent=2, sort_keys=True) + chr(10), encoding="utf-8")


ms.atomic_json = core_atomic
ms.save_state(planted())
text = ms.STATE_FILE.read_text(encoding="utf-8")
must(json.loads(text)["modules"]["m"]["source"]["repository_url"] == KEPT and "token=" not in text, text)
must("SECRET" in text, "documented limit: the path token reaches the file")

real_atomic = v2.atomic_json


def v2_atomic(path, payload, *args, **kw):
    MODES.append(("v2", kw.get("mode", args[0] if args else None)))
    return real_atomic(path, payload, *args, **kw)


v2.atomic_json = v2_atomic
v2.MODULE_STATE = TMP / "v2-module-state.json"
v2.MODULE_STATE.write_text(json.dumps(planted()), encoding="utf-8")
v2.set_enabled(["m"], False)
text = v2.MODULE_STATE.read_text(encoding="utf-8")
must(json.loads(text)["modules"]["m"]["source"]["repository_url"] == KEPT and "token=" not in text, text)
must("SECRET" in text, "documented limit: the path token reaches the file")
must(MODES == [("core", 0o644), ("v2", 0o644)], MODES)
print("       Core's save_state and the v2 helper write the path token to disk and the mode is still 0o644")

for name in ("framwork/tec_tac/module_state.py", "scripts/module-job-helper.py", "scripts/module-v2-job-helper.py"):
    source = (ROOT / name).read_text(encoding="utf-8")
    start = source.index("def strip_repository_url")
    doc = source[start:source.index('"""', source.index('"""', start) + 3)]
    must("never reaches" not in doc, f"{name}: the docstring still overclaims")
    must("path" in doc, f"{name}: the docstring does not mention the path")
print("       the three docstrings no longer say a token never reaches a file, and name the path")
print("module-state-source-url-path-1.17.73: PASS")

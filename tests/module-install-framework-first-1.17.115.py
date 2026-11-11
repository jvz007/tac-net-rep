#!/usr/bin/env python3
"""1.17.115 regression: a corrupt version file does not escape ``inspect_archive`` (held Low of the 1.17.113 review).

``module_manager_v2._runtime_versions`` read VERSION and the UI version file with ``read_text(encoding='utf-8')``, so bytes that are not UTF-8 raised
UnicodeDecodeError (a ValueError) out of ``inspect_archive`` as a 500. Covered, with the real module_manager.py, module_manager_v2.py and
registry.py and real files on disk: an undecodable VERSION or UI version file gives None for that component and raises nothing; an unreadable
VERSION with a clean manifest and with a bad-key manifest still reaches the later per-key refusal; ``_refuse_unmet_framework`` itself swallows a
ValueError; ``_check_runtime_requirements`` fails closed with 'version unavailable'; and the 1.17.113 cases are re-run by that test.
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules.setdefault(name, module)


_stub("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, LOCK_NB=4, flock=lambda *a: None)
_stub("pwd")
for _name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric"):
    _stub(_name)
_stub("cryptography.hazmat.primitives.serialization")
_stub("cryptography.hazmat.primitives.asymmetric.ed25519", Ed25519PublicKey=object)
_stub("cryptography.exceptions", InvalidSignature=Exception)

from tec_tac import module_manager, module_state, registry
from tec_tac import module_manager_v2 as v2

TMP = Path(tempfile.mkdtemp(prefix="tectac-framework-first-"))
EXT, REP = TMP / "extensions", TMP / "reportsets"
EXT.mkdir()
REP.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE
v2.load_state = lambda: STATE
module_manager.get_plugins = registry.get_plugins

FW, UI_FILE = TMP / "VERSION", TMP / "ui-version"
v2.FRAMEWORK_VERSION_FILE, v2.UI_VERSION_FILE = FW, UI_FILE
v2.UI_PACKAGE_FILE = TMP / "ui-package.json"
BAD = bytes([0xFF, 0xFE, 0x80, 0xC3, 0x28])  # not valid UTF-8
FLOOR = {"framework": ">=1.17.112,<2.0.0"}
COUNT = {"n": 0}


def package(name="fwmod", *, requires=None, bad_action=False):
    payload = {"id": name, "type": "extension", "version": "1.0.0", "name": name, "category": "server"}
    if requires is not None:
        payload["requires"] = requires
    if bad_action:
        payload["publisher_permissions"] = ["server_maintenance.register"]
        payload["permission_groups"] = {"Admin": [f"{name}.run"]}
        payload["server_maintenance_actions"] = [{"id": f"{name}.run", "permission": f"{name}.run", "bogus_key": True}]
    COUNT["n"] += 1
    path = TMP / f"{name}-{COUNT['n']}.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"extensions/{name}/tec_tac.json", json.dumps(payload))
    return path


def refusal(path):
    try:
        module_manager.inspect_archive(path)
    except module_manager.ModuleManagerError as exc:
        return str(exc)
    return None


# a good file is read as before
FW.write_text("1.17.115\n", encoding="utf-8")
UI_FILE.write_text("0.12.127\n", encoding="utf-8")
must(v2._runtime_versions() == {"framework": "1.17.115", "ui": "0.12.127"}, v2._runtime_versions())

# undecodable files give None and raise nothing
FW.write_bytes(BAD)
must(v2._runtime_versions() == {"framework": None, "ui": "0.12.127"}, "bad VERSION")
FW.write_text("1.17.115", encoding="utf-8")
UI_FILE.write_bytes(BAD)
must(v2._runtime_versions() == {"framework": "1.17.115", "ui": None}, "bad UI version")
UI_FILE.unlink()
v2.UI_PACKAGE_FILE.write_bytes(BAD)
must(v2._runtime_versions()["ui"] is None, "bad UI package file")
FW.write_text("   \n", encoding="utf-8")
must(v2._runtime_versions()["framework"] is None, "an empty VERSION is None")

# inspect_archive does not escape on a corrupt VERSION
FW.write_bytes(BAD)
must(refusal(package(requires=FLOOR)) is None, "a clean manifest passes the early check; the later checks decide")
text = refusal(package(requires=FLOOR, bad_action=True))
must(text is not None and "unsupported keys" in text, text)
must(module_manager.inspect_archive(package())["installable"] is True, "no requires")

# the early check swallows a ValueError from the read itself
real = v2._runtime_versions
def raising():
    raise UnicodeDecodeError("utf-8", bytes([0xFF]), 0, 1, "invalid start byte")
v2._runtime_versions = raising
must(refusal(package(requires=FLOOR)) is None, "ValueError is swallowed by _refuse_unmet_framework")
text = refusal(package(requires=FLOOR, bad_action=True))
must(text is not None and "unsupported keys" in text, text)
v2._runtime_versions = real

# the later check fails closed with a reason
rows = v2._check_runtime_requirements({"framework": ">=1.17.112"})
must(rows[0]["satisfied"] is False and rows[0]["reason"] == "version unavailable" and rows[0]["current"] is None, rows)

# an unmet floor is still named first when the file is fine
FW.write_text("1.17.111", encoding="utf-8")
text = refusal(package(requires=FLOOR, bad_action=True))
must(text is not None and "Tec-Tac Core 1.17.112" in text and "unsupported keys" not in text, text)

print("module-install-framework-first-1.17.115: ok")

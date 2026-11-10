#!/usr/bin/env python3
"""1.17.113 regression: an unmet ``requires.framework`` is refused first, with the Core version the module needs.

Request: Johan's install of certificatemanagement 0.4.2 (10 November 2026). The refusal said 'unsupported keys', which hid the real
reason (the server runs an older Core). Covered, with the real module_manager.py, module_manager_v2.py and registry.py:

* ``module_manager.inspect_archive`` refuses a package whose ``requires.framework`` is not met BEFORE the per-key checks: with a manifest
  that also carries a server_maintenance_actions entry with unsupported keys, a Core below the floor names 'Tec-Tac Core 1.17.112' and
  the running version and never says 'unsupported keys'; at the floor the old per-key refusal still appears (the order is proven both ways);
* a clean manifest passes at and above the floor; a manifest with no requires, a malformed constraint and an unreadable VERSION file fall
  through to the existing behaviour; a '<' bound that fails names the constraint; a framework-protected id is unaffected;
* ``registry.framework_requirement_problem`` itself; and ``registry.discover_plugins`` on the live roots still discovers a module whose
  floor is above the running version (start-up discovery is not changed).

What cannot run here: a Core that is actually installed under /opt/tec-tac.
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

RUNNING = {"framework": "1.17.111"}
v2._runtime_versions = lambda: {"framework": RUNNING["framework"], "ui": None}

COUNT = {"n": 0}


def package(name="fwmod", *, requires=None, bad_action=False, **extra):
    """A real zip package. ``bad_action`` adds a server_maintenance_actions entry with an unsupported key."""
    payload = {"id": name, "type": "extension", "version": "1.0.0", "name": name, "category": "server"}
    if requires is not None:
        payload["requires"] = requires
    if bad_action:
        payload["publisher_permissions"] = ["server_maintenance.register"]
        payload["permission_groups"] = {"Admin": [f"{name}.run"]}
        payload["server_maintenance_actions"] = [{"id": f"{name}.run", "permission": f"{name}.run", "bogus_key": True}]
    payload.update(extra)
    COUNT["n"] += 1
    path = TMP / f"{name}-{COUNT['n']}.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"extensions/{name}/tec_tac.json", json.dumps(payload))
    return path


def inspect(path):
    return module_manager.inspect_archive(path)


def refusal(path):
    try:
        inspect(path)
    except module_manager.ModuleManagerError as exc:
        return str(exc)
    return None


FLOOR = {"framework": ">=1.17.112,<2.0.0"}

# ---------------------------------------------------------------------------------------------- the order, both ways
RUNNING["framework"] = "1.17.111"
text = refusal(package(requires=FLOOR, bad_action=True))
must(text is not None and "Tec-Tac Core 1.17.112" in text and "1.17.111" in text, text)
must("unsupported keys" not in text and "or later" in text, text)
RUNNING["framework"] = "1.17.112"
text = refusal(package(requires=FLOOR, bad_action=True))
must(text is not None and "unsupported keys" in text and "Tec-Tac Core" not in text, text)

# ---------------------------------------------------------------------------------------------- a clean manifest
for version in ("1.17.112", "1.17.113", "1.18.0"):
    RUNNING["framework"] = version
    result = inspect(package(requires=FLOOR))
    must(result["id"] == "fwmod" and result["installable"] is True, (version, result))
RUNNING["framework"] = "1.17.111"
text = refusal(package(requires=FLOOR))
must(text is not None and "Tec-Tac Core 1.17.112 or later" in text and "this server runs 1.17.111" in text, text)

# ---------------------------------------------------------------------------------------------- a '<' bound names the constraint
RUNNING["framework"] = "2.1.0"
text = refusal(package(requires=FLOOR))
must(text is not None and "Tec-Tac Core >=1.17.112,<2.0.0" in text and "this server runs 2.1.0" in text and "or later" not in text, text)

# ---------------------------------------------------------------------------------------------- fall through to today's behaviour
RUNNING["framework"] = "1.17.111"
must(refusal(package()) is None, "no requires")
must(refusal(package(requires={"ui": ">=0.1.0"})) is None, "no framework entry")
must(refusal(package(requires={"framework": ">=banana"})) is None, "a malformed constraint is left to the later checks")
must(refusal(package(requires={"framework": ""})) is None, "an empty constraint")
must("unsupported keys" in (refusal(package(requires={"framework": ">=banana"}, bad_action=True)) or ""), "a malformed constraint does not hide the per-key check")
RUNNING["framework"] = None
must(refusal(package(requires=FLOOR)) is None, "an unreadable running version is left to the later checks")
must("unsupported keys" in (refusal(package(requires=FLOOR, bad_action=True)) or ""), "and the per-key check still runs")
RUNNING["framework"] = "not-a-version"
must(refusal(package(requires=FLOOR)) is None, "a running version that does not parse is left to the later checks")

# a framework-protected id is unaffected by the early check (it is refused for being protected, as before)
RUNNING["framework"] = "1.17.113"
protected = sorted(module_manager.PROTECTED_PLUGIN_IDS)[0]
result = inspect(package(protected, requires=FLOOR))
must(result["installable"] is False and result["protected"] is True, result)

# ---------------------------------------------------------------------------------------------- the helper
fn = registry.framework_requirement_problem
must(fn({"requires": {"framework": ">=1.17.112"}}, "1.17.112") is None, "met")
must(fn({"requires": {"framework": ">=1.17.112"}}, "1.17.111") == "needs Tec-Tac Core 1.17.112 or later; this server runs 1.17.111", "floor text")
must(fn({"requires": {"framework": ">=1.0.0,<2.0.0"}}, "3.0.0") == "needs Tec-Tac Core >=1.0.0,<2.0.0; this server runs 3.0.0", "constraint text")
must(fn({}, "1.0.0") is None and fn({"requires": []}, "1.0.0") is None and fn({"requires": {"framework": 5}}, "1.0.0") is None, "no constraint")
must(fn({"requires": {"framework": ">=1.17.112"}}, None) is None and fn({"requires": {"framework": ">=1.17.112"}}, "") is None, "no running version")

# ---------------------------------------------------------------------------------------------- start-up discovery is unchanged
live = EXT / "highfloor"
live.mkdir()
(live / "tec_tac.json").write_text(json.dumps({"id": "highfloor", "type": "extension", "version": "1.0.0", "name": "highfloor", "requires": {"framework": ">=9.0.0"}}), encoding="utf-8")
RUNNING["framework"] = "1.17.113"
found = registry.discover_plugins(EXT, REP)
must([p.plugin_id for p in found] == ["highfloor"], "a module whose floor is above the running Core still discovers at start-up")

print("module-install-framework-first-1.17.113: ok")

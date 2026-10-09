#!/usr/bin/env python3
"""1.17.10 regression: what a module registers at run time must match what its manifest declares (AD-20 parity).

Runs the real registry.py, module_state.py, module_replacement.py and capabilities.py against a temporary folder of
real manifests (fcntl stubbed, module state a dict). Django is not needed.
"""
from __future__ import annotations

import json
import logging
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


fcntl = types.ModuleType("fcntl")
fcntl.__dict__.update(LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
sys.modules.setdefault("fcntl", fcntl)

from tec_tac import capabilities as caps, module_replacement as mr, module_state, registry  # noqa: E402
from tec_tac import module_category  # noqa: E402
module_category.is_development_server = lambda: True  # AD-21 (1.17.13): these tests are about replacement, not about the category gate


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


CAPTURE = Capture()
for name in ("tec_tac.capabilities", "tec_tac.module_replacement"):
    logging.getLogger(name).addHandler(CAPTURE)
logging.getLogger("tec_tac.capabilities").setLevel(logging.WARNING)
logging.getLogger("tec_tac.module_replacement").addHandler(logging.NullHandler())

TMP = Path(tempfile.mkdtemp(prefix="tectac-registration-"))
EXT, REP = TMP / "extensions", TMP / "reportsets"
EXT.mkdir()
REP.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE


def manifest(module_id, **extra):
    folder = EXT / module_id
    folder.mkdir(parents=True, exist_ok=True)
    payload = {"id": module_id, "type": "extension", "version": "1.0.0"}
    payload.update(extra)
    if "replaces" in extra:
        payload.setdefault("category", "premium")  # AD-21 (1.17.13): a replacement is a premium module
    (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")


PATCHING = {"patching.windows": "1.2.0", "patching.scan": "1.0.0"}
manifest("patching", category="core", capabilities=PATCHING)
manifest("patchmanagement", replaces="patching", capabilities={**PATCHING, "patching.extra": "1.0.0"})
manifest("emptycore", category="core", capabilities={})
manifest("freecore", category="core")  # no capabilities key


def state(patching, patchmanagement):
    STATE["modules"] = {"patching": {"enabled": patching}, "patchmanagement": {"enabled": patchmanagement},
                        "emptycore": {"enabled": True}, "freecore": {"enabled": True}}


def register(cap, module, version="1.2.0"):
    return caps.register_capability(id=cap, module_id=module, version=version, provider=object())


def fresh():
    caps._clear_capabilities_for_tests()
    CAPTURE.messages.clear()


# 1. a core module that declares capabilities registers exactly those
fresh()
state(patching=True, patchmanagement=False)
reg = register("patching.windows", "patching")
must(caps._registration("patching.windows") is reg, "declared id registers")
reg = register("patching.rogue", "patching")  # declared map exists, id is not in it
must(caps._registration("patching.rogue") is None, "undeclared id is not stored")
must(reg.id == "patching.rogue" and reg.module_id == "patching", reg)
must(len([m for m in CAPTURE.messages if "patching.rogue" in m]) == 1, CAPTURE.messages)
register("patching.rogue", "patching")
must(len([m for m in CAPTURE.messages if "patching.rogue" in m]) == 1, "one warning per module and id")
row = caps.capability_status("patching.rogue")
must(row["state"] != "available", row)
must(row["available"] is False, row)
register("emptycore.thing", "emptycore")  # declared {} means nothing is declared
must(caps._registration("emptycore.thing") is None, "empty declared map registers nothing")

# 2. compat: a core module with no capabilities key keeps registering anything under its prefix
register("freecore.anything", "freecore")
must(caps._registration("freecore.anything") is not None, "no key, no change")
# Core's own ids are exempt
register("core.anything", "core")
register("tec-tac.anything", "tec-tac")
# the prefix rule still raises for a plain mistake
try:
    register("other.thing", "patching")
    raise AssertionError("prefix error expected")
except ValueError as exc:
    must("must begin with provider module prefix" in str(exc), exc)

# 3. an unreadable model lets a core-module registration through
fresh()
original = mr.live_model


def broken(*a, **k):
    raise registry.RegistryError("unreadable")


mr.live_model = broken
try:
    register("patching.rogue", "patching")
    must(caps._registration("patching.rogue") is not None, "unreadable model allows the core-module path")
finally:
    mr.live_model = original

# 4. honoured replacement: version rule
fresh()
state(patching=False, patchmanagement=True)
for version, reason in (("2.0.0", "capability-major-mismatch"), ("2", "capability-major-mismatch"), ("2.0", "capability-major-mismatch"),
                        ("2.0.0-1", "capability-major-mismatch"), ("0.1.0", "capability-major-mismatch"), ("1.1.9", "capability-version-lower")):
    reg = register("patching.windows", "patchmanagement", version)
    must(caps._registration("patching.windows") is None, f"{version} refused")
    must(reg.version == version, reg)
    rows = mr.replacement_status("patchmanagement")["registered_mismatch"]
    must(rows == [{"capability": "patching.windows", "declared": "1.2.0", "registered": version, "reason": reason}], rows)
status = mr.replacement_status("patchmanagement")
must(status["degraded"] is True and status["honoured"] is True, status)
must("patching.windows" in status["unregistered"], status)
must(any("patching.windows" in m and "1.2.0" in m for m in CAPTURE.messages), CAPTURE.messages)
cap = caps.capability_status("patching.windows")
must(cap["available"] is False and cap["state"] == "capability-unavailable", cap)
for version in ("1.2.0", "1.3.0", "1.2.0-1"):
    fresh()
    state(patching=False, patchmanagement=True)
    register("patching.windows", "patchmanagement", version)
    must(caps._registration("patching.windows") is not None, f"{version} accepted")
    must(mr.replacement_status("patchmanagement")["registered_mismatch"] == [], "no mismatch")
# a later correct registration clears the earlier refusal
fresh()
register("patching.windows", "patchmanagement", "1.1.0")
must(mr.registered_mismatches("patchmanagement"), "recorded")
register("patching.windows", "patchmanagement", "1.2.1")
must(mr.registered_mismatches("patchmanagement") == [], "cleared")
must(mr.version_within_declared("1.2.0", "1.2.0") is None and mr.version_within_declared("1.2.0", "2.0.0") == "capability-major-mismatch", "helper")
must(mr.version_within_declared("1.2.0", "1.1.9") == "capability-version-lower" and mr.version_within_declared("1.2.0", "1.2.1") is None, "helper")

# an unparsable registered version fails closed instead of slipping through
must(mr.version_within_declared("1.2.0", "2") == "capability-major-mismatch", "short major")
must(mr.version_within_declared("1.2.0", "2.0.0-1") == "capability-major-mismatch", "suffix")
must(mr.version_within_declared("1.2.0", "garbage") == "capability-major-mismatch", "garbage fails closed")

# 5. a replacement that is not honoured keeps the 1.17.9-1 warn-and-skip, and an undeclared id still raises
fresh()
for flags in ((True, True), (False, False)):
    state(patching=flags[0], patchmanagement=flags[1])
    register("patching.windows", "patchmanagement", "9.9.9")
    must(caps._registration("patching.windows") is None, "not stored")
    must(mr.registered_mismatches("patchmanagement") == [], "no mismatch row for a not-honoured replacement")
state(patching=False, patchmanagement=True)
try:
    register("patching.undeclared", "patchmanagement")
    raise AssertionError("prefix error expected")
except ValueError as exc:
    must("must begin with provider module prefix" in str(exc), exc)

print("[TEST] PASS 1.17.10 registration matches the manifest")

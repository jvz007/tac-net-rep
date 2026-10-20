#!/usr/bin/env python3
"""1.17.58 regression: a capability health check that re-enters capability_status cannot recurse (request of 17 October 2026).

Runs the real registry.py, module_state.py and capabilities.py against a temporary folder of manifests. Django is not needed.
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
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

from tec_tac import capabilities as caps, module_state, registry  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="tectac-health-reentrancy-"))
EXT, REP = TMP / "extensions", TMP / "reportsets"
EXT.mkdir()
REP.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE
IDS = ["a", "b"] + [f"c{i}" for i in range(10)]
for module_id in IDS:
    folder = EXT / module_id
    folder.mkdir()
    (folder / "tec_tac.json").write_text(json.dumps({"id": module_id, "type": "extension", "version": "1.0.0"}), encoding="utf-8")
    STATE["modules"][module_id] = {"enabled": True}


def register(module_id, health):
    return caps.register_capability(id=f"{module_id}.cap", module_id=module_id, version="1.0.0", provider=object(), health=health)


def follows(other):
    """A health callback that depends on another capability, as Licensing and Global Settings do."""
    def health():
        return caps.capability_status(f"{other}.cap")["available"]
    return health


caps._clear_capabilities_for_tests()
must(caps.MAX_HEALTH_DEPTH == 8, "the depth cap is 8")

# A -> B -> A
register("a", follows("b"))
register("b", follows("a"))
started = time.monotonic()
row_a = caps.capability_status("a.cap")
row_b = caps.capability_status("b.cap")
must(time.monotonic() - started < 1.0, "returns at once")
for row in (row_a, row_b):
    must(row["available"] is False and row["state"] == "unhealthy", row)  # the outer call sees the inner refusal as unhealthy
# the inner answer itself is the re-entrant one: ask for it from inside a callback
seen = []
caps._clear_capabilities_for_tests()
register("b", lambda: seen.append(caps.capability_status("a.cap")) or True)
register("a", lambda: seen.append(caps.capability_status("b.cap")) or True)
caps.capability_status("a.cap")
inner = seen[0]  # b's health ran inside a's and asked for a
must(len(seen) == 2, seen)
reentrant = [r for r in seen if r["state"] == "health-reentrant"]
must(len(reentrant) == 1, seen)
row = reentrant[0]
must(row["available"] is False and row["reason"] == "Capability health check re-entered: a.cap -> b.cap -> a.cap", row)
must("Traceback" not in row["reason"] and row["health"] == {}, row)

# get_capability on a re-entrant id raises CapabilityUnhealthy with state 'unhealthy'
caps._clear_capabilities_for_tests()
holder = {}


def reenter_via_get():
    try:
        caps.get_capability("a.cap")
    except caps.CapabilityError as exc:
        holder["exc"] = exc
    return True


register("a", reenter_via_get)
caps.capability_status("a.cap")
exc = holder["exc"]
must(isinstance(exc, caps.CapabilityUnhealthy) and exc.state == "unhealthy", type(exc))
must(exc.status["state"] == "health-reentrant" and "a.cap -> a.cap" in str(exc), exc.status)
must(caps._health_stack() == [], "empty after a refusal")

# depth cap: a chain of 10 distinct ids stops at 8 with the same state
caps._clear_capabilities_for_tests()
states = {}
for i in range(10):
    module_id = f"c{i}"
    nxt = f"c{i + 1}" if i < 9 else None

    def health(module_id=module_id, nxt=nxt):
        if nxt is None:
            return True
        inner = caps.capability_status(f"{nxt}.cap")
        states[nxt] = inner["state"]
        return inner["available"]

    register(module_id, health)
caps.capability_status("c0.cap")
must(states.get("c8") == "unhealthy" or "c8" in states, states)
cap_hits = [k for k, v in states.items() if v == "health-reentrant"]
must(cap_hits == ["c8"], states)  # c0..c7 are on the stack (8 ids), so c8 is refused
must(caps._health_stack() == [], "empty after the chain")

# an exception in a callback never leaves a stale id
caps._clear_capabilities_for_tests()


def boom():
    raise RuntimeError("provider text")


register("a", boom)
row = caps.capability_status("a.cap")
must(row["state"] == "unhealthy" and caps._health_stack() == [], row)
caps._clear_capabilities_for_tests()
register("a", lambda: True)
row = caps.capability_status("a.cap")
must(row["available"] is True and row["state"] == "available", row)

# a second thread is unaffected by a callback running in the first
caps._clear_capabilities_for_tests()
entered, release, result = threading.Event(), threading.Event(), {}


def slow():
    entered.set()
    release.wait(5)
    return True


register("a", slow)
worker = threading.Thread(target=lambda: result.setdefault("first", caps.capability_status("a.cap")))
worker.start()
entered.wait(5)
must(caps._health_stack() == [], "the other thread's stack is its own")
register("b", lambda: True)
must(caps.capability_status("b.cap")["available"] is True, "b is healthy on this thread")
release.set()
worker.join(5)
must(result["first"]["available"] is True, result)

# check_health=False is untouched
caps._clear_capabilities_for_tests()
register("a", follows("a"))
row = caps.capability_status("a.cap", check_health=False)
must(row["state"] == "health-unchecked" and row["health_checked"] is False, row)
print("[TEST] PASS capability health re-entrancy 1.17.58")

#!/usr/bin/env python3
"""1.17.6 regression: _take_bridge_back unregisters formerly forwarded models from Report Manager (held Low from 1.17.5).

Reuses the stub loader of tests/reporting-handover-1.17.4.py (everything before its first scenario), so the real
reporting.py runs against stubs. Django is not installed on the development PC.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
source = (HERE / "reporting-handover-1.17.4.py").read_text(encoding="utf-8")
marker = "# ------------------------------------------------------------------ (a)"
assert marker in source
H = {"__name__": "handover_helpers", "__file__": str(HERE / "reporting-handover-1.17.4.py")}
exec(compile(source.split(marker)[0], "reporting-handover-helpers", "exec"), H)  # noqa: S102 - our own test file
must, fresh, reg, healthy, marked = H["must"], H["fresh"], H["reg"], H["healthy"], H["marked"]
RegistryError = H["RegistryError"]
logging.disable(logging.NOTSET)


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


def forwarded(ids=("alerts", "scriptexecution")):
    env = fresh(report_manager="0.3.0")
    env.rep.install_tactical_reporting_bridge()
    healthy(env)
    reg(env, "ModuleAlert", "alerts", "tec_tac_alerts")
    reg(env, "ModuleAlertEvent", "alerts", "tec_tac_alerts")
    reg(env, "CheckReport", "checks", "tec_tac_checks")
    must(env.rep.reporting_bridge_status()["forwarded_models"] == 3, "three forwarded")
    env.provider.unregistered.clear()
    return env


def capture(env):
    handler = Capture()
    logging.getLogger("tec_tac.reporting").addHandler(handler)
    logging.getLogger("tec_tac.reporting").setLevel(logging.DEBUG)
    return handler


def done(handler):
    logging.getLogger("tec_tac.reporting").removeHandler(handler)


# 1. a forwarded registration is unregistered at take-back, in id order, with the module's source_module context
env = forwarded()
h = capture(env)
env.rep._take_bridge_back("test")
done(h)
ids = [call[0] for call in env.provider.unregistered]
must(ids == sorted(ids) and set(ids) == {"alerts.modulealert", "alerts.modulealertevent", "checks.checkreport"}, ids)
ctx = {call[0]: call[1] for call in env.provider.unregistered}
must(ctx["alerts.modulealert"]["source_module"] == "alerts" and ctx["checks.checkreport"]["source_module"] == "checks", ctx)
must(all(c["source_action"] == env.rep.SHIM_SOURCE_ACTION for c in ctx.values()), ctx)
st = env.rep.reporting_bridge_status()
must(st["installed"] is True and st["owner"] == "core" and st["forwarded_models"] == 0, st)
must(marked(env) == (True, True), "Core's bridge is installed after the calls")
# 6. a later unregister makes no second provider call
before = len(env.provider.unregistered)
must(env.rep.unregister_reporting_model("alerts.modulealert") is True, "unregister works")
must(len(env.provider.unregistered) == before, "no second provider call after take-back")

# 3. a provider that raises on one id does not stop the others or the bridge install
env = forwarded()
original = env.provider.unregister_model


def flaky(reporting_id=None, **kw):
    if reporting_id == "alerts.modulealertevent":
        raise RegistryError("core-bridge-active refuses unregister", state="core-bridge-active")
    return original(reporting_id, **kw)


env.provider.unregister_model = flaky
h = capture(env)
env.rep._take_bridge_back("test")
done(h)
must([c[0] for c in env.provider.unregistered] == ["alerts.modulealert", "checks.checkreport"], env.provider.unregistered)
must(any(r.levelno >= logging.ERROR and "alerts.modulealertevent" in r.getMessage() for r in h.records), "the failure is logged")
must(env.rep.reporting_bridge_status()["installed"] is True, "the bridge is installed despite the failure")

# 4. no provider (capability unavailable): one warning, bridge installed
env = forwarded()
env.cap.update(available=False, state="unhealthy", health={"healthy": False, "mode": "core-bridge-active"})
h = capture(env)
env.rep._take_bridge_back("test")
done(h)
must(env.provider.unregistered == [], "no call without a provider")
warns = [r for r in h.records if r.levelno == logging.WARNING and "not available to remove" in r.getMessage()]
must(len(warns) == 1, [r.getMessage() for r in h.records])
must(env.rep.reporting_bridge_status()["installed"] is True, "bridge installed")

# 5. pending-only fallback makes no provider call
env = fresh(report_manager="0.3.0")
env.rep.install_tactical_reporting_bridge()
reg(env, "ModuleAlert", "alerts", "tec_tac_alerts")  # capability unavailable: pending
must(env.rep.reporting_bridge_status()["pending_models"] == 1, env.rep.reporting_bridge_status())
healthy(env)
env.rep._take_bridge_back("test")
must(env.provider.unregistered == [], "pending-only: no provider call")
must(env.rep.reporting_bridge_status()["installed"] is True, "bridge installed")

# nothing forwarded: no lookup noise, nothing raised
env = fresh()
env.rep._take_bridge_back("test")
must(env.provider.unregistered == [], "nothing to do")

# docs
docs = (HERE.parent / "docs" / "module-reporting.md").read_text(encoding="utf-8")
must("1.17.6" in docs and "best-effort `unregister_model`" in docs, "docs describe the take-back unregister")
print("reporting takeback unregister 1.17.6: ok")

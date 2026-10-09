#!/usr/bin/env python3
"""1.17.5 regression: the installer check and the fallback for already forwarded registrations.

Two held findings from the 1.17.4 review:
  Medium: install.sh asserted `not s['error']`, so Report Manager owning the bridge but reporting unhealthy made the
          installer fail and the update helper roll back a healthy Core. Status now carries bridge_error and
          handover_error; the installer asserts only bridge_error.
  Low:    _take_bridge_back() left _FORWARDED set, so registrations forwarded at ready() were served by neither bridge.

Django is not installed on the development PC. The harness (stubs for django, the capability registry and a fake
ee.reporting package) is the one in tests/reporting-handover-1.17.4.py, loaded by executing the part of that file
that precedes its first scenario.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "reporting-handover-1.17.4.py"
source = HARNESS.read_text(encoding="utf-8")
marker = "# ------------------------------------------------------------------ (a)"
H = {"__file__": str(HARNESS), "__name__": "handover_harness"}
exec(compile(source[: source.index(marker)], "reporting-handover-1.17.4.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse of the 1.17.x harness
must, fresh, reg, healthy, marked = H["must"], H["fresh"], H["reg"], H["healthy"], H["marked"]
ROOT, APP = H["ROOT"], H["APP"]

# ------------------------------------------------------------------ installer snippet (the VERIFY_REPORTING_CODE line)
script = (ROOT / "install.sh").read_text(encoding="utf-8")
line = next(item for item in script.splitlines() if item.startswith("VERIFY_REPORTING_CODE="))
code = line[len('VERIFY_REPORTING_CODE="'):-1]
must("s['error']" not in code and "s['bridge_error']" in code, "the installer asserts bridge_error, not the combined error")
must("assert s['installed'] or s['handover']" in code, "the installer keeps the installed-or-handover assertion")


def verify(env):
    sys.modules.update(env.mods)
    sys.modules["tec_tac.reporting"] = env.rep
    sys.modules["tec_tac"].reporting = env.rep
    exec(compile(code, "VERIFY_REPORTING_CODE", "exec"), {})  # noqa: S102 - test-only run of the install.sh check


def refuses(env, why):
    try:
        verify(env)
    except AssertionError:
        return
    raise AssertionError(why)


UNHEALTHY = {"available": False, "state": "unhealthy", "reason": "bridge not owned", "health": {"healthy": False, "mode": "report-manager"}}

# the unhealthy Report Manager state passes the installer and still shows the error
env = fresh(report_manager="0.3.0", cap_state=UNHEALTHY)
env.rep.install_tactical_reporting_bridge()
status = env.rep.settle_reporting_bridge()
must(status["installed"] is False and status["handover"] is True and status["fallback"] is False, status)
must(status["error"] == "bridge not owned" and status["bridge_error"] is None and status["handover_error"] == "bridge not owned", status)
must(marked(env) == (False, False) and env.constants.REPORTING_MODELS is H["NATIVE"], "nothing patched")
verify(env)

# normal, handover and fallback states still pass
env = fresh()
env.rep.install_tactical_reporting_bridge()
verify(env)
env = fresh(report_manager="0.3.0")
env.rep.install_tactical_reporting_bridge()
verify(env)
env.rep.settle_reporting_bridge()  # capability absent: fallback
must(env.rep.reporting_bridge_status()["fallback"] is True, "fallback")
verify(env)

# the check is not weakened: Core's own bridge error still fails it, in every state
env = fresh()
env.rep._BRIDGE_ERROR = "broken"
st = env.rep.reporting_bridge_status()
must(st["bridge_error"] == "broken" and st["handover_error"] is None and st["error"] == "broken", st)
refuses(env, "a Core bridge error must fail the install check")
env = fresh(report_manager="0.3.0", cap_state=UNHEALTHY)
env.rep.install_tactical_reporting_bridge()
env.rep.settle_reporting_bridge()
env.rep._BRIDGE_ERROR = "broken too"
refuses(env, "a Core bridge error must fail the install check even with a handover error")
env = fresh()
env.rep.install_tactical_reporting_bridge()
env.views.QuerySchema.get = lambda self, request: None
refuses(env, "a lost marker must still fail when Core claims installed")

# status keys: the 1.17.4 set plus the two new ones; error is their combination
OLD, NEW = H["OLD_KEYS"], H["NEW_KEYS"]
must({"bridge_error", "handover_error"} <= NEW, "the 1.17.4 harness lists the new keys")
for label, env in (("normal", fresh()), ("handover", fresh(report_manager="0.3.0")), ("unhealthy", fresh(report_manager="0.3.0", cap_state=UNHEALTHY))):
    env.rep.install_tactical_reporting_bridge()
    env.rep.settle_reporting_bridge()
    st = env.rep.reporting_bridge_status()
    must(set(st) == OLD | NEW, (label, set(st) ^ (OLD | NEW)))
    must(st["error"] == (st["bridge_error"] or st["handover_error"]), (label, st))

# the contract text lists both keys and says error is their combination
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
contracts = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in n.targets))
purpose = next(r["purpose"] for r in contracts if r["name"] == "reporting_bridge_status")
must("bridge_error" in purpose and "handover_error" in purpose and "error is their combination" in purpose, purpose)
docs = (ROOT / "docs" / "module-reporting.md").read_text(encoding="utf-8")
must("`bridge_error`" in docs and "`handover_error`" in docs, "docs list the new keys")

# ------------------------------------------------------------------ fallback keeps registrations already forwarded
FALL = {"available": False, "state": "unhealthy", "reason": "core owns it", "health": {"healthy": False, "mode": "core-bridge-active"}}


def forwarded_env():
    env = fresh(report_manager="0.3.0")
    env.rep.install_tactical_reporting_bridge()
    healthy(env)
    plain = reg(env, "ModuleAlert")
    hidden = reg(env, "CheckReport", "checks", "tec_tac_checks", hidden_fields=["secret"])
    must(plain["forwarded"] is True and hidden["forwarded"] is True, (plain, hidden))
    st = env.rep.reporting_bridge_status()
    must(st["owner"] == "reportmanager" and st["forwarded_models"] == 2, st)
    return env


def fall_back(env, how):
    if how == "unavailable":
        env.cap.update(FALL)
    else:  # the provider's health callback raises: capability_status itself fails

        def boom(*args, **kwargs):
            raise RuntimeError("health callback raised")

        env.mods["tec_tac.capabilities"].capability_status = boom
    return env.rep.settle_reporting_bridge()


for how in ("unavailable", "health raises"):
    env = forwarded_env()
    st = fall_back(env, how)
    at_takeback = len(env.provider.unregistered)  # 1.17.6: take-back may call the provider once per former forwarded id
    must(st["fallback"] is True and st["installed"] is True and st["owner"] == "core" and st["forwarded_models"] == 0, (how, st))
    must(st["error"] is None, (how, st))
    must(marked(env) == (True, True), f"{how}: Core's bridge is installed again")
    must(("ModuleAlert", "tec_tac_alerts") in env.constants.REPORTING_MODELS, f"{how}: the plain model is served by Core")
    must(("CheckReport", "tec_tac_checks") not in env.constants.REPORTING_MODELS, f"{how}: hidden_fields model is not exposed")
    row = env.rep.reporting_model_status("alerts.modulealert")
    must(row["available"] is True and row["state"] == "available" and row["forwarded"] is False, (how, row))
    bad = env.rep.reporting_model_status("checks.checkreport")
    must(bad["available"] is False and bad["state"] == "hidden-fields-unavailable" and bad["forwarded"] is False, (how, bad))
    listed = {r["id"]: r for r in env.rep.list_reporting_models()}
    must(listed["alerts.modulealert"]["state"] == "available" and listed["checks.checkreport"]["state"] == "hidden-fields-unavailable", listed)
    must(not any(r["state"] == "report-manager-unavailable" for r in listed.values()), "no registration is left unserved")
    # unregistering a former forwarded model must not call the provider, even if Report Manager is healthy again
    env.cap.update(available=True, state="available", health={"healthy": True, "mode": "report-manager"})
    must(env.rep.unregister_reporting_model("alerts.modulealert") is True, "unregister works")
    must(len(env.provider.unregistered) == at_takeback, f"{how}: the provider is not called again for a former forwarded model after take-back")
    must(("ModuleAlert", "tec_tac_alerts") not in env.constants.REPORTING_MODELS, "the allow-list drops it")

# no fallback: a healthy capability at settle leaves them forwarded
env = forwarded_env()
healthy(env)
st = env.rep.settle_reporting_bridge()
must(st["owner"] == "reportmanager" and st["forwarded_models"] == 2 and st["fallback"] is False and st["installed"] is False, st)
must(all(r["forwarded"] for r in env.rep.list_reporting_models()), "still forwarded")
must(marked(env) == (False, False) and env.constants.REPORTING_MODELS is H["NATIVE"], "Core patches nothing")
env.rep.unregister_reporting_model("alerts.modulealert")
must(len(env.provider.unregistered) == 1, "a still forwarded model is removed from Report Manager")

print("reporting installer fix 1.17.5: ok")

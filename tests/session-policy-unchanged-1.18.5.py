#!/usr/bin/env python3
"""Regression: tectac_session_policy writes no audit row when the policy does not change (Core 1.18.5)."""
import ast
import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CMD = ROOT / "framwork" / "tec_tac" / "management" / "commands" / "tectac_session_policy.py"
assert b"\r" not in CMD.read_bytes()


class CommandError(Exception):
    pass


class BaseCommand:
    def __init__(self):
        self.out = []
        self.stdout = types.SimpleNamespace(write=self.out.append)


class SessionSecurityError(RuntimeError):
    pass


rec = {"update": []}
state = {"ip_change_policy": "audit", "idle_timeout_minutes": 30}


def _update(policy, *, requested_by=""):
    rec["update"].append((policy, requested_by))
    if policy["ip_change_policy"] not in ("off", "audit", "reauthenticate", "terminate"):
        raise SessionSecurityError("ip_change_policy must be off, audit, reauthenticate, or terminate.")
    state["ip_change_policy"] = policy["ip_change_policy"]


def stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


stub("django")
stub("django.core")
stub("django.core.management")
stub("django.core.management.base", BaseCommand=BaseCommand, CommandError=CommandError)
pkg = types.ModuleType("tec_tac")
pkg.__path__ = []
sys.modules["tec_tac"] = pkg
spec = importlib.util.spec_from_file_location("tectac_session_policy_u", CMD)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert "tec_tac.session_security" not in sys.modules
src = CMD.read_text(encoding="utf-8")
top = [n for n in ast.parse(src).body if isinstance(n, (ast.Import, ast.ImportFrom))]
assert all(getattr(n, "module", "") == "django.core.management.base" for n in top)
pkg.session_security = stub(
    "tec_tac.session_security",
    SessionSecurityError=SessionSecurityError,
    _update_global_policy=_update,
    get_effective_policy=lambda user=None, request=None: dict(state),
)


def run(**opts):
    rec["update"].clear()
    cmd = mod.Command()
    cmd.handle(**{"show": False, "ip_change": None, **opts})
    return cmd.out


# (a) unchanged
state["ip_change_policy"] = "audit"
out = run(ip_change="audit")
assert rec["update"] == [], rec
text = "\n".join(out)
assert "ip_change_policy unchanged: audit" in text
assert "changed:" not in text.replace("unchanged:", "") and "audit row" not in text, text

# (b) changed
state["ip_change_policy"] = "audit"
out = run(ip_change="off")
assert rec["update"] == [({"ip_change_policy": "off"}, mod.ACTOR_LABEL)], rec
assert any("audit -> off" in line for line in out), out

# (c) unchanged with --show
state["ip_change_policy"] = "audit"
out = run(ip_change="audit", show=True)
assert rec["update"] == []
assert out[0] == "ip_change_policy unchanged: audit" and out[1] == "ip_change_policy: audit", out

# (d) every value
for value in mod.IP_CHANGE_CHOICES:
    state["ip_change_policy"] = value
    run(ip_change=value)
    assert rec["update"] == [], value
    state["ip_change_policy"] = "off" if value != "off" else "terminate"
    run(ip_change=value)
    assert len(rec["update"]) == 1 and rec["update"][0][0] == {"ip_change_policy": value}, value

# no current value: treated as changed
state.pop("ip_change_policy")
run(ip_change="audit")
assert len(rec["update"]) == 1
state["ip_change_policy"] = "audit"

# (e) invalid value
try:
    run(ip_change="bogus")
    raise AssertionError("invalid value accepted")
except CommandError:
    pass
print("session policy unchanged 1.18.5 regression: PASS")

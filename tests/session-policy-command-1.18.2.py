#!/usr/bin/env python3
"""Regression: tectac_session_policy sets the session IP-change policy through the audited path (Core 1.18.2)."""
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

    def add_arguments(self, parser):
        pass


class SessionSecurityError(RuntimeError):
    pass


rec = {"update": []}
state = {"ip_change_policy": "reauthenticate", "idle_timeout_minutes": 30}


def _update(policy, *, requested_by=""):
    rec["update"].append((policy, requested_by))
    if policy["ip_change_policy"] not in ("off", "audit", "reauthenticate", "terminate"):
        raise SessionSecurityError("ip_change_policy must be off, audit, reauthenticate, or terminate.")
    state["ip_change_policy"] = policy["ip_change_policy"]
    return dict(state)


def _get(user=None, request=None):
    return dict(state)


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

spec = importlib.util.spec_from_file_location("tectac_session_policy_t", CMD)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert "tec_tac.session_security" not in sys.modules
src = CMD.read_text(encoding="utf-8")
top = [n for n in ast.parse(src).body if isinstance(n, (ast.Import, ast.ImportFrom))]
assert all(getattr(n, "module", "") == "django.core.management.base" for n in top), "only the Django base import at top level"

ss = stub(
    "tec_tac.session_security",
    SessionSecurityError=SessionSecurityError,
    _update_global_policy=_update,
    get_effective_policy=_get,
)
pkg.session_security = ss

assert mod.IP_CHANGE_CHOICES == ("off", "audit", "reauthenticate", "terminate")
for value in mod.IP_CHANGE_CHOICES:
    rec["update"].clear()
    mod.Command().handle(show=False, ip_change=value)
    assert rec["update"] == [({"ip_change_policy": value}, mod.ACTOR_LABEL)], rec
    assert "server command" in rec["update"][0][1]

try:
    mod.Command().handle(show=False, ip_change=None)
    raise AssertionError("missing option accepted")
except CommandError:
    pass

rec["update"].clear()
try:
    mod.Command().handle(show=False, ip_change="bogus")
    raise AssertionError("invalid value accepted")
except CommandError as exc:
    assert "ip_change_policy" in str(exc)

rec["update"].clear()
cmd = mod.Command()
cmd.handle(show=True, ip_change=None)
assert rec["update"] == [] and cmd.out[0].startswith("ip_change_policy:"), cmd.out

state["ip_change_policy"] = "reauthenticate"
cmd = mod.Command()
cmd.handle(show=True, ip_change="off")
assert any("reauthenticate -> off" in line for line in cmd.out), cmd.out
assert any(line.startswith("ip_change_policy: off") for line in cmd.out), cmd.out

assert "urlpatterns" not in src and "path(" not in src and "re_path" not in src

views = (ROOT / "framwork" / "tec_tac" / "session_security_views.py").read_text(encoding="utf-8")
assert "_update_global_policy(payload, requested_by=request.user.username)" in views
assert "_update_global_policy(" in src
assert "session_policy_changed" in (ROOT / "framwork" / "tec_tac" / "session_security.py").read_text(encoding="utf-8")

print("session policy command 1.18.2 regression: PASS")

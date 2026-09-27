#!/usr/bin/env python3
"""D6a regression: account-guard compatibility failure must not abort AppConfig.ready()."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

root = Path(__file__).resolve().parents[1]

# Package shell.
pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(root / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg

# Minimal Django stubs used by apps.py.
class AppConfig:
    pass

class Pattern:
    def __init__(self, route):
        self.pattern = route

def path(route, target):
    return Pattern(route)

def include(value):
    return value

django = types.ModuleType("django")
django_apps = types.ModuleType("django.apps")
django_urls = types.ModuleType("django.urls")
django_apps.AppConfig = AppConfig
django_urls.path = path
django_urls.include = include
sys.modules["django"] = django
sys.modules["django.apps"] = django_apps
sys.modules["django.urls"] = django_urls

calls = {"fallback": 0, "reporting": 0, "api_guarded": False}

def stub_module(name, **attrs):
    mod = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    sys.modules[name] = mod
    return mod

stub_module("tec_tac.session_security", register_core_session_security_capability=lambda: None)
stub_module("tec_tac.server_backup", register_core_server_backup_capability=lambda: None)
stub_module("tec_tac.server_maintenance", register_core_server_maintenance_capability=lambda: None)
stub_module("tec_tac.resources", register_core_resources_capability=lambda: None)
stub_module("tec_tac.reporting", install_tactical_reporting_bridge=lambda: calls.__setitem__("reporting", calls["reporting"] + 1))

def precise_guard():
    raise AttributeError("simulated missing Tactical Reset2FA self-service view")

def fallback_guard():
    calls["fallback"] += 1
    # The real fallback is regression-tested in tactical-superuser-guard.py.
    # Here we assert AppConfig actually reaches that recovery path when one
    # self-service compatibility target is missing.
    calls["api_guarded"] = True
    return True

# Precise guard and fail-closed fallback are separate modules.  Simulate an
# import/compatibility failure in the precise module while keeping the fallback
# independently importable.
stub_module("tec_tac.tactical_account_guard", install_tactical_account_guard=precise_guard)
stub_module(
    "tec_tac.tactical_account_guard_fallback",
    install_tactical_account_guard_fail_closed=fallback_guard,
)

tacticalrmm = types.ModuleType("tacticalrmm")
tactical_urls = types.ModuleType("tacticalrmm.urls")
tactical_urls.urlpatterns = []
tacticalrmm.urls = tactical_urls
sys.modules["tacticalrmm"] = tacticalrmm
sys.modules["tacticalrmm.urls"] = tactical_urls

spec = importlib.util.spec_from_file_location("tec_tac.apps", root / "framwork" / "tec_tac" / "apps.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

# Must not propagate the simulated precise-guard failure.
mod.TecTacFrameworkConfig().ready()
assert calls["fallback"] == 1, "fail-closed account guard was not installed"
assert calls["api_guarded"] is True, "API-key fail-closed recovery path was not reached"
assert calls["reporting"] == 1, "AppConfig.ready stopped after guard compatibility failure"
assert len(tactical_urls.urlpatterns) == 1, "Core route registration did not continue"
print("apps-ready-startup-safety: PASS")

#!/usr/bin/env python3
"""D6a regression: precise-guard import failure cannot take out fallback guard."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg

class AppConfig:
    pass

class Pattern:
    def __init__(self, route): self.pattern = route

def path(route, target): return Pattern(route)
def include(value): return value

django = types.ModuleType("django")
django_apps = types.ModuleType("django.apps")
django_urls = types.ModuleType("django.urls")
django_apps.AppConfig = AppConfig
django_urls.path = path
django_urls.include = include
sys.modules.update({"django": django, "django.apps": django_apps, "django.urls": django_urls})

calls = {"fallback": 0, "reporting": 0}

def stub(name, **attrs):
    mod = types.ModuleType(name)
    for key, value in attrs.items(): setattr(mod, key, value)
    sys.modules[name] = mod
    return mod

stub("tec_tac.session_security", register_core_session_security_capability=lambda: None)
stub("tec_tac.server_backup", register_core_server_backup_capability=lambda: None)
stub("tec_tac.server_maintenance", register_core_server_maintenance_capability=lambda: None)
stub("tec_tac.resources", register_core_resources_capability=lambda: None)
stub("tec_tac.reporting", install_tactical_reporting_bridge=lambda: calls.__setitem__("reporting", calls["reporting"] + 1))

# A module object without install_tactical_account_guard makes the local from-import
# fail exactly where apps.py must catch it.
stub("tec_tac.tactical_account_guard")
stub(
    "tec_tac.tactical_account_guard_fallback",
    install_tactical_account_guard_fail_closed=lambda: calls.__setitem__("fallback", calls["fallback"] + 1) or True,
)

tacticalrmm = types.ModuleType("tacticalrmm")
tactical_urls = types.ModuleType("tacticalrmm.urls")
tactical_urls.urlpatterns = []
tacticalrmm.urls = tactical_urls
sys.modules.update({"tacticalrmm": tacticalrmm, "tacticalrmm.urls": tactical_urls})

spec = importlib.util.spec_from_file_location("tec_tac.apps", ROOT / "framwork" / "tec_tac" / "apps.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

mod.TecTacFrameworkConfig().ready()
assert calls["fallback"] == 1, "separate fallback was not reached after precise import failure"
assert calls["reporting"] == 1, "startup stopped after precise guard import failure"
assert len(tactical_urls.urlpatterns) == 1, "Core route registration did not continue"
print("d6a-guard-import-isolation: PASS")

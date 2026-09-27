#!/usr/bin/env python3
"""D6a regression: Tec-Tac bootstrap failures degrade, never abort Tactical startup."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

root = Path(__file__).resolve().parents[1]

# Minimal Django app-registry stubs needed by bootstrap.py.
class FakeApps:
    pass

django_apps = object()

def original_populate(self, installed_apps=None):
    return list(installed_apps or [])

FakeApps.populate = original_populate

django = types.ModuleType("django")
django_apps_mod = types.ModuleType("django.apps")
django_registry_mod = types.ModuleType("django.apps.registry")
django_apps_mod.apps = django_apps
django_registry_mod.Apps = FakeApps
sys.modules["django"] = django
sys.modules["django.apps"] = django_apps_mod
sys.modules["django.apps.registry"] = django_registry_mod

pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(root / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg

class RegistryError(RuntimeError):
    pass

class ModuleStateError(RuntimeError):
    pass

state = {"failure": "registry"}

registry = types.ModuleType("tec_tac.registry")
registry.RegistryError = RegistryError

def get_plugins():
    if state["failure"] == "registry":
        raise RegistryError("broken registry")
    return [object()]

registry.get_plugins = get_plugins
registry.iter_python_paths = lambda plugins: []
sys.modules["tec_tac.registry"] = registry

module_state = types.ModuleType("tec_tac.module_state")
module_state.ModuleStateError = ModuleStateError

def filter_enabled_plugins(plugins):
    if state["failure"] == "state":
        raise ModuleStateError("broken module state")
    return plugins

module_state.filter_enabled_plugins = filter_enabled_plugins
sys.modules["tec_tac.module_state"] = module_state

spec = importlib.util.spec_from_file_location("tec_tac.bootstrap", root / "framwork" / "tec_tac" / "bootstrap.py")
bootstrap = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bootstrap
spec.loader.exec_module(bootstrap)

for failure in ("registry", "state"):
    state["failure"] = failure
    FakeApps.populate = original_populate
    # Must not raise even though extension discovery/state is corrupt.
    bootstrap.load_extensions()
    assert getattr(FakeApps.populate, "_tec_tac_extension_loader", False)
    installed = ["tactical.base"]
    result = FakeApps.populate(django_apps, installed)
    assert "tec_tac.apps.TecTacFrameworkConfig" in result
    assert result.count("tec_tac.apps.TecTacFrameworkConfig") == 1

apps_source = (root / "framwork" / "tec_tac" / "apps.py").read_text()
assert "install_tactical_account_guard_fail_closed" in apps_source
assert "except Exception:" in apps_source
assert "Tec-Tac precise Tactical account guard failed" in apps_source

print("startup-safety: PASS")

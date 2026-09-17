"""Tec-Tac bootstrap for Tactical RMM extensions.

Loaded from Tactical's ignored local_settings.py. The framework owns extension
path discovery and Django app registration so Tactical tracked source remains
untouched.
"""

import sys
from pathlib import Path

from django.apps import apps as django_apps
from django.apps.registry import Apps


TEC_TAC_ROOT = Path("/opt/tec-tac")
EXTENSIONS_ROOT = TEC_TAC_ROOT / "extensions"

# POC extension registry. Add future extension descriptors here, not in
# Tactical's local_settings.py.
EXTENSIONS = (
    {
        "name": "reporting",
        "python_path": EXTENSIONS_ROOT / "reporting",
        "django_apps": ("tfdreporting.apps.TfdreportingConfig",),
    },
)


def _register_extension_paths() -> None:
    for extension in EXTENSIONS:
        path = str(extension["python_path"])
        if path not in sys.path:
            sys.path.insert(0, path)


def load_extensions() -> None:
    """Register Tec-Tac extension paths and Django apps once per process."""
    _register_extension_paths()

    if getattr(Apps.populate, "_tec_tac_extension_loader", False):
        return

    original_populate = Apps.populate

    def tec_tac_populate(self, installed_apps=None):
        if self is django_apps and installed_apps is not None:
            installed_apps = list(installed_apps)

            for extension in EXTENSIONS:
                for app_config in extension["django_apps"]:
                    if app_config not in installed_apps:
                        installed_apps.append(app_config)

        return original_populate(self, installed_apps)

    tec_tac_populate._tec_tac_extension_loader = True
    Apps.populate = tec_tac_populate

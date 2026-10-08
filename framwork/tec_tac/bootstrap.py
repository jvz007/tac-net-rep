"""Upgrade-safe Tec-Tac bootstrap with Module Management v2 enable state."""
import logging
import sys
from django.apps import apps as django_apps
from django.apps.registry import Apps
from tec_tac.module_state import ModuleStateError, filter_enabled_plugins

from tec_tac.registry import RegistryError, get_plugins, iter_python_paths

logger = logging.getLogger("tec_tac.bootstrap")

FRAMEWORK_APP = "tec_tac.apps.TecTacFrameworkConfig"

def _register_plugin_paths(plugins):
    for plugin_path in iter_python_paths(plugins):
        path = str(plugin_path)
        if path not in sys.path:
            sys.path.insert(0, path)

def load_extensions():
    # Tec-Tac extensions are additive. A corrupt/invalid extension registry or
    # module-state file must never prevent Tactical itself from starting.
    try:
        plugins = filter_enabled_plugins(get_plugins())
    except (RegistryError, ModuleStateError):
        logger.exception(
            "Tec-Tac extension discovery failed; starting Tactical with Core only and no extension apps"
        )
        plugins = []
    _register_plugin_paths(plugins)
    if getattr(Apps.populate, "_tec_tac_extension_loader", False):
        return
    original_populate = Apps.populate
    def tec_tac_populate(self, installed_apps=None):
        if self is django_apps and installed_apps is not None:
            installed_apps = list(installed_apps)
            if FRAMEWORK_APP not in installed_apps:
                installed_apps.append(FRAMEWORK_APP)
            for plugin in plugins:
                for app_config in plugin.django_apps:
                    if app_config not in installed_apps:
                        installed_apps.append(app_config)
        result = original_populate(self, installed_apps)
        if self is django_apps and installed_apps is not None:
            # 1.17.4: every AppConfig.ready() has run, in any process (web, celery, shell). Settle the reporting
            # handover here: replay pending registrations to Report Manager, or take Core's bridge back.
            try:
                from tec_tac.reporting import settle_reporting_bridge

                settle_reporting_bridge()
            except Exception:
                logger.exception("Tec-Tac reporting handover could not settle; Tactical starts regardless")
        return result
    tec_tac_populate._tec_tac_extension_loader = True
    Apps.populate = tec_tac_populate

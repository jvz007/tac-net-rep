"""Upgrade-safe Tec-Tac bootstrap with Module Management v2 enable state."""
import sys
from django.apps import apps as django_apps
from django.apps.registry import Apps
from tec_tac.module_state import filter_enabled_plugins

from tec_tac.registry import get_plugins, iter_python_paths

FRAMEWORK_APP = "tec_tac.apps.TecTacFrameworkConfig"

def _register_plugin_paths(plugins):
    for plugin_path in iter_python_paths(plugins):
        path = str(plugin_path)
        if path not in sys.path:
            sys.path.insert(0, path)

def load_extensions():
    plugins = filter_enabled_plugins(get_plugins())
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
        return original_populate(self, installed_apps)
    tec_tac_populate._tec_tac_extension_loader = True
    Apps.populate = tec_tac_populate

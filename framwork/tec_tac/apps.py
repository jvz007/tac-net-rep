from django.apps import AppConfig
from django.urls import include, path


class TecTacFrameworkConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "tec_tac"
    verbose_name = "Tec-Tac Framework"

    def ready(self):
        # Framework-owned privileged capabilities are registered before module
        # AppConfig.ready() consumers resolve them. The provider exposes only
        # typed operations; privileged execution remains in the root helper.
        from .session_security import register_core_session_security_capability
        from .server_backup import register_core_server_backup_capability
        from .server_maintenance import register_core_server_maintenance_capability
        from .resources import register_core_resources_capability
        from .reporting import install_tactical_reporting_bridge
        from .tactical_account_guard import install_tactical_account_guard
        register_core_session_security_capability()
        register_core_server_backup_capability()
        register_core_server_maintenance_capability()
        register_core_resources_capability()

        # Tactical's native role/account editors can otherwise grant effective
        # superuser authority to mid-level managers. Install the Core-owned,
        # authenticated mutation guard without modifying upstream Tactical code.
        install_tactical_account_guard()

        # Core owns the compatibility boundary with Tactical Report Manager.
        # Install this before module AppConfig.ready() registrations execute so
        # modules never need to import ee.reporting internals themselves.
        install_tactical_reporting_bridge()

        # Register framework-owned API routes in memory. This deliberately
        # avoids editing Tactical's tracked tacticalrmm/urls.py file.
        from tacticalrmm import urls as tactical_urls

        route_prefix = "api/tfd/"
        route_exists = any(
            str(getattr(pattern, "pattern", "")) == route_prefix
            for pattern in tactical_urls.urlpatterns
        )
        if not route_exists:
            tactical_urls.urlpatterns.append(
                path(route_prefix, include("tec_tac.urls"))
            )

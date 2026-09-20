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
        from .server_backup import register_core_server_backup_capability
        register_core_server_backup_capability()

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

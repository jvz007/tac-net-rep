from django.apps import AppConfig
from django.urls import include, path


class TecTacFrameworkConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "tec_tac"
    verbose_name = "Tec-Tac Framework"

    def ready(self):
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

from django.apps import AppConfig
from django.urls import include, path

class TecTacPackageTestConfig(AppConfig):
    default_auto_field="django.db.models.BigAutoField"
    name="tec_tac_packagetest"
    label="tec_tac_packagetest"
    verbose_name="Tec-Tac Package Test"
    def ready(self):
        from tacticalrmm import urls as tactical_urls
        route_prefix="api/tfd/packagetest/"
        if not any(str(getattr(pattern,"pattern","")) == route_prefix for pattern in tactical_urls.urlpatterns):
            tactical_urls.urlpatterns.append(path(route_prefix, include("tec_tac_packagetest.urls")))

from django.apps import AppConfig


class TfdreportingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "tfdreporting"

    def ready(self):
        reporting_models = (
            ("NetworkAvailability", "tfdreporting"),
        )

        # Tactical Report Manager keeps an allow-list of Django models.
        # Extend that registry in memory so no Tactical source file is changed.
        from ee.reporting import constants

        for entry in reporting_models:
            if entry not in constants.REPORTING_MODELS:
                constants.REPORTING_MODELS += (entry,)

        # ee.reporting.utils imports REPORTING_MODELS directly. Update its
        # module-level reference as well in case it has already been imported.
        from ee.reporting import utils

        for entry in reporting_models:
            if entry not in utils.REPORTING_MODELS:
                utils.REPORTING_MODELS += (entry,)

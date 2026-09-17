from django.apps import AppConfig


class TecTacExampleExtensionConfig(AppConfig):
    """Reference AppConfig for a Tec-Tac extension plugin."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "tec_tac_example_extension"
    verbose_name = "Tec-Tac Example Extension"

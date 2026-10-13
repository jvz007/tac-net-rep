from django.db import migrations, models


class Migration(migrations.Migration):
    """The system name an authenticator shows, as a runtime setting (1.17.23). Additive: one text column, default "Tec-Tac".

    The existing row reads "Tec-Tac". Existing authenticator entries keep working: only new set-ups carry the name."""

    dependencies = [
        ("tec_tac", "0026_runtime_upload_limit"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacruntimeconfig",
            name="system_name",
            field=models.CharField(default="Tec-Tac", max_length=60),
        ),
    ]

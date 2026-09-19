# Generated for Tec-Tac Framework 1.13.9
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0003_scheduler_model_options"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacUserPreferences",
            fields=[
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name="tec_tac_preferences",
                        serialize=False,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                ("preferences", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Tec-Tac user preferences",
                "verbose_name_plural": "Tec-Tac user preferences",
            },
        ),
    ]

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0021_saved_views"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacRuntimeConfig",
            fields=[
                ("singleton", models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ("module_register_timeout_seconds", models.PositiveIntegerField(default=30)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="tec_tac_runtime_config_updates", to=settings.AUTH_USER_MODEL)),
            ],
            options={"verbose_name": "Tec-Tac runtime configuration"},
        ),
    ]

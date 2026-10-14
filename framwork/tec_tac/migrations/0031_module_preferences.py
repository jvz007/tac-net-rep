from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    """Module user preferences (Core 1.17.35, core.module_preferences 1.0.0): one per-person choice a module keeps through Core.

    Additive: one new table. Nothing existing changes. Written by hand, because Django is not installed on the development PC. Check it
    with `manage.py makemigrations --check --dry-run` on the dev server; the model and this file must agree."""

    dependencies = [
        ("tec_tac", "0030_notice_ledger"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacModulePreference",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("module_id", models.CharField(max_length=100)),
                ("name", models.CharField(max_length=64)),
                ("value", models.JSONField()),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="tec_tac_module_preferences", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddConstraint(
            model_name="tectacmodulepreference",
            constraint=models.UniqueConstraint(fields=("user", "module_id", "name"), name="tectac_modpref_unique"),
        ),
    ]

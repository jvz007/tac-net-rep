from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):
    """Core 1.17.97: ``TecTacRemovedSchedule``, the memory that an administrator removed a module-owned schedule. A new table, no data migration.
    Written by hand, because Django is not installed on the development PC; check it with `manage.py makemigrations --check --dry-run` on the dev
    server: the model and this file must agree."""

    dependencies = [
        ("tec_tac", "0042_clear_monthly_fields_non_monthly"),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacRemovedSchedule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("owner_module", models.CharField(max_length=100)),
                ("owner_key", models.CharField(max_length=255)),
                ("removed_by_username", models.CharField(blank=True, default="", max_length=150)),
                ("removed_at", models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.AddConstraint(
            model_name="tectacremovedschedule",
            constraint=models.UniqueConstraint(fields=("owner_module", "owner_key"), name="tectac_removed_sched_unique"),
        ),
    ]

from django.db import migrations, models


class Migration(migrations.Migration):
    """Core 1.17.86: ``TecTacSchedule.paused_reason``, set while a module the schedule belongs to is disabled. Additive, blank by default, no data
    migration. Written by hand, because Django is not installed on the development PC; check it with `manage.py makemigrations --check --dry-run`."""

    dependencies = [
        ("tec_tac", "0039_run_started_by"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacschedule",
            name="paused_reason",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
    ]

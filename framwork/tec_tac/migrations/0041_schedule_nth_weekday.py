from django.db import migrations, models


class Migration(migrations.Migration):
    """Core 1.17.88: ``TecTacSchedule.month_week`` and ``month_weekday``, for a monthly schedule that runs on the nth weekday of the month.
    Additive and nullable, no data migration: every existing schedule keeps ``day_of_month``. Written by hand, because Django is not installed
    on the development PC; check it with `manage.py makemigrations --check --dry-run`."""

    dependencies = [
        ("tec_tac", "0040_schedule_paused_reason"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacschedule",
            name="month_week",
            field=models.SmallIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="tectacschedule",
            name="month_weekday",
            field=models.PositiveSmallIntegerField(blank=True, null=True),
        ),
    ]

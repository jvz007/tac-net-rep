from django.db import migrations


def clear_monthly_fields(apps, schema_editor):
    """Core 1.17.90: a schedule that is not monthly holds none of day_of_month, month_week and month_weekday. Older rows may keep a stale one."""
    Schedule = apps.get_model("tec_tac", "TecTacSchedule")
    Schedule.objects.exclude(schedule_type="monthly").update(day_of_month=None, month_week=None, month_weekday=None)


class Migration(migrations.Migration):
    """Data only, no model change. Not reversible in a useful way: the cleared values had no effect."""

    dependencies = [
        ("tec_tac", "0041_schedule_nth_weekday"),
    ]

    operations = [
        migrations.RunPython(clear_monthly_fields, migrations.RunPython.noop),
    ]

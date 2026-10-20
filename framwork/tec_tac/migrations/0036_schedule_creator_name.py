from django.db import migrations, models


class Migration(migrations.Migration):
    """The names of the person who created a schedule and the person who last confirmed it (Core 1.17.63, CQ179 b).

    Additive: two blank text columns on ``TecTacSchedule``. No data migration: a row made before this one reads its creator from
    ``created_by`` (``scheduler.schedule_creator_names``). Written by hand, because Django is not installed on the development PC.
    Check it with `manage.py makemigrations --check --dry-run` on the dev server; the model and this file must agree."""

    dependencies = [
        ("tec_tac", "0035_server_job_hook"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacschedule",
            name="created_by_username",
            field=models.CharField(blank=True, default="", max_length=150),
        ),
        migrations.AddField(
            model_name="tectacschedule",
            name="confirmed_by_username",
            field=models.CharField(blank=True, default="", max_length=150),
        ),
    ]

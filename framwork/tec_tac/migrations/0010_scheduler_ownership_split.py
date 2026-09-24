from django.db import migrations, models


def classify_existing_schedules(apps, schema_editor):
    Schedule = apps.get_model("tec_tac", "TecTacSchedule")
    Run = apps.get_model("tec_tac", "TecTacScheduleRun")
    Schedule.objects.exclude(owner_module="").update(owner_type="module")
    for run in Run.objects.select_related("schedule").iterator():
        schedule = run.schedule
        if schedule is None:
            continue
        run.owner_type = schedule.owner_type
        run.owner_module = schedule.owner_module
        run.owner_key = schedule.owner_key
        run.save(update_fields=["owner_type", "owner_module", "owner_key"])


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0009_user_notice_center")]

    operations = [
        migrations.AddField(
            model_name="tectacschedule",
            name="owner_type",
            field=models.CharField(choices=[("user", "User"), ("module", "Module")], default="user", max_length=16),
        ),
        migrations.AddField(
            model_name="tectacschedulerun",
            name="owner_type",
            field=models.CharField(choices=[("user", "User"), ("module", "Module")], default="user", max_length=16),
        ),
        migrations.AddField(
            model_name="tectacschedulerun",
            name="owner_module",
            field=models.CharField(blank=True, default="", max_length=100),
        ),
        migrations.AddField(
            model_name="tectacschedulerun",
            name="owner_key",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.RunPython(classify_existing_schedules, migrations.RunPython.noop),
        migrations.AddIndex(
            model_name="tectacschedule",
            index=models.Index(fields=["owner_type", "enabled"], name="tectac_sched_owner_type_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacschedulerun",
            index=models.Index(fields=["owner_type", "created_at"], name="tectac_run_owner_type_idx"),
        ),
    ]

from django.db import migrations, models


def backfill_run_snapshots(apps, schema_editor):
    Run = apps.get_model("tec_tac", "TecTacScheduleRun")
    for run in Run.objects.select_related("schedule").all().iterator():
        schedule = run.schedule
        if schedule is None:
            continue
        run.target_mode_snapshot = schedule.target_mode
        run.parameters_snapshot = schedule.parameters or {}
        run.retry_count_snapshot = schedule.retry_count
        run.retry_delay_seconds_snapshot = schedule.retry_delay_seconds
        run.save(update_fields=[
            "target_mode_snapshot", "parameters_snapshot",
            "retry_count_snapshot", "retry_delay_seconds_snapshot",
        ])


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0012_mfa_backup_totp_binding")]

    operations = [
        migrations.AddField(
            model_name="tectacschedulerconfig", name="run_retention_days",
            field=models.PositiveIntegerField(default=90),
        ),
        migrations.AddField(
            model_name="tectacschedulerconfig", name="queued_stale_minutes",
            field=models.PositiveIntegerField(default=10),
        ),
        migrations.AddField(
            model_name="tectacschedulerun", name="target_mode_snapshot",
            field=models.CharField(max_length=16, choices=[("snapshot", "Snapshot"), ("dynamic", "Dynamic")], default="snapshot"),
        ),
        migrations.AddField(
            model_name="tectacschedulerun", name="parameters_snapshot",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="tectacschedulerun", name="retry_count_snapshot",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="tectacschedulerun", name="retry_delay_seconds_snapshot",
            field=models.PositiveIntegerField(default=60),
        ),
        migrations.RunPython(backfill_run_snapshots, migrations.RunPython.noop),
    ]

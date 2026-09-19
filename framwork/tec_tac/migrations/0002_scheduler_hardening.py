# Generated for Tec-Tac Framework 1.11.0
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def snapshot_runs(apps, schema_editor):
    Run = apps.get_model("tec_tac", "TecTacScheduleRun")
    for run in Run.objects.select_related("schedule").all().iterator():
        schedule = run.schedule
        if not schedule:
            continue
        run.schedule_snapshot_id = schedule.id
        run.schedule_name = schedule.name
        run.module_id = schedule.module_id
        run.action_id = schedule.action_id
        run.save(update_fields=["schedule_snapshot_id", "schedule_name", "module_id", "action_id"])


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0001_scheduler"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(
            name="TecTacSchedulerConfig",
            fields=[
                ("singleton", models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ("once_retention_hours", models.PositiveIntegerField(default=48)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="tec_tac_scheduler_config_updates", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name="TecTacSchedulerState",
            fields=[
                ("singleton", models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ("last_tick_at", models.DateTimeField(blank=True, null=True)),
                ("last_tick_completed_at", models.DateTimeField(blank=True, null=True)),
                ("last_tick_error", models.TextField(blank=True, default="")),
                ("last_checked", models.PositiveIntegerField(default=0)),
                ("last_queued", models.PositiveIntegerField(default=0)),
                ("last_skipped", models.PositiveIntegerField(default=0)),
                ("last_cleaned", models.PositiveIntegerField(default=0)),
                ("last_dispatch_at", models.DateTimeField(blank=True, null=True)),
                ("last_dispatch_error", models.TextField(blank=True, default="")),
            ],
        ),
        migrations.AddField(model_name="tectacschedulerun", name="schedule_snapshot_id", field=models.UUIDField(blank=True, db_index=True, null=True)),
        migrations.AddField(model_name="tectacschedulerun", name="schedule_name", field=models.CharField(blank=True, default="", max_length=255)),
        migrations.AddField(model_name="tectacschedulerun", name="module_id", field=models.CharField(blank=True, default="", max_length=100)),
        migrations.AddField(model_name="tectacschedulerun", name="action_id", field=models.CharField(blank=True, default="", max_length=160)),
        migrations.RunPython(snapshot_runs, migrations.RunPython.noop),
        migrations.AlterField(model_name="tectacschedulerun", name="schedule", field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="runs", to="tec_tac.tectacschedule")),
    ]

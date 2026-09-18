# Generated for Tec-Tac Framework 1.8.0
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    initial = True
    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(
            name="TecTacSchedule",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=255)),
                ("module_id", models.CharField(max_length=100)),
                ("action_id", models.CharField(max_length=160)),
                ("target_mode", models.CharField(choices=[("snapshot", "Snapshot"), ("dynamic", "Dynamic")], default="snapshot", max_length=16)),
                ("targets", models.JSONField(blank=True, default=dict)),
                ("parameters", models.JSONField(blank=True, default=dict)),
                ("schedule_type", models.CharField(choices=[("once", "Once"), ("daily", "Daily"), ("weekly", "Weekly"), ("monthly", "Monthly")], default="once", max_length=16)),
                ("timezone", models.CharField(default="UTC", max_length=64)),
                ("run_at", models.DateTimeField(blank=True, null=True)),
                ("run_time", models.TimeField(blank=True, null=True)),
                ("weekdays", models.JSONField(blank=True, default=list)),
                ("day_of_month", models.PositiveSmallIntegerField(blank=True, null=True)),
                ("enabled", models.BooleanField(default=True)),
                ("missed_policy", models.CharField(choices=[("skip", "Skip"), ("run_on_recovery", "Run on recovery"), ("expire", "Expire")], default="skip", max_length=24)),
                ("missed_grace_minutes", models.PositiveIntegerField(default=60)),
                ("concurrency_policy", models.CharField(choices=[("skip", "Skip while running"), ("queue", "Queue"), ("allow", "Allow overlap")], default="skip", max_length=16)),
                ("retry_count", models.PositiveSmallIntegerField(default=0)),
                ("retry_delay_seconds", models.PositiveIntegerField(default=60)),
                ("last_due_key", models.CharField(blank=True, default="", max_length=80)),
                ("last_run_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="tec_tac_schedules_created", to=settings.AUTH_USER_MODEL)),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="tec_tac_schedules_updated", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ("name", "id")},
        ),
        migrations.CreateModel(
            name="TecTacScheduleRun",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("status", models.CharField(choices=[("queued", "Queued"), ("running", "Running"), ("succeeded", "Succeeded"), ("failed", "Failed"), ("skipped", "Skipped")], default="queued", max_length=16)),
                ("scheduled_for", models.DateTimeField()),
                ("manual", models.BooleanField(default=False)),
                ("targets_snapshot", models.JSONField(blank=True, default=dict)),
                ("result", models.JSONField(blank=True, default=dict)),
                ("error", models.TextField(blank=True, default="")),
                ("error_type", models.CharField(blank=True, default="", max_length=120)),
                ("celery_task_id", models.CharField(blank=True, default="", max_length=80)),
                ("attempt", models.PositiveSmallIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("schedule", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="runs", to="tec_tac.tectacschedule")),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.AddIndex(model_name="tectacschedule", index=models.Index(fields=["enabled", "schedule_type"], name="tectac_sched_enabled_idx")),
        migrations.AddIndex(model_name="tectacschedule", index=models.Index(fields=["module_id", "action_id"], name="tectac_sched_action_idx")),
        migrations.AddIndex(model_name="tectacschedulerun", index=models.Index(fields=["schedule", "status"], name="tectac_run_status_idx")),
        migrations.AddIndex(model_name="tectacschedulerun", index=models.Index(fields=["scheduled_for"], name="tectac_run_due_idx")),
    ]

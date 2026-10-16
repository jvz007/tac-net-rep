import uuid

from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):
    """Event jobs (Core 1.17.45, core.event_jobs 1.0.0): the durable rows of module jobs started by an event, and their counters.

    Additive: two new tables. Nothing existing changes. Written by hand, because Django is not installed on the development PC. Check it
    with `manage.py makemigrations --check --dry-run` on the dev server; the models and this file must agree."""

    dependencies = [
        ("tec_tac", "0031_module_preferences"),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacEventJob",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("module_id", models.CharField(max_length=100)),
                ("job_id", models.CharField(max_length=160)),
                ("key", models.CharField(max_length=128)),
                ("payload", models.JSONField(blank=True, default=dict)),
                ("policy", models.JSONField(blank=True, default=dict)),
                ("status", models.CharField(choices=[("pending", "Pending"), ("running", "Running"), ("succeeded", "Succeeded"), ("failed", "Failed"), ("skipped", "Skipped"), ("expired", "Expired")], default="pending", max_length=16)),
                ("attempt", models.PositiveSmallIntegerField(default=0)),
                ("max_attempts", models.PositiveSmallIntegerField(default=3)),
                ("next_attempt_at", models.DateTimeField(blank=True, null=True)),
                ("expires_at", models.DateTimeField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_enqueued_at", models.DateTimeField(blank=True, null=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("error_type", models.CharField(blank=True, default="", max_length=120)),
                ("error", models.CharField(blank=True, default="", max_length=255)),
                ("result", models.JSONField(blank=True, default=dict)),
                ("celery_task_id", models.CharField(blank=True, default="", max_length=80)),
            ],
            options={"ordering": ("created_at",)},
        ),
        migrations.CreateModel(
            name="TecTacEventJobStat",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("module_id", models.CharField(max_length=100)),
                ("job_id", models.CharField(max_length=160)),
                ("published", models.PositiveBigIntegerField(default=0)),
                ("duplicate", models.PositiveBigIntegerField(default=0)),
                ("dropped", models.PositiveBigIntegerField(default=0)),
                ("dropped_reported", models.PositiveBigIntegerField(default=0)),
                ("dropped_day", models.PositiveBigIntegerField(default=0)),
                ("dropped_day_started", models.DateTimeField(blank=True, null=True)),
                ("succeeded", models.PositiveBigIntegerField(default=0)),
                ("failed", models.PositiveBigIntegerField(default=0)),
                ("expired", models.PositiveBigIntegerField(default=0)),
                ("skipped", models.PositiveBigIntegerField(default=0)),
                ("last_failure_at", models.DateTimeField(blank=True, null=True)),
                ("last_error", models.CharField(blank=True, default="", max_length=255)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AddIndex(
            model_name="tectaceventjob",
            index=models.Index(fields=["status", "next_attempt_at"], name="tectac_evjob_due_idx"),
        ),
        migrations.AddIndex(
            model_name="tectaceventjob",
            index=models.Index(fields=["module_id", "job_id", "status"], name="tectac_evjob_job_idx"),
        ),
        migrations.AddConstraint(
            model_name="tectaceventjob",
            constraint=models.UniqueConstraint(condition=Q(("status__in", ("pending", "running"))), fields=("module_id", "job_id", "key"), name="tectac_evjob_active_key"),
        ),
        migrations.AddConstraint(
            model_name="tectaceventjobstat",
            constraint=models.UniqueConstraint(fields=("module_id", "job_id"), name="tectac_evjobstat_unique"),
        ),
    ]

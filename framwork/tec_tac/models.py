from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q


class TecTacSchedule(models.Model):
    class ScheduleType(models.TextChoices):
        ONCE = "once", "Once"
        DAILY = "daily", "Daily"
        WEEKLY = "weekly", "Weekly"
        MONTHLY = "monthly", "Monthly"
        INTERVAL = "interval", "Interval"

    class TargetMode(models.TextChoices):
        SNAPSHOT = "snapshot", "Snapshot"
        DYNAMIC = "dynamic", "Dynamic"

    class MissedPolicy(models.TextChoices):
        SKIP = "skip", "Skip"
        RUN_ON_RECOVERY = "run_on_recovery", "Run on recovery"
        EXPIRE = "expire", "Expire"

    class ConcurrencyPolicy(models.TextChoices):
        SKIP = "skip", "Skip while running"
        QUEUE = "queue", "Queue"
        ALLOW = "allow", "Allow overlap"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    module_id = models.CharField(max_length=100)
    action_id = models.CharField(max_length=160)
    target_mode = models.CharField(max_length=16, choices=TargetMode.choices, default=TargetMode.SNAPSHOT)
    targets = models.JSONField(default=dict, blank=True)
    parameters = models.JSONField(default=dict, blank=True)

    schedule_type = models.CharField(max_length=16, choices=ScheduleType.choices, default=ScheduleType.ONCE)
    timezone = models.CharField(max_length=64, default="UTC")
    run_at = models.DateTimeField(null=True, blank=True)
    run_time = models.TimeField(null=True, blank=True)
    weekdays = models.JSONField(default=list, blank=True)
    day_of_month = models.PositiveSmallIntegerField(null=True, blank=True)
    interval_seconds = models.PositiveIntegerField(null=True, blank=True)
    interval_anchor_at = models.DateTimeField(null=True, blank=True)

    # Backend-owned schedules use this stable ownership key for idempotent
    # reconciliation. User-created schedules leave both fields blank.
    owner_module = models.CharField(max_length=100, blank=True, default="")
    owner_key = models.CharField(max_length=255, blank=True, default="")

    enabled = models.BooleanField(default=True)
    missed_policy = models.CharField(max_length=24, choices=MissedPolicy.choices, default=MissedPolicy.SKIP)
    missed_grace_minutes = models.PositiveIntegerField(default=60)
    concurrency_policy = models.CharField(max_length=16, choices=ConcurrencyPolicy.choices, default=ConcurrencyPolicy.SKIP)
    retry_count = models.PositiveSmallIntegerField(default=0)
    retry_delay_seconds = models.PositiveIntegerField(default=60)

    last_due_key = models.CharField(max_length=80, blank=True, default="")
    last_run_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="tec_tac_schedules_created")
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="tec_tac_schedules_updated")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name", "id")
        indexes = [
            models.Index(fields=("enabled", "schedule_type"), name="tectac_sched_enabled_idx"),
            models.Index(fields=("module_id", "action_id"), name="tectac_sched_action_idx"),
            models.Index(fields=("owner_module", "owner_key"), name="tectac_sched_owner_idx"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=("owner_module", "owner_key"),
                condition=~Q(owner_key=""),
                name="tectac_sched_owner_unique",
            ),
        ]

    def __str__(self):
        return self.name


class TecTacSchedulerConfig(models.Model):
    singleton = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    once_retention_hours = models.PositiveIntegerField(default=48)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="tec_tac_scheduler_config_updates")

    class Meta:
        verbose_name = "Tec-Tac scheduler configuration"

    @classmethod
    def current(cls):
        obj, _ = cls.objects.get_or_create(singleton=1)
        return obj


class TecTacSchedulerState(models.Model):
    singleton = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    last_tick_at = models.DateTimeField(null=True, blank=True)
    last_tick_completed_at = models.DateTimeField(null=True, blank=True)
    last_tick_error = models.TextField(blank=True, default="")
    last_checked = models.PositiveIntegerField(default=0)
    last_queued = models.PositiveIntegerField(default=0)
    last_skipped = models.PositiveIntegerField(default=0)
    last_cleaned = models.PositiveIntegerField(default=0)
    last_dispatch_at = models.DateTimeField(null=True, blank=True)
    last_dispatch_error = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = "Tec-Tac scheduler runtime state"

    @classmethod
    def current(cls):
        obj, _ = cls.objects.get_or_create(singleton=1)
        return obj



class TecTacScheduleRun(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"
        SKIPPED = "skipped", "Skipped"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    schedule = models.ForeignKey(TecTacSchedule, null=True, blank=True, on_delete=models.SET_NULL, related_name="runs")
    schedule_snapshot_id = models.UUIDField(null=True, blank=True, db_index=True)
    schedule_name = models.CharField(max_length=255, blank=True, default="")
    module_id = models.CharField(max_length=100, blank=True, default="")
    action_id = models.CharField(max_length=160, blank=True, default="")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    scheduled_for = models.DateTimeField()
    manual = models.BooleanField(default=False)
    targets_snapshot = models.JSONField(default=dict, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")
    error_type = models.CharField(max_length=120, blank=True, default="")
    celery_task_id = models.CharField(max_length=80, blank=True, default="")
    attempt = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("schedule", "status"), name="tectac_run_status_idx"),
            models.Index(fields=("scheduled_for",), name="tectac_run_due_idx"),
        ]

    def __str__(self):
        return f"{self.schedule_snapshot_id or self.schedule_id}:{self.status}:{self.scheduled_for.isoformat()}"


class TecTacUserPreferences(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="tec_tac_preferences",
        primary_key=True,
    )
    preferences = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Tec-Tac user preferences"
        verbose_name_plural = "Tec-Tac user preferences"

    def __str__(self):
        return f"Tec-Tac preferences: {self.user_id}"

class TecTacDashboard(models.Model):
    class Visibility(models.TextChoices):
        PRIVATE = "private", "Private"
        SHARED = "shared", "Shared"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=160)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="tec_tac_dashboards",
    )
    visibility = models.CharField(max_length=16, choices=Visibility.choices, default=Visibility.PRIVATE)
    layout = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name", "id")
        indexes = [
            models.Index(fields=("visibility", "name"), name="tectac_dash_vis_name_idx"),
            models.Index(fields=("owner", "name"), name="tectac_dash_owner_name_idx"),
        ]

    def __str__(self):
        return f"{self.name} ({self.visibility})"

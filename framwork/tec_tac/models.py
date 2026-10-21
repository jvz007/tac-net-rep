from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q


def default_session_trusted_proxies():
    # Tec-Tac is normally served by a local nginx reverse proxy. Trust only
    # loopback by default so external clients cannot spoof forwarding headers.
    return ["127.0.0.1/32", "::1/128"]


class TecTacSchedule(models.Model):
    class OwnerType(models.TextChoices):
        USER = "user", "User"
        MODULE = "module", "Module"

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
    target_state = models.CharField(max_length=24, default="valid")
    target_state_detail = models.CharField(max_length=500, blank=True, default="")
    parameters = models.JSONField(default=dict, blank=True)

    schedule_type = models.CharField(max_length=16, choices=ScheduleType.choices, default=ScheduleType.ONCE)
    timezone = models.CharField(max_length=64, default="UTC")
    run_at = models.DateTimeField(null=True, blank=True)
    run_time = models.TimeField(null=True, blank=True)
    weekdays = models.JSONField(default=list, blank=True)
    day_of_month = models.PositiveSmallIntegerField(null=True, blank=True)
    interval_seconds = models.PositiveIntegerField(null=True, blank=True)
    interval_anchor_at = models.DateTimeField(null=True, blank=True)

    # Ownership is explicit so operator-created and module-managed schedules can
    # share one execution engine without sharing one management surface.
    owner_type = models.CharField(max_length=16, choices=OwnerType.choices, default=OwnerType.USER)
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
    # 1.17.63 (CQ179 b): the names of the person who created the schedule and the person who last confirmed it, kept as text so an
    # audit row can still name them after the user row is gone. Blank on a row made before migration 0036: a read falls back to
    # created_by.username (see scheduler.schedule_creator_names).
    created_by_username = models.CharField(max_length=150, blank=True, default="")
    confirmed_by_username = models.CharField(max_length=150, blank=True, default="")
    # 1.17.68 (Johan, 21 October 2026, Q-APM12 b): the Tactical client and site scope and the role flags the owner held when they created or last
    # edited the schedule (see scheduler_creation_scope.py). An unattended run reads this, never the owner's live row, so a disabled owner changes
    # nothing. Empty on a row made before migration 0037: Core never invents one.
    creation_scope = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name", "id")
        indexes = [
            models.Index(fields=("enabled", "schedule_type"), name="tectac_sched_enabled_idx"),
            models.Index(fields=("module_id", "action_id"), name="tectac_sched_action_idx"),
            models.Index(fields=("owner_type", "enabled"), name="tectac_sched_owner_type_idx"),
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
    run_retention_days = models.PositiveIntegerField(default=90)
    queued_stale_minutes = models.PositiveIntegerField(default=10)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="tec_tac_scheduler_config_updates")

    class Meta:
        verbose_name = "Tec-Tac scheduler configuration"

    @classmethod
    def current(cls):
        obj, _ = cls.objects.get_or_create(singleton=1)
        return obj


class ExtensionRolePermission(models.Model):
    """Tec-Tac extension permission attached to an existing Tactical Role ID.

    role_id is deliberately an integer instead of a ForeignKey so Tec-Tac
    migrations stay independent of Tactical's accounts migration graph.

    The table keeps the name it had in the retired reporting proof of concept, so
    an upgraded server needs no DDL (see migration 0023).
    """

    role_id = models.PositiveIntegerField()
    codename = models.CharField(max_length=150)
    granted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tfdreporting_extensionrolepermission"
        constraints = [
            models.UniqueConstraint(
                fields=["role_id", "codename"],
                name="tfd_unique_role_permission",
            )
        ]
        indexes = [
            models.Index(
                fields=["role_id", "codename"],
                name="tfd_role_perm_lookup",
            )
        ]
        ordering = ["role_id", "codename"]

    def __str__(self):
        return f"{self.role_id}: {self.codename} = {self.granted}"


class TecTacRuntimeConfig(models.Model):
    """Core-owned runtime settings the UI shell reads (singleton)."""

    singleton = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    # Seconds a module's register() may take before the UI marks it failed.
    module_register_timeout_seconds = models.PositiveIntegerField(default=30)
    # Largest file one Tactical operation may forward, in whole MiB (1.17.14, CQ40). Default 10; Core accepts 1 to 25.
    tactical_operation_upload_max_mib = models.PositiveIntegerField(default=10)
    # The name an authenticator app shows for this system (1.17.23). Plain text, 1 to 60 characters, no colon.
    system_name = models.CharField(max_length=60, default="Tec-Tac")
    # Retired in 1.17.28 (AD-30 amendment): never read. The scheduler tick sets a stored True back to False with one audit row.
    # Dropped by a later migration, once installs have cleared it.
    priority_mail_private_relay = models.BooleanField(default=False)
    # Licensing enforcement mode (1.17.58): off, log-only or enforce. Blank means "use Core's default" (module_licensing.DEFAULT_LICENSING_MODE),
    # so a later release can change the default with one constant and no data migration. An explicit choice persists. Never null.
    licensing_enforcement_mode = models.CharField(max_length=16, blank=True, default="")
    # Remembered update source per component (1.17.2): {"framework": {"type": "branch", "ref": "dev"}, ...}.
    # A missing or invalid entry reads as the default (release, ref null); see runtime_settings.
    update_sources = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="tec_tac_runtime_config_updates")

    class Meta:
        verbose_name = "Tec-Tac runtime configuration"

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
    owner_type = models.CharField(max_length=16, choices=TecTacSchedule.OwnerType.choices, default=TecTacSchedule.OwnerType.USER)
    owner_module = models.CharField(max_length=100, blank=True, default="")
    owner_key = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    scheduled_for = models.DateTimeField()
    manual = models.BooleanField(default=False)
    targets_snapshot = models.JSONField(default=dict, blank=True)
    target_mode_snapshot = models.CharField(max_length=16, choices=TecTacSchedule.TargetMode.choices, default=TecTacSchedule.TargetMode.SNAPSHOT)
    parameters_snapshot = models.JSONField(default=dict, blank=True)
    retry_count_snapshot = models.PositiveSmallIntegerField(default=0)
    retry_delay_seconds_snapshot = models.PositiveIntegerField(default=60)
    result = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")
    error_type = models.CharField(max_length=120, blank=True, default="")
    celery_task_id = models.CharField(max_length=80, blank=True, default="")
    attempt = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    last_queued_at = models.DateTimeField(null=True, blank=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    # 1.17.61 (additive, blank by default): a handler may return "pending, finished later" (scheduler_completion.PendingCompletion). The run
    # then stays RUNNING with completion_state "pending" and completion_ref {kind, external_job_id, note}; "completed" and "expired" follow.
    completion_state = models.CharField(max_length=16, blank=True, default="")
    completion_ref = models.JSONField(default=dict, blank=True)
    completion_started_at = models.DateTimeField(null=True, blank=True)
    # 1.17.61: the at-most-once marks of system actions (system_actions.py): [{action_id, targets_digest, state, task_id}].
    system_action_marks = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("schedule", "status"), name="tectac_run_status_idx"),
            models.Index(fields=("owner_type", "created_at"), name="tectac_run_owner_type_idx"),
            models.Index(fields=("status", "-created_at"), name="tectac_run_hist_status_idx"),
            models.Index(fields=("action_id", "-created_at"), name="tectac_run_hist_action_idx"),
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


class TecTacSavedView(models.Model):
    """One saved view (filters and layout) for any module, owned by the user who created it.

    ``readers`` is a JSON list of user ids. Empty means shared with everyone; not empty means
    private to the owner and the listed ids. Removing a module leaves its views in place.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    module_id = models.CharField(max_length=100)
    view_key = models.CharField(max_length=64)
    name = models.CharField(max_length=160)
    payload = models.JSONField(default=dict, blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="tec_tac_saved_views",
    )
    readers = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name", "id")
        indexes = [
            models.Index(fields=("module_id", "view_key"), name="tectac_sview_mod_key_idx"),
            models.Index(fields=("owner", "module_id", "view_key"), name="tectac_sview_owner_key_idx"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=("owner", "module_id", "view_key", "name"),
                name="tectac_sview_owner_name_unique",
            ),
        ]

    def __str__(self):
        return f"{self.module_id}/{self.view_key}: {self.name}"


class TecTacSessionSecurityConfig(models.Model):
    class IpChangePolicy(models.TextChoices):
        OFF = "off", "Off"
        AUDIT = "audit", "Audit only"
        REAUTHENTICATE = "reauthenticate", "Require re-authentication"
        TERMINATE = "terminate", "Terminate session"

    singleton = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    idle_timeout_minutes = models.PositiveIntegerField(default=30)
    absolute_lifetime_minutes = models.PositiveIntegerField(default=480)
    ip_change_policy = models.CharField(max_length=20, choices=IpChangePolicy.choices, default=IpChangePolicy.REAUTHENTICATE)
    session_audit_enabled = models.BooleanField(default=True)
    activity_heartbeat_seconds = models.PositiveIntegerField(default=60)
    history_retention_days = models.PositiveIntegerField(default=30)
    last_history_cleanup_at = models.DateTimeField(null=True, blank=True)
    trusted_proxies = models.JSONField(default=default_session_trusted_proxies, blank=True)
    updated_by_label = models.CharField(max_length=150, blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Tec-Tac session security configuration"

    @classmethod
    def current(cls):
        obj, _ = cls.objects.get_or_create(singleton=1)
        return obj


class TecTacSessionTrust(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token_fingerprint = models.CharField(max_length=64, unique=True)
    # Hash identifier of the underlying Tactical Knox token. This is never the
    # bearer token itself and exists only to correlate Core trust metadata with
    # Tactical session administration.
    knox_digest = models.CharField(max_length=128, blank=True, default="", db_index=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="tec_tac_trusted_sessions")
    username = models.CharField(max_length=150, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_activity_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    initial_ip = models.CharField(max_length=64, blank=True, default="")
    last_ip = models.CharField(max_length=64, blank=True, default="")
    user_agent_hash = models.CharField(max_length=64, blank=True, default="")
    absolute_expires_at = models.DateTimeField(db_index=True)
    idle_expires_at = models.DateTimeField(db_index=True)
    revoked = models.BooleanField(default=False, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.CharField(max_length=150, blank=True, default="")
    revocation_reason = models.CharField(max_length=255, blank=True, default="")
    # The theme chosen in the dropdown for this sign-in only (1.17.24). Empty means none was chosen. It lives and dies with the
    # session row, is never copied to the saved preference, and a new sign-in starts with a new row.
    session_theme = models.CharField(max_length=16, blank=True, default="")

    class Meta:
        ordering = ("-last_seen_at", "-created_at")
        indexes = [
            models.Index(fields=("user", "revoked"), name="tectac_sess_user_rev_idx"),
            models.Index(fields=("username", "last_seen_at"), name="tectac_sess_user_seen_idx"),
        ]

    def __str__(self):
        return f"{self.username}:{self.id}"


class TecTacSessionAudit(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(TecTacSessionTrust, null=True, blank=True, on_delete=models.SET_NULL, related_name="audit_events")
    username = models.CharField(max_length=150, blank=True, default="", db_index=True)
    event_type = models.CharField(max_length=64, db_index=True)
    previous_ip = models.CharField(max_length=64, blank=True, default="")
    new_ip = models.CharField(max_length=64, blank=True, default="")
    reason = models.CharField(max_length=255, blank=True, default="")
    requested_by = models.CharField(max_length=150, blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=("event_type", "created_at"), name="tectac_sess_audit_evt_idx")]

    def __str__(self):
        return f"{self.event_type}:{self.username}:{self.created_at.isoformat()}"

class TecTacMfaBackupCode(models.Model):
    """One-time MFA recovery code owned by a Tactical user.

    Only Django password hashes are stored. The plaintext recovery code is
    returned once at generation time and cannot be recovered from the database.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="tec_tac_mfa_backup_codes",
    )
    code_hash = models.CharField(max_length=255)
    totp_fingerprint = models.CharField(max_length=64, blank=True, default="", db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("created_at", "id")
        indexes = [
            models.Index(fields=("user", "used_at"), name="tectac_mfa_code_user_idx"),
        ]

    def __str__(self):
        return f"{self.user_id}:{'used' if self.used_at else 'available'}:{self.id}"


class TecTacUserNotice(models.Model):
    class Level(models.TextChoices):
        INFO = "info", "Info"
        SUCCESS = "success", "Success"
        WARNING = "warning", "Warning"
        ERROR = "error", "Error"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="tec_tac_notices",
    )
    client_id = models.CharField(max_length=64, blank=True, default="")
    source = models.CharField(max_length=100, default="core")
    level = models.CharField(max_length=12, choices=Level.choices, default=Level.INFO)
    title = models.CharField(max_length=120, blank=True, default="")
    message = models.CharField(max_length=1000)
    action_label = models.CharField(max_length=60, blank=True, default="")
    action_route = models.CharField(max_length=500, blank=True, default="")
    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("user", "read_at", "created_at"), name="tectac_notice_unread_idx"),
            models.Index(fields=("user", "created_at"), name="tectac_notice_user_idx"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=("user", "client_id"),
                condition=~Q(client_id=""),
                name="tectac_notice_client_unique",
            ),
        ]

    def __str__(self):
        return f"{self.user_id}:{self.level}:{self.source}:{self.created_at.isoformat() if self.created_at else 'new'}"


class TecTacNoticeLedger(models.Model):
    """Which server-raised notices and Priority 1 emails a person has already had (Core 1.17.34).

    The module failure sweep reads and writes it. It is the dedupe record, so it is kept apart from TecTacUserNotice, which the person
    can clear ("Clear read") and which is pruned at 30 days or 500 rows. ``kind`` is ``notice`` (the toast and history row) or ``email``
    (the Priority 1 email); ``key`` is the module job id. Neither Clear read nor the notice pruning touches this table. The sweep deletes
    rows older than fourteen days itself (1.17.38; seven days before). No message text, address or name is stored.
    """

    KIND_NOTICE = "notice"
    KIND_EMAIL = "email"

    # The id is implicit on purpose (1.17.36): migration 0030 creates it as Django's implicit id, so the model must not redeclare it.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="tec_tac_notice_ledger",
    )
    kind = models.CharField(max_length=12)
    key = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=("kind", "key"), name="tectac_nledger_key_idx"),
            models.Index(fields=("kind", "created_at"), name="tectac_nledger_age_idx"),
        ]
        constraints = [
            models.UniqueConstraint(fields=("user", "kind", "key"), name="tectac_nledger_unique"),
        ]

    def __str__(self):
        return f"{self.user_id}:{self.kind}:{self.key}"


class TecTacModulePreference(models.Model):
    """One per-person choice a module keeps through Core (core.module_preferences 1.0.0, Core 1.17.35).

    A row belongs to one person, one module id and one name, and holds one small JSON value (at most 4 KiB, 5 levels deep). It is a
    separate table, not the reserved ``extensions`` object of the Tec-Tac preference document: that document is replaced as a whole, so
    a stale tab would overwrite a module's choice. Rows of a removed module stay (they are harmless and go with the person on account
    delete). No secret, token or personal data may be stored; this is the person's own display choice.
    """

    # The id is implicit on purpose (1.17.36): migration 0031 creates it as Django's implicit id, so the model must not redeclare it.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="tec_tac_module_preferences",
    )
    module_id = models.CharField(max_length=100)
    name = models.CharField(max_length=64)
    value = models.JSONField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("user", "module_id", "name"), name="tectac_modpref_unique"),
        ]

    def __str__(self):
        return f"{self.user_id}:{self.module_id}:{self.name}"

class TecTacEventJob(models.Model):
    """One event-started job a module published through ``tec_tac.event_jobs`` (core.event_jobs 1.0.0, Core 1.17.45).

    The row is the durable record: the publish stores it, a Celery message only tells a worker to look at it, and the Scheduler tick
    enqueues any row whose message was lost. ``payload`` is data the module chose (ids, never secrets or text bodies, at most 2 KiB).
    It is never logged, audited, listed or returned by a status route. ``policy`` is a snapshot of the registered limits taken at
    publish time, so the tick can recover a row without the handler being registered in its own process.
    A partial unique constraint lets one (module, job, key) be pending or running only once.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"
        SKIPPED = "skipped", "Skipped"
        EXPIRED = "expired", "Expired"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    module_id = models.CharField(max_length=100)
    job_id = models.CharField(max_length=160)
    key = models.CharField(max_length=128)
    payload = models.JSONField(default=dict, blank=True)
    policy = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    attempt = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField(default=3)
    next_attempt_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_enqueued_at = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error_type = models.CharField(max_length=120, blank=True, default="")
    error = models.CharField(max_length=255, blank=True, default="")
    result = models.JSONField(default=dict, blank=True)
    celery_task_id = models.CharField(max_length=80, blank=True, default="")

    class Meta:
        ordering = ("created_at",)
        indexes = [
            models.Index(fields=("status", "next_attempt_at"), name="tectac_evjob_due_idx"),
            models.Index(fields=("module_id", "job_id", "status"), name="tectac_evjob_job_idx"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=("module_id", "job_id", "key"),
                condition=Q(status__in=("pending", "running")),
                name="tectac_evjob_active_key",
            ),
        ]

    def __str__(self):
        return f"{self.job_id}:{self.status}"


class TecTacEventJobStat(models.Model):
    """Counters of one event job (one row per module and job id). ``dropped`` counts publishes Core refused to store (backlog, rate)
    and rows the tick trimmed; ``dropped_reported`` is how many of them already have an audit row. ``dropped_day`` counts drops in the
    window that started at ``dropped_day_started`` (reset after 24 hours)."""

    module_id = models.CharField(max_length=100)
    job_id = models.CharField(max_length=160)
    published = models.PositiveBigIntegerField(default=0)
    duplicate = models.PositiveBigIntegerField(default=0)
    dropped = models.PositiveBigIntegerField(default=0)
    dropped_reported = models.PositiveBigIntegerField(default=0)
    dropped_day = models.PositiveBigIntegerField(default=0)
    dropped_day_started = models.DateTimeField(null=True, blank=True)
    succeeded = models.PositiveBigIntegerField(default=0)
    failed = models.PositiveBigIntegerField(default=0)
    expired = models.PositiveBigIntegerField(default=0)
    skipped = models.PositiveBigIntegerField(default=0)
    last_failure_at = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=255, blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("module_id", "job_id"), name="tectac_evjobstat_unique"),
        ]

    def __str__(self):
        return self.job_id


class TecTacServerJobHook(models.Model):
    """One finished server-maintenance job Core has dealt with for its owning module (Core 1.17.62, R-22 part 2).

    The row is the at-most-once claim: the tick inserts it (unique on ``job_id``) before it publishes the module's event job, so a job is
    handed over at most once per Core. ``state`` is ``claiming`` (the tick is publishing it now), ``retry`` (the event could not be stored
    yet; the next tick tries again, three tries in all), ``queued`` (the event job is stored),
    ``skipped`` (the module was not runnable, one audit row), ``ignored`` (the job has no owner module or the owner registered no hook)
    or ``abandoned`` (the event job could not be stored after three tries). It holds ids and a status only: never output and never
    parameters.
    """

    class State(models.TextChoices):
        CLAIMING = "claiming", "Claiming"
        RETRY = "retry", "Waiting to retry"
        QUEUED = "queued", "Queued"
        SKIPPED = "skipped", "Skipped"
        IGNORED = "ignored", "Ignored"
        ABANDONED = "abandoned", "Abandoned"

    job_id = models.UUIDField(unique=True)
    module_id = models.CharField(max_length=100, blank=True, default="")
    action_id = models.CharField(max_length=128, blank=True, default="")
    job_status = models.CharField(max_length=32, blank=True, default="")
    state = models.CharField(max_length=16, choices=State.choices, default=State.CLAIMING)
    reason = models.CharField(max_length=40, blank=True, default="")
    attempts = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("created_at",)
        indexes = [
            models.Index(fields=("created_at",), name="tectac_svjobhook_created"),
        ]

    def __str__(self):
        return f"{self.job_id}:{self.state}"


class TecTacDelegationGrant(models.Model):
    """What a person confirmed once so that one module may start another module's system action for them later (Core 1.17.68, S4).

    The owner module (Maintenance) registers a grant when a person saves a profile. The provider module (Advanced Patch Management) names the
    owner in ``delegable_to`` when it registers the system action. A grant holds the confirmed action, targets and parameters, the person (by
    row and by stored name) and that person's scope at the time (``creation_scope``). It holds no endpoint list: the endpoints are read when a
    run starts and are always inside the targets AND the stored scope. A person who saves the profile later takes the grant over. Editing or
    removing it revokes every ticket made for it (see delegation.py).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner_module = models.CharField(max_length=100)
    grant_key = models.CharField(max_length=120)
    provider_module = models.CharField(max_length=100)
    action_id = models.CharField(max_length=160)
    targets = models.JSONField(default=dict, blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    parameters_digest = models.CharField(max_length=64, blank=True, default="")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="tec_tac_delegation_grants_created")
    created_by_username = models.CharField(max_length=150, blank=True, default="")
    confirmed_by_username = models.CharField(max_length=150, blank=True, default="")
    creation_scope = models.JSONField(default=dict, blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("owner_module", "grant_key")
        indexes = [
            models.Index(fields=("provider_module", "action_id"), name="tectac_deleg_provider_idx"),
        ]
        constraints = [
            models.UniqueConstraint(fields=("owner_module", "grant_key"), name="tectac_deleg_owner_key_unique"),
        ]

    def __str__(self):
        return f"{self.owner_module}:{self.grant_key}"


from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


def default_trusted_proxies():
    return ["127.0.0.1/32", "::1/128"]


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0006_scheduler_interval_reconciliation"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacSessionSecurityConfig",
            fields=[
                ("singleton", models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ("idle_timeout_minutes", models.PositiveIntegerField(default=30)),
                ("absolute_lifetime_minutes", models.PositiveIntegerField(default=480)),
                ("ip_change_policy", models.CharField(choices=[("off", "Off"), ("audit", "Audit only"), ("reauthenticate", "Require re-authentication"), ("terminate", "Terminate session")], default="reauthenticate", max_length=20)),
                ("session_audit_enabled", models.BooleanField(default=True)),
                ("activity_heartbeat_seconds", models.PositiveIntegerField(default=60)),
                ("trusted_proxies", models.JSONField(blank=True, default=default_trusted_proxies)),
                ("updated_by_label", models.CharField(blank=True, default="", max_length=150)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"verbose_name": "Tec-Tac session security configuration"},
        ),
        migrations.CreateModel(
            name="TecTacSessionTrust",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("token_fingerprint", models.CharField(max_length=64, unique=True)),
                ("username", models.CharField(db_index=True, max_length=150)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("last_activity_at", models.DateTimeField()),
                ("last_seen_at", models.DateTimeField()),
                ("initial_ip", models.CharField(blank=True, default="", max_length=64)),
                ("last_ip", models.CharField(blank=True, default="", max_length=64)),
                ("user_agent_hash", models.CharField(blank=True, default="", max_length=64)),
                ("absolute_expires_at", models.DateTimeField(db_index=True)),
                ("idle_expires_at", models.DateTimeField(db_index=True)),
                ("revoked", models.BooleanField(db_index=True, default=False)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_by", models.CharField(blank=True, default="", max_length=150)),
                ("revocation_reason", models.CharField(blank=True, default="", max_length=255)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="tec_tac_trusted_sessions", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ("-last_seen_at", "-created_at")},
        ),
        migrations.CreateModel(
            name="TecTacSessionAudit",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("username", models.CharField(blank=True, db_index=True, default="", max_length=150)),
                ("event_type", models.CharField(db_index=True, max_length=64)),
                ("previous_ip", models.CharField(blank=True, default="", max_length=64)),
                ("new_ip", models.CharField(blank=True, default="", max_length=64)),
                ("reason", models.CharField(blank=True, default="", max_length=255)),
                ("requested_by", models.CharField(blank=True, default="", max_length=150)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("session", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="audit_events", to="tec_tac.tectacsessiontrust")),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.AddIndex(model_name="tectacsessiontrust", index=models.Index(fields=["user", "revoked"], name="tectac_sess_user_rev_idx")),
        migrations.AddIndex(model_name="tectacsessiontrust", index=models.Index(fields=["username", "last_seen_at"], name="tectac_sess_user_seen_idx")),
        migrations.AddIndex(model_name="tectacsessionaudit", index=models.Index(fields=["event_type", "created_at"], name="tectac_sess_audit_evt_idx")),
    ]

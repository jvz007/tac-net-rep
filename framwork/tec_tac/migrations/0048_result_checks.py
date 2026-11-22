import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    """Result checks (Core 1.18.44, core.result_checks 1.0.0): the follow-up of a bulk run, and one row per endpoint of it.

    Additive: two new tables. Nothing existing changes. No output text is stored. Written by hand, because Django is not installed on the
    development PC. Check it with `manage.py makemigrations --check --dry-run` on the dev server; the models and this file must agree.
    It depends on 0047 and on the user model (the standard swappable dependency, as 0039 does)."""

    dependencies = [
        ("tec_tac", "0047_published_installer_mtime"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacResultCheck",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("module_id", models.CharField(max_length=100)),
                ("reader_id", models.CharField(max_length=160)),
                ("label", models.CharField(max_length=80)),
                ("job_ref", models.JSONField(blank=True, default=dict)),
                ("status", models.CharField(choices=[("open", "Open"), ("closed", "Closed")], default="open", max_length=8)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("next_check_at", models.DateTimeField()),
                ("deadline_at", models.DateTimeField()),
                ("closed_at", models.DateTimeField(blank=True, null=True)),
                ("queued_until", models.DateTimeField(blank=True, null=True)),
                ("running_until", models.DateTimeField(blank=True, null=True)),
                ("notice_sent", models.BooleanField(default=False)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ("created_at",)},
        ),
        migrations.CreateModel(
            name="TecTacResultCheckItem",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("endpoint_id", models.CharField(max_length=200)),
                ("hostname", models.CharField(blank=True, default="", max_length=255)),
                ("state", models.CharField(default="running", max_length=16)),
                ("exit_code", models.IntegerField(blank=True, null=True)),
                ("checked_at", models.DateTimeField(blank=True, null=True)),
                ("result_check", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="items", to="tec_tac.tectacresultcheck")),
            ],
        ),
        migrations.AddIndex(
            model_name="tectacresultcheck",
            index=models.Index(fields=["status", "next_check_at"], name="tectac_rescheck_due_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacresultcheck",
            index=models.Index(fields=["user", "status"], name="tectac_rescheck_user_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacresultcheck",
            index=models.Index(fields=["status", "closed_at"], name="tectac_rescheck_closed_idx"),
        ),
        migrations.AddConstraint(
            model_name="tectacresultcheckitem",
            constraint=models.UniqueConstraint(fields=("result_check", "endpoint_id"), name="tectac_rescheckitem_unique"),
        ),
        migrations.AddIndex(
            model_name="tectacresultcheckitem",
            index=models.Index(fields=["result_check", "state"], name="tectac_rescheckitem_state_idx"),
        ),
    ]

import uuid

import django.db.models.deletion
from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):
    """Engineer Console certificates (Core 1.18.52, C3): the certificate authority, the certificates and the enrolments, and the validity
    setting.

    Additive: three new tables and one new column on the runtime configuration. Nothing existing changes. The user is a plain integer
    in all three tables (no foreign key), so no swappable dependency is needed. Written by hand, because Django is not installed on the
    development PC. Check it with `manage.py makemigrations --check --dry-run` on the dev server; the models and this file must agree
    (tests/console-certificates-setting-1.18.52.py compares them by reading both)."""

    dependencies = [
        ("tec_tac", "0048_result_checks"),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacConsoleCA",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("server_id", models.CharField(max_length=32, unique=True)),
                ("public_key_der", models.BinaryField()),
                ("cert_der", models.BinaryField()),
                ("key_blob", models.BinaryField()),
                ("key_id", models.CharField(max_length=32)),
                ("not_before", models.DateTimeField()),
                ("not_after", models.DateTimeField()),
                ("state", models.CharField(choices=[("active", "Active"), ("retired", "Retired")], default="active", max_length=8)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("created_by", models.IntegerField(blank=True, null=True)),
                ("retired_at", models.DateTimeField(blank=True, null=True)),
                ("retired_by", models.IntegerField(blank=True, null=True)),
            ],
            options={"db_table": "core_console_ca"},
        ),
        migrations.CreateModel(
            name="TecTacConsoleCertificate",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("serial", models.CharField(max_length=32, unique=True)),
                ("user_id", models.IntegerField()),
                ("username_snapshot", models.CharField(max_length=150)),
                ("pc_label", models.CharField(max_length=64)),
                ("spki_sha256", models.CharField(max_length=64)),
                ("cert_der", models.BinaryField()),
                ("not_before", models.DateTimeField()),
                ("not_after", models.DateTimeField()),
                ("state", models.CharField(choices=[("active", "Active"), ("revoked", "Revoked")], default="active", max_length=8)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_by", models.IntegerField(blank=True, null=True)),
                ("revoked_reason", models.CharField(blank=True, default="", max_length=16)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("ca", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="+", to="tec_tac.tectacconsoleca")),
            ],
            options={"db_table": "core_console_certificate"},
        ),
        migrations.CreateModel(
            name="TecTacConsoleEnrolment",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("user_id", models.IntegerField()),
                ("authorised_by", models.IntegerField()),
                ("authorised_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField()),
                ("state", models.CharField(choices=[("open", "Open"), ("used", "Used"), ("cancelled", "Cancelled"), ("expired", "Expired")], default="open", max_length=9)),
                ("code_hash", models.CharField(blank=True, default="", max_length=64)),
                ("code_expires_at", models.DateTimeField(blank=True, null=True)),
                ("used_serial", models.CharField(blank=True, default="", max_length=32)),
            ],
            options={"db_table": "core_console_enrolment"},
        ),
        migrations.AddConstraint(
            model_name="tectacconsoleca",
            constraint=models.UniqueConstraint(condition=Q(state="active"), fields=("state",), name="tectac_console_ca_one_active"),
        ),
        migrations.AddIndex(
            model_name="tectacconsolecertificate",
            index=models.Index(fields=["user_id", "state"], name="tectac_concert_user_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacconsolecertificate",
            index=models.Index(fields=["ca", "state"], name="tectac_concert_ca_idx"),
        ),
        migrations.AddConstraint(
            model_name="tectacconsoleenrolment",
            constraint=models.UniqueConstraint(condition=Q(state="open"), fields=("user_id",), name="tectac_console_enrol_one_open"),
        ),
        migrations.AddIndex(
            model_name="tectacconsoleenrolment",
            index=models.Index(fields=["code_hash"], name="tectac_console_enrol_code_idx"),
        ),
        migrations.AddField(
            model_name="tectacruntimeconfig",
            name="console_certificate_validity_days",
            field=models.PositiveIntegerField(default=365),
        ),
    ]

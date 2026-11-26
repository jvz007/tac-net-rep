import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    """Engineer Console sessions (Core 1.18.56, C1): the Console's sign-in record and its one-time sign-in codes.

    Additive: two new tables. Nothing existing changes. The user and the Tec-Tac session are plain values in both tables (no foreign key),
    like 0049, so no swappable dependency is needed. Written by hand, because Django is not installed on the development PC. Check it with
    `manage.py makemigrations --check --dry-run` on the dev server; the models and this file must agree
    (tests/console-sessions-migration-1.18.56.py compares them by reading both)."""

    dependencies = [
        ("tec_tac", "0049_console_certificates"),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacConsoleSession",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("user_id", models.IntegerField()),
                ("trust_id", models.UUIDField()),
                ("token_hash", models.CharField(max_length=64, unique=True)),
                ("serial", models.CharField(max_length=32)),
                ("pc_label", models.CharField(max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                ("revoked", models.BooleanField(default=False)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_reason", models.CharField(blank=True, default="", max_length=24)),
            ],
            options={"db_table": "core_console_session"},
        ),
        migrations.CreateModel(
            name="TecTacConsoleSignin",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("code_hash", models.CharField(max_length=64, unique=True)),
                ("user_id", models.IntegerField()),
                ("serial", models.CharField(max_length=32)),
                ("code_challenge", models.CharField(max_length=43)),
                ("redirect_port", models.IntegerField()),
                ("host", models.CharField(max_length=253)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField()),
                ("used_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={"db_table": "core_console_signin"},
        ),
        migrations.AddIndex(
            model_name="tectacconsolesession",
            index=models.Index(fields=["user_id", "revoked"], name="tectac_consess_user_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacconsolesession",
            index=models.Index(fields=["serial", "revoked"], name="tectac_consess_serial_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacconsolesession",
            index=models.Index(fields=["trust_id"], name="tectac_consess_trust_idx"),
        ),
    ]

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0010_scheduler_ownership_split"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacsessiontrust",
            name="knox_digest",
            field=models.CharField(blank=True, db_index=True, default="", max_length=128),
        ),
        migrations.CreateModel(
            name="TecTacMfaBackupCode",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("code_hash", models.CharField(max_length=255)),
                ("used_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="tec_tac_mfa_backup_codes", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ("created_at", "id")},
        ),
        migrations.AddIndex(
            model_name="tectacmfabackupcode",
            index=models.Index(fields=["user", "used_at"], name="tectac_mfa_code_user_idx"),
        ),
    ]

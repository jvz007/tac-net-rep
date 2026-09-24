from django.conf import settings
from django.db import migrations, models
from django.db.models import Q
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0008_alter_tectacsessionsecurityconfig_trusted_proxies"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacUserNotice",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("client_id", models.CharField(blank=True, default="", max_length=64)),
                ("source", models.CharField(default="core", max_length=100)),
                ("level", models.CharField(choices=[("info", "Info"), ("success", "Success"), ("warning", "Warning"), ("error", "Error")], default="info", max_length=12)),
                ("title", models.CharField(blank=True, default="", max_length=120)),
                ("message", models.CharField(max_length=1000)),
                ("action_label", models.CharField(blank=True, default="", max_length=60)),
                ("action_route", models.CharField(blank=True, default="", max_length=500)),
                ("read_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="tec_tac_notices", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.AddIndex(
            model_name="tectacusernotice",
            index=models.Index(fields=["user", "read_at", "created_at"], name="tectac_notice_unread_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacusernotice",
            index=models.Index(fields=["user", "created_at"], name="tectac_notice_user_idx"),
        ),
        migrations.AddConstraint(
            model_name="tectacusernotice",
            constraint=models.UniqueConstraint(condition=~Q(client_id=""), fields=("user", "client_id"), name="tectac_notice_client_unique"),
        ),
    ]

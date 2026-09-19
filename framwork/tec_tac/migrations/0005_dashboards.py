from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0004_user_preferences"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacDashboard",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=160)),
                ("visibility", models.CharField(choices=[("private", "Private"), ("shared", "Shared")], default="private", max_length=16)),
                ("layout", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("owner", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="tec_tac_dashboards", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ("name", "id")},
        ),
        migrations.AddIndex(
            model_name="tectacdashboard",
            index=models.Index(fields=["visibility", "name"], name="tectac_dash_vis_name_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacdashboard",
            index=models.Index(fields=["owner", "name"], name="tectac_dash_owner_name_idx"),
        ),
    ]

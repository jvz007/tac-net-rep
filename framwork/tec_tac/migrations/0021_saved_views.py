from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0020_scheduler_target_parity_repair"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacSavedView",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("module_id", models.CharField(max_length=100)),
                ("view_key", models.CharField(max_length=64)),
                ("name", models.CharField(max_length=160)),
                ("payload", models.JSONField(blank=True, default=dict)),
                ("readers", models.JSONField(blank=True, default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("owner", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="tec_tac_saved_views", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ("name", "id")},
        ),
        migrations.AddIndex(
            model_name="tectacsavedview",
            index=models.Index(fields=["module_id", "view_key"], name="tectac_sview_mod_key_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacsavedview",
            index=models.Index(fields=["owner", "module_id", "view_key"], name="tectac_sview_owner_key_idx"),
        ),
        migrations.AddConstraint(
            model_name="tectacsavedview",
            constraint=models.UniqueConstraint(fields=("owner", "module_id", "view_key", "name"), name="tectac_sview_owner_name_unique"),
        ),
    ]

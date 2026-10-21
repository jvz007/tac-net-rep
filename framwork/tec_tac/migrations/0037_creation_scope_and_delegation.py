import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    """The creation-time scope of a schedule and the delegation grant (Core 1.17.68, Johan 21 October 2026).

    Additive: one JSON column on ``TecTacSchedule`` (``creation_scope``, default empty, so a row made before this one simply has none and Core
    never invents one) and one new table, ``TecTacDelegationGrant``. No existing column changes and nothing needs a data migration. Written by
    hand, because Django is not installed on the development PC. Check it with `manage.py makemigrations --check --dry-run` on the dev server;
    the models and this file must agree."""

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("tec_tac", "0036_schedule_creator_name"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacschedule",
            name="creation_scope",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.CreateModel(
            name="TecTacDelegationGrant",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("owner_module", models.CharField(max_length=100)),
                ("grant_key", models.CharField(max_length=120)),
                ("provider_module", models.CharField(max_length=100)),
                ("action_id", models.CharField(max_length=160)),
                ("targets", models.JSONField(blank=True, default=dict)),
                ("parameters", models.JSONField(blank=True, default=dict)),
                ("parameters_digest", models.CharField(blank=True, default="", max_length=64)),
                ("created_by_username", models.CharField(blank=True, default="", max_length=150)),
                ("confirmed_by_username", models.CharField(blank=True, default="", max_length=150)),
                ("creation_scope", models.JSONField(blank=True, default=dict)),
                ("enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="tec_tac_delegation_grants_created", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ("owner_module", "grant_key"),
            },
        ),
        migrations.AddIndex(
            model_name="tectacdelegationgrant",
            index=models.Index(fields=["provider_module", "action_id"], name="tectac_deleg_provider_idx"),
        ),
        migrations.AddConstraint(
            model_name="tectacdelegationgrant",
            constraint=models.UniqueConstraint(fields=("owner_module", "grant_key"), name="tectac_deleg_owner_key_unique"),
        ),
    ]

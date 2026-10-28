import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    """The person who pressed Run now on a schedule (Core 1.17.85). Additive: a nullable user link and a blank name on ``TecTacScheduleRun``.
    No data migration: every earlier run reads as started by nobody. Written by hand, because Django is not installed on the development PC.
    Check it with `manage.py makemigrations --check --dry-run` on the dev server; the model and this file must agree."""

    dependencies = [
        ("tec_tac", "0038_communicator_service_user"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacschedulerun",
            name="started_by",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name="tectacschedulerun",
            name="started_by_username",
            field=models.CharField(blank=True, default="", max_length=150),
        ),
    ]

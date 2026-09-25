from django.db import migrations, models
from django.utils import timezone


def backfill_last_queued_at(apps, schema_editor):
    Run = apps.get_model("tec_tac", "TecTacScheduleRun")
    for run in Run.objects.filter(status="queued", last_queued_at__isnull=True).iterator():
        run.last_queued_at = run.created_at or timezone.now()
        run.save(update_fields=["last_queued_at"])


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0013_scheduler_durability")]
    operations = [
        migrations.AddField(
            model_name="tectacschedulerun",
            name="last_queued_at",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.RunPython(backfill_last_queued_at, migrations.RunPython.noop),
    ]

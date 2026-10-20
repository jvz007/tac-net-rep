from django.db import migrations, models


class Migration(migrations.Migration):
    """Pending completion and system-action marks on a Scheduler run (Core 1.17.61).

    Additive: four columns on ``TecTacScheduleRun``, all blank or empty by default, so every existing row reads as a run with no pending
    completion and no system-action mark and nothing changes until a handler returns ``PendingCompletion`` or a module runs a system
    action. Written by hand, because Django is not installed on the development PC. Check it with
    `manage.py makemigrations --check --dry-run` on the dev server; the model and this file must agree."""

    dependencies = [
        ("tec_tac", "0033_runtime_licensing_mode"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacschedulerun",
            name="completion_state",
            field=models.CharField(blank=True, default="", max_length=16),
        ),
        migrations.AddField(
            model_name="tectacschedulerun",
            name="completion_ref",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="tectacschedulerun",
            name="completion_started_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="tectacschedulerun",
            name="system_action_marks",
            field=models.JSONField(blank=True, default=list),
        ),
    ]

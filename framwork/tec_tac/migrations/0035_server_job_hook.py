from django.db import migrations, models


class Migration(migrations.Migration):
    """The handed-over record of a finished server-maintenance job (Core 1.17.62, R-22 part 2).

    Additive: one new table, ``TecTacServerJobHook``, unique on ``job_id``. No existing table changes and nothing needs a data migration.
    Written by hand, because Django is not installed on the development PC. Check it with
    `manage.py makemigrations --check --dry-run` on the dev server; the model and this file must agree."""

    dependencies = [
        ("tec_tac", "0034_scheduler_run_completion"),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacServerJobHook",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("job_id", models.UUIDField(unique=True)),
                ("module_id", models.CharField(blank=True, default="", max_length=100)),
                ("action_id", models.CharField(blank=True, default="", max_length=128)),
                ("job_status", models.CharField(blank=True, default="", max_length=32)),
                ("state", models.CharField(choices=[("claiming", "Claiming"), ("retry", "Waiting to retry"), ("queued", "Queued"), ("skipped", "Skipped"), ("ignored", "Ignored"), ("abandoned", "Abandoned")], default="claiming", max_length=16)),
                ("reason", models.CharField(blank=True, default="", max_length=40)),
                ("attempts", models.PositiveSmallIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ("created_at",),
            },
        ),
        migrations.AddIndex(
            model_name="tectacserverjobhook",
            index=models.Index(fields=["created_at"], name="tectac_svjobhook_created"),
        ),
    ]

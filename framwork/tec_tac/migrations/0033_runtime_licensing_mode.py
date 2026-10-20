from django.db import migrations, models


class Migration(migrations.Migration):
    """The licensing enforcement mode as a runtime setting (Core 1.17.58, Johan 19 October 2026: log-only first).

    Additive: one text column, blank by default. Blank means "use Core's default", which is log-only: nothing is enforced. Existing rows
    read blank, so nothing changes until a superuser chooses a mode. A later release can move the default to enforce with one constant
    (``module_licensing.DEFAULT_LICENSING_MODE``) and no data migration. Written by hand, because Django is not installed on the
    development PC. Check it with `manage.py makemigrations --check --dry-run` on the dev server; the model and this file must agree."""

    dependencies = [
        ("tec_tac", "0032_event_jobs"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacruntimeconfig",
            name="licensing_enforcement_mode",
            field=models.CharField(blank=True, default="", max_length=16),
        ),
    ]

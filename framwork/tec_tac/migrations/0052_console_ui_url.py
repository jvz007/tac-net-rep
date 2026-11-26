from django.db import migrations, models


class Migration(migrations.Migration):
    """The Tec-Tac web address the Engineer Console opens for its sign-in (Core 1.18.58): the runtime setting console_ui_url.

    Additive: one new text column with an empty default (empty = unset, so Core reads the single https origin in Tactical's CORS settings).
    Written by hand, because Django is not installed on the development PC. Check it with `manage.py makemigrations --check --dry-run` on the
    dev server; the model and this file must agree (tests/console-ui-url-setting-1.18.58.py compares them by reading both)."""

    dependencies = [
        ("tec_tac", "0051_console_enrolment_pkce"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacruntimeconfig",
            name="console_ui_url",
            field=models.CharField(blank=True, default="", max_length=300),
        ),
    ]

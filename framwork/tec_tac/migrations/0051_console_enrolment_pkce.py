from django.db import migrations, models


class Migration(migrations.Migration):
    """Engineer Console enrolment over loopback with PKCE (Core 1.18.57, C2): the S256 challenge bound to an enrolment's current one-time code.

    Additive: one new text column with an empty default (no challenge = today's behaviour). Written by hand, because Django is not installed on
    the development PC. Check it with `manage.py makemigrations --check --dry-run` on the dev server; the model and this file must agree
    (tests/console-enrolment-pkce-1.18.57.py compares them by reading both)."""

    dependencies = [
        ("tec_tac", "0050_console_sessions"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacconsoleenrolment",
            name="code_challenge",
            field=models.CharField(blank=True, default="", max_length=43),
        ),
    ]

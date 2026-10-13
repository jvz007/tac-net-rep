from django.db import migrations, models


class Migration(migrations.Migration):
    """The theme chosen for one sign-in, held on the session trust row (1.17.24). Additive: one text column, default empty.

    Empty means no theme was chosen for the session. Existing rows read as empty. The value is never copied to the saved
    preference and dies with the session row. The reverse drops the column."""

    dependencies = [
        ("tec_tac", "0027_runtime_system_name"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacsessiontrust",
            name="session_theme",
            field=models.CharField(blank=True, default="", max_length=16),
        ),
    ]

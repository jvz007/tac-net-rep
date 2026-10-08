from django.db import migrations, models


class Migration(migrations.Migration):
    """Remembered update source per component (1.17.2). Additive: one JSON column, default {}."""

    dependencies = [
        ("tec_tac", "0024_retire_tfdreporting_poc"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacruntimeconfig",
            name="update_sources",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]

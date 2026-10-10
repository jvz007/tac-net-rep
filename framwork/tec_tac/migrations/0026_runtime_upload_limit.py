from django.db import migrations, models


class Migration(migrations.Migration):
    """The Tactical operation upload ceiling as a system setting (1.17.14, CQ40). Additive: one integer column, default 10 (MiB).

    A row that exists already reads as 10, the ceiling Core had before the setting existed."""

    dependencies = [
        ("tec_tac", "0025_runtime_update_sources"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacruntimeconfig",
            name="tactical_operation_upload_max_mib",
            field=models.PositiveIntegerField(default=10),
        ),
    ]

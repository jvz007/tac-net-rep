from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0015_scheduler_target_canonicalization")]

    operations = [
        migrations.AddField(
            model_name="tectacsessionsecurityconfig",
            name="history_retention_days",
            field=models.PositiveIntegerField(default=30),
        ),
    ]

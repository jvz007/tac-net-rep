from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0016_session_history_retention")]

    operations = [
        migrations.AddField(
            model_name="tectacsessionsecurityconfig",
            name="last_history_cleanup_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

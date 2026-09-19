# Generated for Tec-Tac Framework 1.12.0
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0002_scheduler_hardening")]
    operations = [
        migrations.AlterModelOptions(
            name="tectacschedulerconfig",
            options={"verbose_name": "Tec-Tac scheduler configuration"},
        ),
        migrations.AlterModelOptions(
            name="tectacschedulerstate",
            options={"verbose_name": "Tec-Tac scheduler runtime state"},
        ),
    ]

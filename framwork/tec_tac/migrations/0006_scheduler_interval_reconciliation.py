# Generated for Tec-Tac Framework 1.15.14
from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0005_dashboards")]
    operations = [
        migrations.AlterField(
            model_name="tectacschedule",
            name="schedule_type",
            field=models.CharField(
                choices=[
                    ("once", "Once"),
                    ("daily", "Daily"),
                    ("weekly", "Weekly"),
                    ("monthly", "Monthly"),
                    ("interval", "Interval"),
                ],
                default="once",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="tectacschedule",
            name="interval_seconds",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="tectacschedule",
            name="interval_anchor_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="tectacschedule",
            name="owner_module",
            field=models.CharField(blank=True, default="", max_length=100),
        ),
        migrations.AddField(
            model_name="tectacschedule",
            name="owner_key",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddIndex(
            model_name="tectacschedule",
            index=models.Index(fields=["owner_module", "owner_key"], name="tectac_sched_owner_idx"),
        ),
        migrations.AddConstraint(
            model_name="tectacschedule",
            constraint=models.UniqueConstraint(
                fields=("owner_module", "owner_key"),
                condition=~Q(owner_key=""),
                name="tectac_sched_owner_unique",
            ),
        ),
    ]

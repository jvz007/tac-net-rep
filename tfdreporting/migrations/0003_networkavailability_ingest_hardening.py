from django.db import migrations, models
from django.db.models import Q
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("tfdreporting", "0002_extensionrolepermission"),
    ]

    operations = [
        migrations.AddField(
            model_name="networkavailability",
            name="idempotency_key",
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name="networkavailability",
            name="ingested_by",
            field=models.CharField(blank=True, default="", max_length=150),
        ),
        migrations.AddField(
            model_name="networkavailability",
            name="received_at",
            field=models.DateTimeField(default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="networkavailability",
            name="received_at",
            field=models.DateTimeField(auto_now_add=True),
        ),
        migrations.AddConstraint(
            model_name="networkavailability",
            constraint=models.UniqueConstraint(
                condition=Q(idempotency_key__isnull=False),
                fields=("source", "idempotency_key"),
                name="tfd_netavail_source_idempotency_unique",
            ),
        ),
    ]

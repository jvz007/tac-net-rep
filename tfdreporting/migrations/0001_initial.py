from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="NetworkAvailability",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("client_name", models.CharField(max_length=255)),
                ("site_name", models.CharField(max_length=255)),
                ("device_name", models.CharField(max_length=255)),
                ("source", models.CharField(max_length=100)),
                ("timestamp", models.DateTimeField()),
                ("status", models.CharField(max_length=50)),
                ("availability_pct", models.DecimalField(blank=True, decimal_places=3, max_digits=6, null=True)),
                ("latency_ms", models.DecimalField(blank=True, decimal_places=3, max_digits=10, null=True)),
                ("packet_loss_pct", models.DecimalField(blank=True, decimal_places=3, max_digits=6, null=True)),
            ],
            options={"ordering": ["-timestamp"]},
        ),
    ]

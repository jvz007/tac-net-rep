from django.db import migrations, models


class Migration(migrations.Migration):
    """Core 1.18.39 (AD-74): ``TecTacPublishedInstaller``, the one row of the public Endpoint Agent installer (table ``core_published_installer``).
    A new table, no data migration, nothing existing is touched. Written by hand, because Django is not installed on the development PC; check it
    with `manage.py makemigrations --check --dry-run` on the dev server: the model and this file must agree. It depends only on 0045 (no
    floating dependency on another app)."""

    dependencies = [
        ("tec_tac", "0045_communicator_service_user_retry"),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacPublishedInstaller",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("slot", models.CharField(max_length=32, unique=True)),
                ("module_id", models.CharField(max_length=100)),
                ("path", models.CharField(max_length=4096)),
                ("sha256", models.CharField(max_length=64)),
                ("size", models.PositiveBigIntegerField()),
                ("version", models.CharField(max_length=40)),
                ("published_at", models.DateTimeField(auto_now=True)),
            ],
            options={"db_table": "core_published_installer"},
        ),
    ]

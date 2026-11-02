from django.db import migrations, models


class Migration(migrations.Migration):
    """Core 1.17.100 (AD-57): ``TecTacSecret``, the encrypted rows of core.secrets (table ``core_secret``). A new table, no data migration,
    nothing existing is touched. Written by hand, because Django is not installed on the development PC; check it with
    `manage.py makemigrations --check --dry-run` on the dev server: the model and this file must agree."""

    dependencies = [
        ("tec_tac", "0043_removed_schedule_marker"),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacSecret",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("owner_module", models.CharField(max_length=100)),
                ("name", models.CharField(max_length=64)),
                ("ciphertext", models.BinaryField()),
                ("key_id", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("last_read_at", models.DateTimeField(blank=True, null=True)),
                ("read_count", models.PositiveBigIntegerField(default=0)),
            ],
            options={"db_table": "core_secret"},
        ),
        migrations.AddConstraint(
            model_name="tectacsecret",
            constraint=models.UniqueConstraint(fields=("owner_module", "name"), name="core_secret_owner_name_unique"),
        ),
    ]

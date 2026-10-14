from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    """The notice ledger (Core 1.17.34): which module failure notices and Priority 1 emails a person has already had.

    Additive: one new table. Nothing existing changes and no data is copied; the sweep reads the existing notice and email marker rows
    together with the ledger, so a notice raised before this release still counts as raised. Written by hand, because Django is not
    installed on the development PC. Check it with `manage.py makemigrations --check --dry-run` on the dev server."""

    dependencies = [
        ("tec_tac", "0029_priority_mail_private_relay"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TecTacNoticeLedger",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("kind", models.CharField(max_length=12)),
                ("key", models.CharField(max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="tec_tac_notice_ledger", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddIndex(
            model_name="tectacnoticeledger",
            index=models.Index(fields=["kind", "key"], name="tectac_nledger_key_idx"),
        ),
        migrations.AddIndex(
            model_name="tectacnoticeledger",
            index=models.Index(fields=["kind", "created_at"], name="tectac_nledger_age_idx"),
        ),
        migrations.AddConstraint(
            model_name="tectacnoticeledger",
            constraint=models.UniqueConstraint(fields=("user", "kind", "key"), name="tectac_nledger_unique"),
        ),
    ]

from django.db import migrations, models


class Migration(migrations.Migration):
    """Core 1.18.40: ``TecTacPublishedInstaller.mtime_ns``, the file's modified time (nanoseconds) at the moment Core hashed it. The public installer
    route re-hashes only when the size or this time differ. Nullable, no data migration: a row published by 1.18.39 keeps None, re-hashes once and
    stores the time on its first serve. Written by hand, because Django is not installed on the development PC; check it with
    `manage.py makemigrations --check --dry-run` on the dev server: the model and this file must agree. It depends only on 0046."""

    dependencies = [
        ("tec_tac", "0046_published_installer"),
    ]

    operations = [
        migrations.AddField(
            model_name="tectacpublishedinstaller",
            name="mtime_ns",
            field=models.PositiveBigIntegerField(null=True),
        ),
    ]

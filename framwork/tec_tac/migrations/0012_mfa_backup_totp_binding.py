from django.db import migrations, models


def invalidate_unbound_backup_codes(apps, schema_editor):
    TecTacMfaBackupCode = apps.get_model("tec_tac", "TecTacMfaBackupCode")
    TecTacMfaBackupCode.objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0011_access_security")]

    operations = [
        migrations.AddField(
            model_name="tectacmfabackupcode",
            name="totp_fingerprint",
            field=models.CharField(blank=True, db_index=True, default="", max_length=64),
        ),
        migrations.RunPython(invalidate_unbound_backup_codes, migrations.RunPython.noop),
    ]

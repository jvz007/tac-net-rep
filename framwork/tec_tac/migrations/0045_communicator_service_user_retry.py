import importlib

from django.db import migrations

# 1.18.31: servers where 0038 already ran and logged "could not be made" (Tactical 1.6.1 columns) get the service user here. Idempotent: it never
# changes an existing row. It reuses 0038's code, so it also takes the historical model's defaults (1.18.32). Same dependency pin as 0038 (accounts 0042 exists in Tactical 1.5.2 and 1.6.1; a floating one breaks migrate).
_first = importlib.import_module("tec_tac.migrations.0038_communicator_service_user")


def create_service_user(apps, schema_editor):
    _first.create_service_user(apps, schema_editor)


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0044_core_secret"),
        ("accounts", "0042_copy_mesh_permission_to_terminal"),
    ]

    operations = [
        migrations.RunPython(create_service_user, migrations.RunPython.noop),
    ]

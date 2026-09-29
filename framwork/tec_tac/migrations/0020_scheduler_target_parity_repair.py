from importlib import import_module
from django.db import migrations


def repair_scheduler_targets(apps, schema_editor):
    # Re-run the frozen 0015 compatibility normalizer after later runtime target
    # hardening. This repairs installations where 0015 had already run before
    # the stricter parity rules shipped. Run history remains immutable because
    # 0015's repair function touches only TecTacSchedule rows.
    legacy = import_module("tec_tac.migrations.0015_scheduler_target_canonicalization")
    legacy.canonicalize_existing_targets(apps, schema_editor)


class Migration(migrations.Migration):
    dependencies = [("tec_tac", "0019_scheduler_endpoint_identity")]
    operations = [migrations.RunPython(repair_scheduler_targets, migrations.RunPython.noop)]

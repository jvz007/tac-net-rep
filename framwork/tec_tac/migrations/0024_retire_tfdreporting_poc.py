from django.db import migrations

OLD_NETWORK_TABLE = "tfdreporting_networkavailability"
OLD_CODENAME_PREFIX = "tfdreporting."


def report_and_remove_old_permissions(apps, schema_editor):
    """Count the network rows about to be dropped and delete the POC's permission rows.

    The ingest endpoint and its data are retired. A server backup taken before the
    upgrade keeps the old rows.
    """
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        if OLD_NETWORK_TABLE in set(connection.introspection.table_names(cursor)):
            cursor.execute(f"SELECT COUNT(*) FROM {OLD_NETWORK_TABLE}")
            dropped = cursor.fetchone()[0]
        else:
            dropped = 0
    print(f"  tfdreporting network availability rows dropped: {dropped}")
    model = apps.get_model("tec_tac", "ExtensionRolePermission")
    model.objects.filter(codename__startswith=OLD_CODENAME_PREFIX).delete()


class Migration(migrations.Migration):
    """Retire the tfdreporting network-availability POC.

    This does not touch the tfdreporting rows in django_migrations, so an older Core
    that is restored over this database still sees them as applied. Irreversible by
    design (approved by Johan, 8 October 2026): the dropped table is not recreated.
    """

    dependencies = [
        ("tec_tac", "0023_extension_role_permission"),
    ]

    operations = [
        migrations.RunPython(report_and_remove_old_permissions, migrations.RunPython.noop),
        migrations.RunSQL(
            sql=f"DROP TABLE IF EXISTS {OLD_NETWORK_TABLE}",
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]

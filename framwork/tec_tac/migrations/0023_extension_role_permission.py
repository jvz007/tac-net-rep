from django.db import migrations, models

TABLE = "tfdreporting_extensionrolepermission"


def create_if_missing(apps, schema_editor):
    """Create the table only when it is absent.

    An upgraded server already has it (the retired reporting proof of concept created it), so
    nothing changes. A fresh install no longer runs the old proof of concept's migrations, so this
    is what creates it.
    """
    model = apps.get_model("tec_tac", "ExtensionRolePermission")
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        existing = set(connection.introspection.table_names(cursor))
    if model._meta.db_table in existing:
        return
    schema_editor.create_model(model)


def drop_table(apps, schema_editor):
    model = apps.get_model("tec_tac", "ExtensionRolePermission")
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        existing = set(connection.introspection.table_names(cursor))
    if model._meta.db_table in existing:
        schema_editor.delete_model(model)


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0022_runtime_config"),
    ]

    operations = [
        # State only. The table and its constraint and index already exist on a
        # server that ran the old proof of concept migrations, with these exact names.
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.CreateModel(
                    name="ExtensionRolePermission",
                    fields=[
                        ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                        ("role_id", models.PositiveIntegerField()),
                        ("codename", models.CharField(max_length=150)),
                        ("granted", models.BooleanField(default=False)),
                        ("created_at", models.DateTimeField(auto_now_add=True)),
                        ("updated_at", models.DateTimeField(auto_now=True)),
                    ],
                    options={"ordering": ["role_id", "codename"], "db_table": TABLE},
                ),
                migrations.AddConstraint(
                    model_name="extensionrolepermission",
                    constraint=models.UniqueConstraint(fields=("role_id", "codename"), name="tfd_unique_role_permission"),
                ),
                migrations.AddIndex(
                    model_name="extensionrolepermission",
                    index=models.Index(fields=["role_id", "codename"], name="tfd_role_perm_lookup"),
                ),
            ],
        ),
        # A separate operation, after the state above, so it sees the model.
        migrations.RunPython(create_if_missing, drop_table),
    ]

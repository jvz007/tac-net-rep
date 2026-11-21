import logging

from django.db import migrations, transaction

logger = logging.getLogger(__name__)

# 1.17.76 (AD-50): the least-privilege Tactical service user of Core's agent.command row is made HERE, at install or upgrade time, never on the first send.
# system_commands._service_user() only reads and re-checks it. Keep the names in step with system_commands.SERVICE_USERNAME and SERVICE_ROLE.
USERNAME = "tectac-communicator"
ROLE = "Tec-Tac Communicator (send commands only)"
FLAG = "can_send_cmd"


def create_service_user(apps, schema_editor):
    """Create the role (can_send_cmd and no other flag) and the user (no sign-in, no usable password) when missing. Never changes an existing row: a deviating
    one is refused at run time (function_unavailable). A server without Tactical's accounts tables, or a Tactical without the flag, is skipped and logged."""
    try:
        with transaction.atomic(using=schema_editor.connection.alias):  # a savepoint: a fault here never poisons the migration's own transaction
            _make(apps, schema_editor)
    except Exception as exc:
        logger.exception("The Communicator service user could not be made (%s); agent.command refuses until the migration runs again.", type(exc).__name__)


_INTEGER_KINDS = {"IntegerField", "BigIntegerField", "SmallIntegerField", "PositiveIntegerField", "PositiveSmallIntegerField", "PositiveBigIntegerField",
                  "FloatField", "DecimalField", "AutoField", "BigAutoField", "SmallAutoField"}
_TEXT_KINDS = {"CharField", "TextField", "SlugField", "EmailField", "URLField", "GenericIPAddressField"}


def _row_values(columns, known, force_bool_false, now, model_defaults=None):
    """Return {column: value} for one INSERT. columns: (name, kind, null_ok, has_default, is_pk) read from the live table, so a column the historical model
    does not know (Tactical 1.6.1 adds some in accounts 0043 and 0044) is still filled and never trips a NOT NULL error. Pure function: tested without Django.
    force_bool_false: every boolean column is false unless known says otherwise, even one whose database default is true (least privilege).
    model_defaults: {column: value} the historical model's own defaults (what Django's create() wrote); used for a column the caller did not pass, after the
    force_bool_false rule and before the neutral values, which remain for columns the model does not know."""
    model_defaults = model_defaults or {}
    values = {}
    for name, kind, null_ok, has_default, is_pk in columns:
        if is_pk:
            continue
        if name in known:
            values[name] = known[name]
        elif kind == "BooleanField" and force_bool_false:
            values[name] = False
        elif name in model_defaults:
            values[name] = model_defaults[name]
        elif null_ok or has_default:
            continue
        elif kind == "BooleanField":
            values[name] = False
        elif kind in _INTEGER_KINDS:
            values[name] = 0
        elif kind in _TEXT_KINDS:
            values[name] = ""
        elif kind == "JSONField":
            values[name] = "{}"
        elif kind == "DateTimeField":
            values[name] = now
        elif kind == "DateField":
            values[name] = now.date()
        elif kind == "UUIDField":
            import uuid
            values[name] = str(uuid.uuid4())
        else:
            raise ValueError(f"no safe value for the NOT NULL column {name} ({kind})")
    return values


def _model_defaults(model, connection):
    """{column: database-ready default} for every concrete field of the historical model that has a default and is not the pk. A model without
    concrete_fields (an older stand-in) gives {}. Callable defaults (JSON dicts, choices) are evaluated, as Django's create() did."""
    defaults = {}
    for field in getattr(model._meta, "concrete_fields", ()):
        if field.column == model._meta.pk.column or not field.has_default():
            continue
        defaults[field.column] = field.get_db_prep_save(field.get_default(), connection)
    return defaults


def _insert(schema_editor, model, known, force_bool_false):
    """INSERT one row into model's table with the live column list (not the historical model's). Columns the model knows get the model's defaults."""
    from django.utils import timezone

    conn = schema_editor.connection
    table = model._meta.db_table
    pk = model._meta.pk.column
    with conn.cursor() as cursor:
        desc = conn.introspection.get_table_description(cursor, table)
        columns = [(d.name, conn.introspection.get_field_type(d.type_code, d), bool(d.null_ok), d.default is not None, d.name == pk) for d in desc]
        values = _row_values(columns, known, force_bool_false, timezone.now(), _model_defaults(model, conn))
        names = list(values)
        columns_sql = ", ".join(conn.ops.quote_name(n) for n in names)
        sql = f"INSERT INTO {conn.ops.quote_name(table)} ({columns_sql}) VALUES ({', '.join(['%s'] * len(names))})"
        cursor.execute(sql, [values[n] for n in names])


def _make(apps, schema_editor):
    from django.contrib.auth.hashers import make_password

    Role = apps.get_model("accounts", "Role")
    User = apps.get_model("accounts", "User")
    db = schema_editor.connection.alias
    if not any(f.name == FLAG for f in Role._meta.get_fields()):
        logger.warning("Tactical's Role has no %s; the Communicator service user was not made.", FLAG)
        return
    role = Role.objects.using(db).filter(name=ROLE).first()
    if role is None:
        # Raw INSERT over the live columns: the historical Role (accounts 0042) lacks columns that 1.6.1 added as NOT NULL without a database default.
        _insert(schema_editor, Role, {"name": ROLE, FLAG: True}, True)
        role = Role.objects.using(db).filter(name=ROLE).first()
    if not User.objects.using(db).filter(username=USERNAME).exists():
        _insert(schema_editor, User, {"username": USERNAME, "email": "", "password": make_password(None), "is_active": True, "is_superuser": False,
                                      "is_staff": False, "block_dashboard_login": True, "role_id": role.pk}, False)


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0037_creation_scope_and_delegation"),
        # Pinned, not "__latest__": a floating dependency resolves to accounts.0044 on Tactical 1.6.1 while
        # tec_tac.0038 is already applied, and migrate then fails with InconsistentMigrationHistory.
        # 0042 is the newest accounts migration in both Tactical 1.5.2 and 1.6.1 (can_send_cmd exists since 0017).
        ("accounts", "0042_copy_mesh_permission_to_terminal"),
    ]

    operations = [
        migrations.RunPython(create_service_user, migrations.RunPython.noop),
    ]

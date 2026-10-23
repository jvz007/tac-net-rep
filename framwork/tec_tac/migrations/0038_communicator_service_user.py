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
        values = {f.name: (f.name == FLAG) for f in Role._meta.get_fields() if f.get_internal_type() == "BooleanField"}
        role = Role.objects.using(db).create(name=ROLE, **values)
    if not User.objects.using(db).filter(username=USERNAME).exists():
        User.objects.using(db).create(username=USERNAME, email="", password=make_password(None), is_active=True, is_superuser=False, is_staff=False,
                                      block_dashboard_login=True, role=role)


class Migration(migrations.Migration):
    dependencies = [
        ("tec_tac", "0037_creation_scope_and_delegation"),
        ("accounts", "__latest__"),
    ]

    operations = [
        migrations.RunPython(create_service_user, migrations.RunPython.noop),
    ]

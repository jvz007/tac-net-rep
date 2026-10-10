"""Runtime check for Core 1.17.14 upload ceiling setting (CQ40). It did NOT run on the development PC (Django is not installed there).

Run it on the dev server through Tactical's manage.py shell, after migration 0026 has been applied (`manage.py migrate`):

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/runtime-settings-upload-runtime-1.17.14.py

It proves what the stub tests (tests/runtime-settings-upload-1.17.14.py, tests/tactical-operations-upload-setting-1.17.14.py) cannot:

1. migration 0026 added the column, a row that existed before reads as 10, and the getter returns 10 MiB;
2. `RuntimeSettingsView.patch` stores the new value on the real singleton row, and `get_tactical_upload_max_bytes()` and the executor's
   `upload_ceiling_bytes()` read it back at once (no restart);
3. each changed setting writes its own strict audit row in Tactical's real AuditLog, with `object_id` the setting name and the before and
   after values, and a second PATCH with the same value writes none;
4. the permission split: a user with a role holding `core.runtime_settings.manage` who is not a superuser gets 403 for the upload key and
   can still change the timeout; a superuser changes both in one request and gets two audit rows;
5. a bad value (bool, float, string, 0, 26) is refused with 400 and changes nothing.

Everything happens inside one database transaction that is rolled back at the end. The audit rows it wrote are rolled back with it. The view
is called directly (its permission and throttle classes are covered by the stub tests); only the request's user and data are supplied. It
prints PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import sys
import types

from accounts.models import Role, User
from django.db import transaction
from logs.models import AuditLog
from rest_framework.exceptions import PermissionDenied
from tec_tac import runtime_settings as rs
from tec_tac.models import TecTacRuntimeConfig
from tec_tac.tactical_operations import upload_ceiling_bytes

UP, TO = rs.SETTING_TACTICAL_UPLOAD_MAX_MIB, rs.SETTING_MODULE_REGISTER_TIMEOUT
MIB = 2**20
RESULTS = []


class Rollback(Exception):
    pass


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


def rows(setting):
    return AuditLog.objects.filter(object_type="runtime_settings", debug_info__object_id=setting).order_by("-id")


def run():
    manager_role = Role.objects.create(name="tectac-runtime-upload-manager")
    superuser = User.objects.create(username="tectac-runtime-upload-super", email="s@example.invalid", is_superuser=True)
    manager = User.objects.create(username="tectac-runtime-upload-manager", email="m@example.invalid", role=manager_role)
    config = TecTacRuntimeConfig.current()

    def patch(user, data):
        return rs.RuntimeSettingsView().patch(types.SimpleNamespace(user=user, data=data))

    def s1_migration_and_default():
        assert hasattr(config, "tactical_operation_upload_max_mib"), "migration 0026 has not run"
        TecTacRuntimeConfig.objects.filter(pk=config.pk).update(tactical_operation_upload_max_mib=10)
        assert rs.get_tactical_upload_max_bytes() == 10 * MIB and upload_ceiling_bytes() == 10 * MIB

    def s2_patch_and_read_back():
        answer = patch(superuser, {UP: 15})
        assert answer.status_code == 200 and answer.data[UP]["value"] == 15 and answer.data[UP]["bytes"] == 15 * MIB, answer.data
        assert TecTacRuntimeConfig.objects.get(pk=config.pk).tactical_operation_upload_max_mib == 15
        assert rs.get_tactical_upload_max_bytes() == 15 * MIB and upload_ceiling_bytes() == 15 * MIB, "the executor did not see the new value at once"

    def s3_audit_rows():
        row = rows(UP).first()
        assert row is not None and row.username == superuser.username, row
        assert row.before_value == {UP: 10} and row.after_value == {UP: 15}, (row.before_value, row.after_value)
        count = rows(UP).count()
        patch(superuser, {UP: 15})
        assert rows(UP).count() == count, "the same value wrote an audit row"

    def s4_permission_split():
        for data in ({UP: 20}, {TO: 60, UP: 20}):
            try:
                patch(manager, data)
            except PermissionDenied:
                pass
            except Exception as exc:  # noqa: BLE001
                # a role with no manage grant is refused at the first gate; that is also a 403
                assert "permission" in str(exc).lower(), exc
            else:
                raise AssertionError(f"a non-superuser changed the upload limit: {data}")
        assert TecTacRuntimeConfig.objects.get(pk=config.pk).tactical_operation_upload_max_mib == 15
        before = rows(TO).count()
        answer = patch(superuser, {TO: 90, UP: 25})
        assert answer.status_code == 200 and answer.data[TO]["value"] == 90 and answer.data[UP]["value"] == 25, answer.data
        assert rows(TO).count() == before + 1 and rows(UP).first().after_value == {UP: 25}, "one row per changed setting"

    def s5_bad_values():
        for bad in (True, 12.5, "12", None, 0, 26):
            answer = patch(superuser, {UP: bad})
            assert answer.status_code == 400, (bad, answer.status_code)
        assert TecTacRuntimeConfig.objects.get(pk=config.pk).tactical_operation_upload_max_mib == 25
        assert patch(superuser, {}).status_code == 400 and patch(superuser, {"nope": 1}).status_code == 400

    step("1 the column exists, an older row reads as 10", s1_migration_and_default)
    step("2 PATCH stores the value and the executor reads it back at once", s2_patch_and_read_back)
    step("3 each change writes its own strict audit row, a repeat writes none", s3_audit_rows)
    step("4 only a superuser changes the upload limit, the timeout keeps its own rule", s4_permission_split)
    step("5 bad values and an empty body are refused and change nothing", s5_bad_values)


try:
    with transaction.atomic():
        run()
        raise Rollback()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)

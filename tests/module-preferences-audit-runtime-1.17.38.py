"""Runtime check for Core 1.17.38 module preference audit rows (core.module_preferences 1.2.0). It did NOT run on the development PC
(Django is not installed there), so the real AuditLog rows, the rollback and the database refusals can only be proved on the dev server.

Run it on the dev server through Tactical's manage.py shell, after Core 1.17.38 is installed:

    cp /opt/tec-tac-src/tests/module-preferences-audit-runtime-1.17.38.py /tmp/ && chmod 644 /tmp/module-preferences-audit-runtime-1.17.38.py
    sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/module-preferences-audit-runtime-1.17.38.py'

It proves what the stub test (tests/module-preferences-audit-1.17.38.py) cannot: that the real AuditLog holds one row for each add, modify and
delete, with the object id, the metadata and no value; that a read and an unchanged write add no row; that a change whose audit row cannot be
written is refused with audit_failed (503) and leaves the stored value as it was; and that a person who may not use a module with permission
groups is refused before anything is written. Tactical's manage.py shell is not an installed module, so the public functions refuse it; this
probe calls the private functions, which record source 'browser' (module_verified false). The module_python rows are proved by the stub test.

Everything runs inside one database transaction that is rolled back at the end, so no user, preference or AuditLog row is left behind. It prints
PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import uuid

from accounts.models import User
from django.db import transaction
from logs.models import AuditLog
from tec_tac import audit, notices
from tec_tac import module_preferences as mp
from tec_tac.models import TecTacModulePreference
from tec_tac.registry import get_plugins

RESULTS = []
MARK = "wspref-" + uuid.uuid4().hex[:8]
VALUE_MARK = "VALUE-" + uuid.uuid4().hex[:10]


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


def make_user(suffix):
    user = User(username=f"{MARK}-{suffix}", email=f"{MARK}-{suffix}@example.invalid")
    user.set_password(uuid.uuid4().hex)
    user.save()
    return user


def enabled_modules():
    """(a module with no permission groups, a module with some), each the first installed, enabled extension of its kind."""
    open_id = restricted_id = None
    for plugin in get_plugins():
        if plugin.plugin_type != "extension":
            continue
        try:
            module_id = notices.enabled_extension_id(plugin.plugin_id)
        except notices.NoticeError:
            continue
        permissions = {code for _, values in plugin.permission_groups for code in values}
        if permissions and restricted_id is None:
            restricted_id = module_id
        if not permissions and open_id is None:
            open_id = module_id
    return open_id, restricted_id


def rows_for(user, module_id):
    return AuditLog.objects.filter(username=user.username, object_type="module_preference",
                                   debug_info__object_id=f"{module_id}/header-collapsed").order_by("id")


def run():
    open_id, restricted_id = enabled_modules()
    module_id = open_id or restricted_id
    if module_id is None:
        raise RuntimeError("no installed, enabled extension to test with")
    alice = make_user("alice")
    state = {}

    def add_row_and_modify_and_delete():
        mp._set(alice, "header-collapsed", True, module_id=module_id)
        added = list(rows_for(alice, module_id))
        assert len(added) == 1, f"one row on add, got {len(added)}"
        row = added[0]
        assert row.action == "add" and row.object_type == "module_preference", (row.action, row.object_type)
        assert row.message == "Tec-Tac module preference add.", row.message
        debug = row.debug_info
        assert debug["module_id"] == "core" and debug["object_id"] == f"{module_id}/header-collapsed", debug.get("object_id")
        meta = debug["metadata"]
        assert meta["module"] == module_id and meta["name"] == "header-collapsed", meta
        assert meta["size_bytes"] == 4 and meta["source"] == "browser" and meta["module_verified"] is False, meta
        assert meta["user_id"] == alice.pk, meta
        assert row.before_value is None and row.after_value is None, "no value is recorded before or after"
        mp._set(alice, "header-collapsed", False, module_id=module_id)
        modified = list(rows_for(alice, module_id))
        assert [r.action for r in modified] == ["add", "modify"], [r.action for r in modified]
        assert modified[1].debug_info["metadata"]["size_bytes"] == 5, "the size of the new value"
        assert mp._delete(alice, "header-collapsed", module_id=module_id) is True, "delete removes the row"
        deleted = list(rows_for(alice, module_id))
        assert [r.action for r in deleted] == ["add", "modify", "delete"], [r.action for r in deleted]
        assert "size_bytes" not in deleted[2].debug_info["metadata"], "a delete carries no size"
        state["rows"] = len(deleted)

    def reads_and_unchanged_writes_add_no_row():
        before = rows_for(alice, module_id).count()
        mp._get(alice, "header-collapsed", module_id=module_id)
        mp._list_for(alice, module_id=module_id)
        mp._set(alice, "header-collapsed", True, module_id=module_id)
        mark = rows_for(alice, module_id).count()
        mp._set(alice, "header-collapsed", True, module_id=module_id)
        assert rows_for(alice, module_id).count() == mark == before + 1, "an unchanged write adds no row"
        assert mp._delete(alice, "header-collapsed", module_id=module_id) is True
        assert mp._delete(alice, "header-collapsed", module_id=module_id) is False, "a missing name answers False"
        assert rows_for(alice, module_id).count() == mark + 1, "a delete of a missing name adds no row"

    def the_value_is_never_recorded():
        mp._set(alice, "header-collapsed", {"text": VALUE_MARK, "nested": [VALUE_MARK]}, module_id=module_id)
        for row in AuditLog.objects.filter(username=alice.username, object_type="module_preference"):
            text = repr(row.debug_info) + repr(row.message) + repr(row.before_value) + repr(row.after_value)
            assert VALUE_MARK not in text, "the stored value appears in an audit row"

    def audit_failure_rolls_back():
        mp._set(alice, "keep-me", "before", module_id=module_id)
        original = audit._auditlog_model

        def broken():
            raise RuntimeError("audit store down for this probe")

        audit._auditlog_model = broken
        try:
            try:
                mp._set(alice, "keep-me", "after", module_id=module_id)
            except mp.ModulePreferenceError as exc:
                assert exc.code == "audit_failed" and exc.status_code == 503, (exc.code, exc.status_code)
            else:
                raise AssertionError("the change was saved without its audit row")
        finally:
            audit._auditlog_model = original
        assert mp._get(alice, "keep-me", module_id=module_id) == "before", "the rolled back value is the one stored before"

    def a_person_who_may_not_use_the_module_is_refused():
        if restricted_id is None:
            print("       skipped: no installed, enabled module with permission groups on this server")
            return
        carol = make_user("carol")
        try:
            mp._set(carol, "header-collapsed", True, module_id=restricted_id)
        except mp.ModulePreferenceError as exc:
            assert exc.code == "module_not_allowed" and exc.status_code == 403, (exc.code, exc.status_code)
        else:
            raise AssertionError("a person without the module's permissions wrote a preference")
        assert not AuditLog.objects.filter(username=carol.username).exists(), "no audit row for the refused person"
        assert not TecTacModulePreference.objects.filter(user_id=carol.pk).exists(), "no preference row for the refused person"

    step(f"add, modify and delete each write one AuditLog row ({module_id})", add_row_and_modify_and_delete)
    step("reads and unchanged writes add no row", reads_and_unchanged_writes_add_no_row)
    step("the stored value never appears in an audit row", the_value_is_never_recorded)
    step("an audit failure refuses the change and keeps the stored value", audit_failure_rolls_back)
    step("a person who may not use a module with permission groups is refused", a_person_who_may_not_use_the_module_is_refused)

    raise Rollback()


try:
    with transaction.atomic():
        run()
except Rollback:
    pass

left = User.objects.filter(username__startswith="wspref-").count()
print("no probe rows left" if left == 0 else f"FAIL {left} probe user(s) left behind")
RESULTS.append(left == 0)
if all(RESULTS):
    print("module-preferences-audit-runtime-1.17.38: ok")
else:
    print("module-preferences-audit-runtime-1.17.38: FAILED")
    raise SystemExit(1)

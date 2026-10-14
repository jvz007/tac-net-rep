"""Runtime check for Core 1.17.35 module user preferences (core.module_preferences 1.0.0; 1.1.0 from 1.17.37). It did NOT run on the development
PC (Django is not installed there), so the migration 0031, the unique constraint and the JSON column can only be proved on the dev server.

Since 1.17.37 this probe calls the private functions (_get, _set, _delete, _list_for). Tactical's manage.py shell is not an installed module, so the
public functions refuse it with caller_not_allowed (403), as they should. The caller check itself is proved by tests/module-preferences-caller-1.17.37.py.

Run it on the dev server through Tactical's manage.py shell, after the migration 0031_module_preferences has run:

    cp /opt/tec-tac-src/tests/module-preferences-runtime-1.17.35.py /tmp/ && chmod 644 /tmp/module-preferences-runtime-1.17.35.py
    sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/module-preferences-runtime-1.17.35.py'

It proves what the stub test (tests/module-preferences-1.17.35.py) cannot: that the real TecTacModulePreference table stores and reads the
JSON value, that a second write to the same person, module and name updates one row, that the database refuses a second row with the
same person, module and name (the unique constraint), that another person never sees the row, that the 50 names limit is enforced on the
real table, that a refused value writes nothing, and that deleting the person removes their rows (the cascade).

It uses the first installed, enabled extension it finds (the module id is checked by the real notices.enabled_extension_id). Everything runs
inside one database transaction that is rolled back at the end, so no user or row is left behind. It prints PASS or FAIL for each step and
exits with status 1 when any step fails.
"""
import uuid

from accounts.models import User
from django.db import IntegrityError, transaction
from tec_tac import module_preferences as mp, notices
from tec_tac.models import TecTacModulePreference
from tec_tac.registry import get_plugins

RESULTS = []
MARK = "wspref-" + uuid.uuid4().hex[:8]


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


def first_enabled_module():
    for plugin in get_plugins():
        if plugin.plugin_type != "extension":
            continue
        try:
            return notices.enabled_extension_id(plugin.plugin_id)
        except notices.NoticeError:
            continue
    raise RuntimeError("no installed, enabled extension to test with")


def run():
    module_id = first_enabled_module()
    alice = make_user("alice")
    bob = make_user("bob")
    state = {}

    def round_trip():
        assert mp._get(alice, "header-collapsed", module_id=module_id, default="none") == "none", "a missing name gives the default"
        assert mp._set(alice, "header-collapsed", True, module_id=module_id) is True, "set returns the value"
        assert mp._get(alice, "header-collapsed", module_id=module_id) is True, "the real column reads back the JSON value"
        assert mp._list_for(alice, module_id=module_id) == {"header-collapsed": True}, "list_for shows the row"
        assert mp._delete(alice, "header-collapsed", module_id=module_id) is True, "delete removes it"
        assert mp._get(alice, "header-collapsed", module_id=module_id, default="gone") == "gone", "and it is gone"

    def upsert_keeps_one_row():
        mp._set(alice, "tabs", {"order": ["a", "b"], "open": 2}, module_id=module_id)
        mp._set(alice, "tabs", {"order": ["b", "a"]}, module_id=module_id)
        rows = TecTacModulePreference.objects.filter(user_id=alice.pk, module_id=module_id, name="tabs")
        assert rows.count() == 1, f"one row, got {rows.count()}"
        assert rows.get().value == {"order": ["b", "a"]}, "the value is replaced, not merged"

    def unique_constraint_holds():
        try:
            with transaction.atomic():
                TecTacModulePreference.objects.create(user_id=alice.pk, module_id=module_id, name="tabs", value=1)
        except IntegrityError:
            pass
        else:
            raise AssertionError("the database accepted a second row for the same person, module and name")

    def self_only():
        assert mp._get(bob, "tabs", module_id=module_id, default="fresh") == "fresh", "bob never sees alice's row"
        assert mp._list_for(bob, module_id=module_id) == {}, "bob's list is empty"
        assert mp._delete(bob, "tabs", module_id=module_id) is False, "bob cannot delete it"
        assert mp._get(alice, "tabs", module_id=module_id) == {"order": ["b", "a"]}, "and alice still has it"

    def refused_value_writes_nothing():
        before = TecTacModulePreference.objects.filter(user_id=alice.pk, module_id=module_id).count()
        for bad in ([[[[[[1]]]]]], "x" * 5000):
            try:
                mp._set(alice, "big", bad, module_id=module_id)
            except mp.ModulePreferenceError as exc:
                assert exc.code == "invalid_value", exc.code
            else:
                raise AssertionError("a refused value was stored")
        assert TecTacModulePreference.objects.filter(user_id=alice.pk, module_id=module_id).count() == before, "no row was written"

    def fifty_names_limit():
        for n in range(mp.MAX_NAMES_PER_MODULE - TecTacModulePreference.objects.filter(user_id=bob.pk, module_id=module_id).count()):
            mp._set(bob, f"limit-{n:02d}", n, module_id=module_id)
        assert TecTacModulePreference.objects.filter(user_id=bob.pk, module_id=module_id).count() == mp.MAX_NAMES_PER_MODULE, "50 rows"
        try:
            mp._set(bob, "limit-fifty-one", 1, module_id=module_id)
        except mp.ModulePreferenceError as exc:
            assert exc.code == "preference_limit", exc.code
        else:
            raise AssertionError("a 51st name was stored")
        assert TecTacModulePreference.objects.filter(user_id=bob.pk, module_id=module_id).count() == mp.MAX_NAMES_PER_MODULE, "still 50"

    def deleting_the_person_removes_the_rows():
        before = TecTacModulePreference.objects.filter(user_id=bob.pk).count()
        assert before >= 1, "bob has rows to remove"
        bob.delete()
        assert TecTacModulePreference.objects.filter(user_id=bob.pk).count() == 0, "the cascade removed every row"
        state["cascade"] = before

    step(f"round trip on the real table ({module_id})", round_trip)
    step("a second write updates one row", upsert_keeps_one_row)
    step("the database refuses a second row (unique constraint)", unique_constraint_holds)
    step("another person never sees or deletes the row", self_only)
    step("a refused value writes nothing", refused_value_writes_nothing)
    step("the 50 names limit holds on the real table", fifty_names_limit)
    step("deleting the person removes their rows", deleting_the_person_removes_the_rows)

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
    print("module-preferences-runtime-1.17.35: ok")
else:
    print("module-preferences-runtime-1.17.35: FAILED")
    raise SystemExit(1)

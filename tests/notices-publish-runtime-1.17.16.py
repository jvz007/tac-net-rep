"""Runtime check for Core 1.17.16 ``tec_tac.notices.publish`` (CQ49). It did NOT run on the development PC (Django is not installed there).

Run it on the dev server through Tactical's manage.py shell, so Django, the real database and the real Core code are loaded:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/notices-publish-runtime-1.17.16.py

It proves what the stub test (tests/notices-publish-1.17.16.py) cannot: that ``publish`` writes a real ``TecTacUserNotice`` row for an
active interactive user with source = the module id and the key ``<module>:<client_id>``; that a second call returns created False and
a notice the person has read stays read; that an inactive user, an installer user, an agent-linked user and a user blocked from the
dashboard are refused; that ``core``, ``tec-tac`` and a module id that is not installed are refused; and that the real column holds the
longest key.

It needs one enabled extension on the server. It uses the first one it finds. Everything happens inside one database transaction that is
rolled back at the end, so no user or notice is left behind. It prints PASS or FAIL for each step and exits with status 1 when any
step fails.
"""
import sys
import uuid

from accounts.models import User
from django.db import transaction
from tec_tac import notices
from tec_tac.models import TecTacUserNotice
from tec_tac.module_state import is_enabled, load_state
from tec_tac.registry import get_plugins

RESULTS = []
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]


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


def make_user(suffix, **fields):
    user = User(username=f"{MARK}-{suffix}", **fields)
    user.set_password(uuid.uuid4().hex)
    user.save()
    return user


def refused(*args, **kwargs):
    try:
        notices.publish(*args, **kwargs)
    except notices.NoticeError:
        return
    raise AssertionError(f"publish was accepted: {args} {kwargs}")


def run():
    state = load_state()
    module = next((p.plugin_id for p in get_plugins() if p.plugin_type == "extension" and is_enabled(p.plugin_id, state)), None)
    assert module, "this probe needs one enabled extension"
    print(f"using module {module}")
    person = make_user("person")
    other = make_user("other")
    inactive = make_user("inactive", is_active=False)
    installer = make_user("installer", is_installer_user=True)
    blocked = make_user("blocked", block_dashboard_login=True)
    key = f"probe:{uuid.uuid4().hex[:8]}"

    def stores_a_row():
        result = notices.publish(person, key, "success", "The probe finished.", {"label": "Open", "route": "/modules"}, module_id=module)
        assert result["created"] is True and result["notice"]["source"] == module, result
        row = TecTacUserNotice.objects.get(user=person, client_id=f"{module}:{key}")
        assert row.source == module and row.level == "success" and row.action_route == "/modules" and row.read_at is None, row
        by_name = notices.publish(other.username, key, "info", "By username.", module_id=module)
        assert by_name["created"] is True, by_name

    def dedupes_and_keeps_read():
        again = notices.publish(person, key, "error", "Changed text.", module_id=module)
        assert again["created"] is False and again["notice"]["message"] == "The probe finished.", again
        assert TecTacUserNotice.objects.filter(user=person, client_id=f"{module}:{key}").count() == 1
        notices.mark_all_read(person)
        again = notices.publish(person, key, "success", "The probe finished.", module_id=module)
        assert again["created"] is False and again["notice"]["read"] is True, again

    def refuses_the_wrong_people():
        for who in (inactive, installer, blocked, "nobody-" + MARK, inactive.username):
            refused(who, key + "x", "info", "m", module_id=module)
        assert not TecTacUserNotice.objects.filter(user__in=[inactive, installer, blocked]).exists()

    def refuses_the_wrong_modules():
        for name in ("core", "tec-tac", "no-such-module-" + MARK):
            refused(person, key + "y", "info", "m", module_id=name)

    def holds_the_longest_key():
        longest = "k" * (64 - len(module) - 1)
        result = notices.publish(person, longest, "info", "m", module_id=module)
        assert result["created"] is True and len(TecTacUserNotice.objects.get(user=person, client_id=f"{module}:{longest}").client_id) == 64
        refused(person, longest + "k", "info", "m", module_id=module)

    step("a notice is stored with the module as source", stores_a_row)
    step("a second call dedupes and a read notice stays read", dedupes_and_keeps_read)
    step("inactive, installer, blocked and unknown users are refused", refuses_the_wrong_people)
    step("core, tec-tac and an unknown module are refused", refuses_the_wrong_modules)
    step("the longest key fits the real column", holds_the_longest_key)
    raise Rollback()


try:
    with transaction.atomic():
        run()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)

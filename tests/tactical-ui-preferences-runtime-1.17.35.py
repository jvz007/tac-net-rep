"""Runtime check for Core 1.17.35 Tactical UI preferences (GET and PUT /api/tfd/account/tactical-ui/). It did NOT run on the development PC
(Django is not installed there), so the real model choices and the real save can only be proved on the dev server.

Run it on the dev server through Tactical's manage.py shell (after Core 1.17.35 is installed):

    cp /opt/tec-tac-src/tests/tactical-ui-preferences-runtime-1.17.35.py /tmp/ && chmod 644 /tmp/tactical-ui-preferences-runtime-1.17.35.py
    sudo -u tactical bash -c 'cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /tmp/tactical-ui-preferences-runtime-1.17.35.py'

It proves what the stub test (tests/tactical-ui-preferences-1.17.35.py) cannot: that the real accounts.User columns take each new value, that
the choices come from Tactical's own model fields, that one invalid value in a mixed request saves nothing, that block_dashboard_login is
refused, and that the hot-path context carries the scalars. Everything runs inside one transaction that is rolled back at the end. It prints
PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import uuid

from accounts.models import User
from django.db import transaction
from tec_tac import account_self_service as svc

RESULTS = []
MARK = "wspref-ui-" + uuid.uuid4().hex[:8]


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


def run():
    user = User(username=MARK, email=f"{MARK}@example.invalid", is_superuser=True)
    user.set_password(uuid.uuid4().hex)
    user.save()
    values = {
        "dark_mode": False, "show_community_scripts": False, "default_agent_tbl_tab": "server", "client_tree_sort": "alpha",
        "client_tree_splitter": 30, "loading_bar_color": "deep-purple-3", "dash_info_color": "#1b5e20", "dash_positive_color": "positive",
        "dash_negative_color": "negative", "dash_warning_color": "#ffcc00", "clear_search_when_switching": False,
        "date_format": "YYYY-MM-DD HH:mm",
    }

    def round_trip():
        answer = svc.update_tactical_ui_preferences(user, values)
        for name, value in values.items():
            assert answer[name] == value, f"{name} in the answer: {answer[name]!r}"
        fresh = User.objects.get(pk=user.pk)
        for name, value in values.items():
            assert getattr(fresh, name) == value, f"{name} stored on the real column: {getattr(fresh, name)!r}"
        got = svc.tactical_ui_preferences(fresh)
        assert [c["value"] for c in got["default_agent_tbl_choices"]] == ["server", "workstation", "mixed"], "tab choices from the model"
        assert [c["value"] for c in got["client_tree_sort_choices"]] == ["alphafail", "alpha"], "sort choices from the model"

    def empty_date_format_is_null():
        svc.update_tactical_ui_preferences(user, {"date_format": ""})
        assert User.objects.get(pk=user.pk).date_format is None, "an empty date format stores null"

    def mixed_invalid_saves_nothing():
        before = {name: getattr(User.objects.get(pk=user.pk), name) for name in values}
        try:
            svc.update_tactical_ui_preferences(user, {"dark_mode": True, "client_tree_splitter": 100})
        except svc.AccountSelfServiceError:
            pass
        else:
            raise AssertionError("splitter 100 was accepted")
        after = {name: getattr(User.objects.get(pk=user.pk), name) for name in values}
        assert before == after, "the valid dark_mode in the same request was not saved"

    def block_dashboard_login_refused():
        try:
            svc.update_tactical_ui_preferences(user, {"block_dashboard_login": True})
        except svc.AccountSelfServiceError as exc:
            assert "Unknown Tactical UI preference" in str(exc), str(exc)
        else:
            raise AssertionError("block_dashboard_login was accepted")
        assert User.objects.get(pk=user.pk).block_dashboard_login is False, "the login block is untouched"

    def hot_path_context():
        context = svc.tactical_ui_context(User.objects.get(pk=user.pk))
        assert {"agent_dblclick_action", "url_action_id", "can_run_url_actions"} <= set(context), "the three keys stay"
        assert context["client_tree_splitter"] == 30 and context["date_format"] == "YYYY-MM-DD HH:mm", "the scalars are published"
        assert "default_agent_tbl_choices" not in context, "no choice list on the hot path"

    step("save every new Tactical UI preference on the real User row", round_trip)
    step("an empty date format stores null", empty_date_format_is_null)
    step("one invalid value in a mixed request saves nothing", mixed_invalid_saves_nothing)
    step("block_dashboard_login is refused", block_dashboard_login_refused)
    step("the runtime context carries the scalars, not the choice lists", hot_path_context)

    raise Rollback()


try:
    with transaction.atomic():
        run()
except Rollback:
    pass

left = User.objects.filter(username__startswith="wspref-ui-").count()
print("no probe rows left" if left == 0 else f"FAIL {left} probe user(s) left behind")
RESULTS.append(left == 0)
if all(RESULTS):
    print("tactical-ui-preferences-runtime-1.17.35: ok")
else:
    print("tactical-ui-preferences-runtime-1.17.35: FAILED")
    raise SystemExit(1)

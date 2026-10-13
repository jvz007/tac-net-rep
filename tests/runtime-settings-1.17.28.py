"""Runtime check for Core 1.17.28: the private mail relay is withdrawn, and its stored value is cleared once. DEV SERVER ONLY.
It did NOT run on the development PC (Django, Tactical and the database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/runtime-settings-1.17.28.py

Run it after Core 1.17.28 is on the dev server. Migrations are unchanged in 1.17.28, so there is nothing new to migrate.
Everything is written inside one transaction that is ROLLED BACK at the end, audit rows included. Nothing is sent: the mail host lookup is
replaced by a stub and the Priority 1 send is never reached. Prints PASS or FAIL for each step.

Checks: the GET answer has no priority_mail_private_relay key; a stored True in the real row is cleared by clear_retired_private_relay()
with exactly one strict audit row in Tactical's AuditLog (modify, runtime_settings, before true, after false); a second call writes no
row; a stored False writes no row; a mail server on 10.0.0.5 is refused by Core's Priority 1 host check with the column True (ignored).
"""
import sys

from django.db import transaction
from logs.models import AuditLog
from tec_tac import priority_mail
from tec_tac.models import TecTacRuntimeConfig
from tec_tac.runtime_settings import clear_retired_private_relay, serialize_runtime_settings

RESULTS = []
KEY = "priority_mail_private_relay"


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


def check(cond, message=""):
    if not cond:
        raise AssertionError(message)


def last_id():
    row = AuditLog.objects.order_by("-pk").first()
    return row.pk if row else 0


def new_rows(since):
    return list(AuditLog.objects.filter(pk__gt=since).order_by("pk"))


ANSWERS = {}
priority_mail.resolve_addresses = lambda name: list(ANSWERS[name])


def set_column(value):
    config = TecTacRuntimeConfig.current()
    config.priority_mail_private_relay = value
    config.save(update_fields=["priority_mail_private_relay"])
    return config


try:
    with transaction.atomic():
        def get_has_no_key():
            check(KEY not in serialize_runtime_settings(), "the GET answer must not carry the retired key")

        def stored_true_is_cleared_once():
            set_column(True)
            since = last_id()
            check(clear_retired_private_relay() is True, "a stored True must be cleared")
            check(TecTacRuntimeConfig.current().priority_mail_private_relay is False, "the column must read False")
            rows = new_rows(since)
            check(len(rows) == 1, ("exactly one audit row", [r.pk for r in rows]))
            row = rows[0]
            check(row.object_type == "runtime_settings" and row.action == "modify", (row.object_type, row.action))
            check(row.debug_info.get("object_id") == KEY, row.debug_info)
            since = last_id()
            check(clear_retired_private_relay() is False and new_rows(since) == [], "a second call must write no row")

        def stored_false_writes_nothing():
            set_column(False)
            since = last_id()
            check(clear_retired_private_relay() is False, "a stored False must write nothing")
            check(new_rows(since) == [], "a stored False must write no row")

        def column_ignored_for_core_send():
            set_column(True)
            ANSWERS["relay.probe"] = ["10.0.0.5"]
            check(priority_mail.public_refusal("relay.probe") == priority_mail.REFUSED, "a private server is refused with the column True")
            set_column(False)

        step("GET carries no retired key", get_has_no_key)
        step("a stored True is cleared once with one audit row", stored_true_is_cleared_once)
        step("a stored False writes no row", stored_false_writes_nothing)
        step("a private mail server is refused with the column True", column_ignored_for_core_send)
        raise Rollback()
except Rollback:
    pass

passed = sum(1 for ok in RESULTS if ok)
print(f"{passed}/{len(RESULTS)} runtime checks passed for runtime-settings-1.17.28 (rolled back, nothing kept)")
sys.exit(0 if all(RESULTS) and len(RESULTS) == 4 else 1)

"""Runtime check for Core 1.17.26: the private mail relay setting (AD-30). DEV SERVER ONLY.
It did NOT run on the development PC (Django, Tactical and the database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/priority-mail-runtime-1.17.26.py

Run it after `manage.py migrate` has applied tec_tac 0029. Everything is written inside one transaction that is ROLLED BACK at the end.
The name lookup is replaced by a stub, so nothing touches the network and nothing is sent. Prints PASS or FAIL for each step.

Checks: migration 0029 added the column and the real row reads off; the reader answers False by default and True once the row is True;
a name that resolves to a private address is refused with the setting off and accepted with it on (this script's frame is Core's own,
so host_check is called with core_seams=True the way send_p1_email does); metadata, loopback and link-local stay refused with it on; the
same call with core_seams=False is refused; the setting reads off again once it is switched off.
"""
import sys

from django.db import connection, transaction
from tec_tac import priority_mail
from tec_tac.models import TecTacRuntimeConfig
from tec_tac.runtime_settings import get_priority_mail_private_relay

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


def check(cond, message=""):
    if not cond:
        raise AssertionError(message)


ANSWERS = {}
priority_mail.resolve_addresses = lambda name: list(ANSWERS[name])


def name(*addresses):
    ANSWERS["relay.probe"] = addresses
    return "relay.probe"


try:
    with transaction.atomic():
        def column_exists():
            with connection.cursor() as cursor:
                columns = [c.name for c in connection.introspection.get_table_description(cursor, TecTacRuntimeConfig._meta.db_table)]
            check("priority_mail_private_relay" in columns, columns)

        def default_reads_off():
            config = TecTacRuntimeConfig.current()
            check(config.priority_mail_private_relay is False, config.priority_mail_private_relay)
            check(get_priority_mail_private_relay() is False, "the reader reads off")
            check(priority_mail.host_check(name("10.0.0.5"), core_seams=True) == (priority_mail.REFUSED, False), "private refused when off")

        def on_accepts_private_only():
            config = TecTacRuntimeConfig.current()
            config.priority_mail_private_relay = True
            config.save(update_fields=["priority_mail_private_relay"])
            check(get_priority_mail_private_relay() is True, "the reader reads on")
            check(priority_mail.host_check(name("10.0.0.5"), core_seams=True) == (None, True), "10.x accepted")
            check(priority_mail.host_check(name("192.168.1.9", "100.64.0.9"), core_seams=True) == (None, True), "192.168.x and 100.64.x accepted")
            for refused in ("127.0.0.1", "::1", "169.254.169.254", "169.254.10.1", "0.0.0.0", "224.0.0.1"):
                check(priority_mail.host_check(name(refused), core_seams=True)[0] == priority_mail.REFUSED, refused)
            check(priority_mail.host_check(name("10.0.0.5", "127.0.0.1"), core_seams=True)[0] == priority_mail.REFUSED, "a mixed answer is refused")
            check(priority_mail.host_check(name("10.0.0.5"), core_seams=False) == (priority_mail.REFUSED, False), "not Core's own call: public only")

        def off_again_reads_off():
            config = TecTacRuntimeConfig.current()
            config.priority_mail_private_relay = False
            config.save(update_fields=["priority_mail_private_relay"])
            check(get_priority_mail_private_relay() is False, "off reads off")
            check(priority_mail.host_check(name("10.0.0.5"), core_seams=True)[0] == priority_mail.REFUSED, "private refused again")

        step("migration 0029 added the column", column_exists)
        step("the default reads off and refuses private names", default_reads_off)
        step("on accepts private ranges and nothing else", on_accepts_private_only)
        step("off again reads off", off_again_reads_off)
        raise Rollback()
except Rollback:
    pass

print("RESULT:", "PASS" if all(RESULTS) else "FAIL", f"({sum(RESULTS)}/{len(RESULTS)})")
sys.exit(0 if all(RESULTS) else 1)

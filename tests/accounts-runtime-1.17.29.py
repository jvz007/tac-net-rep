"""Runtime check for Core 1.17.29: core.accounts check_available on real tables. DEV SERVER ONLY. It did NOT run on the development PC
(Django, Tactical and the database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/accounts-runtime-1.17.29.py

Everything runs inside one transaction that is ROLLED BACK at the end, so no account or audit row is kept. Prints PASS, FAIL or SKIP for
each step.

Checks: core.accounts 1.1.0 is registered with check_available; a call from the shell (no module's code on the stack) is refused with
caller_not_allowed and runs no write; if the enabled userinvite extension is installed, a call made from a stand-in frame whose code file
lies in userinvite's own folder answers free for an unused pair, username_taken for an existing username in another case, email_taken for an
existing email in another case and username_taken with both flags for a pair that clashes twice, and writes no audit row and no user. The
rule-level behaviour is pinned by tests/accounts-check-available-1.17.29.py; this file checks the same rules on the real tables.
"""
import sys
import uuid

from accounts.models import User
from django.db import transaction
from logs.models import AuditLog
from tec_tac import registry
from tec_tac.accounts import AccountsError
from tec_tac.capabilities import get_capability, has_capability

RESULTS = []
ACCOUNTS_BEFORE = User.objects.count()
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]


class Rollback(Exception):
    pass


def step(name, fn):
    try:
        outcome = fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        if outcome == "SKIP":
            print(f"SKIP {name}")
            return
        RESULTS.append(True)
        print(f"PASS {name}")


def check(cond, message=""):
    if not cond:
        raise AssertionError(message)


def last_audit_id():
    row = AuditLog.objects.order_by("-pk").first()
    return row.pk if row else 0


def module_root(module_id):
    for plugin in registry.get_plugins():
        if plugin.plugin_id == module_id and plugin.plugin_type == "extension" and not plugin.legacy:
            return plugin.root
    return None


def stand_in_call(root, fn, *args, **kwargs):
    """Run fn from code whose file lies in the module's folder, so Core sees that module as the caller."""
    filename = str(root / "runtime_probe.py")
    ns: dict = {"__name__": "module_probe"}
    exec(compile("def call(fn, a, kw):\n    return fn(*a, **kw)\n", filename, "exec"), ns)  # noqa: S102 - runtime probe only
    return ns["call"](fn, args, kwargs)


try:
    with transaction.atomic():
        before = User.objects.count()
        accounts_cap = None

        def capability_registered():
            global accounts_cap
            check(has_capability("core.accounts", version="1.1.0", module_id="core"), "core.accounts 1.1.0 is registered")
            accounts_cap = get_capability("core.accounts")
            check(callable(accounts_cap.check_available), "check_available is on the provider")

        def shell_refused():
            try:
                accounts_cap.check_available("someone", "someone@probe.invalid")
            except AccountsError as exc:
                check(exc.code == "caller_not_allowed", exc.code)
                return
            raise AssertionError("a shell call was answered")

        step("core.accounts 1.1.0 is registered with check_available", capability_registered)
        step("check_available refuses a caller with no module's code on the stack", shell_refused)

        invite_root = module_root("userinvite")
        if invite_root is None:
            print("SKIP the userinvite stand-in checks: no enabled userinvite extension is installed on this server")
        else:
            existing = User.objects.order_by("pk").first()

            def availability():
                since = last_audit_id()
                free = stand_in_call(invite_root, accounts_cap.check_available, f"{MARK}-free", f"{MARK}@probe.invalid")
                check(free.status == "free" and not free.username_taken and not free.email_taken, free)
                if existing is not None and existing.username and existing.email:
                    name = stand_in_call(invite_root, accounts_cap.check_available, existing.username.swapcase(), f"{MARK}@probe.invalid")
                    check(name.status == "username_taken" and name.username_taken and not name.email_taken, name)
                    mail = stand_in_call(invite_root, accounts_cap.check_available, f"{MARK}-free", existing.email.upper())
                    check(mail.status == "email_taken" and mail.email_taken and not mail.username_taken, mail)
                    both = stand_in_call(invite_root, accounts_cap.check_available, existing.username, existing.email)
                    check(both.status == "username_taken" and both.username_taken and both.email_taken, both)
                check(AuditLog.objects.filter(pk__gt=since).count() == 0, "a read writes no audit row")
                check(User.objects.count() == before, "a read creates no user")

            step("check_available answers free, username_taken, email_taken and both, with no write", availability)

        raise Rollback()
except Rollback:
    pass

after_rollback = User.objects.count()
print("account count before the run:", ACCOUNTS_BEFORE, "after the rollback:", after_rollback)
check_result = after_rollback == ACCOUNTS_BEFORE
print("PASS the rollback left no account" if check_result else "FAIL the rollback left an account behind")
RESULTS.append(check_result)
print("RESULT:", "PASS" if all(RESULTS) else "FAIL", f"({sum(RESULTS)}/{len(RESULTS)})")
sys.exit(0 if all(RESULTS) else 1)

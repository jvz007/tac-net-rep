"""Runtime check for Core 1.17.27: core.accounts on real tables. DEV SERVER ONLY.
It did NOT run on the development PC (Django, Tactical and the database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/accounts-runtime-1.17.27.py

Everything runs inside one transaction that is ROLLED BACK at the end, so no account or audit row is kept. Prints PASS, FAIL or SKIP for
each step.

Checks: the capability is registered with its two operations; a call from the shell (no module's code on the stack) is refused with
caller_not_allowed and creates nothing; the same for list_grantable_roles. If the enabled userinvite extension is installed, a call made
from its folder (a stand-in frame whose code file lies in userinvite's own folder, so the stack check sees the module) creates a user with
a usable password, no TOTP key, the role, one Core audit row that names accept-invite and nothing secret, and refuses a duplicate and a
superuser role. The rule-level behaviour is pinned by tests/accounts-contract-1.17.27.py and the frame rule by
tests/caller-identity-core-provider-1.17.27.py; this file checks the same rules on the real tables.
"""
import sys
import uuid

from accounts.models import Role, User
from django.db import transaction
from logs.models import AuditLog
from tec_tac import registry
from tec_tac.accounts import AccountsError
from tec_tac.capabilities import get_capability, has_capability

RESULTS = []
ACCOUNTS_BEFORE = User.objects.count()
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
PASSWORD = "Harbour-Lantern-Vine-" + uuid.uuid4().hex[:6]


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


def expect_refusal(code, fn):
    try:
        fn()
    except AccountsError as exc:
        check(exc.code == code, f"expected {code}, got {exc.code}")
        check(PASSWORD not in exc.message, "no password in the refusal")
        return
    raise AssertionError(f"expected {code}, the call succeeded")


def user_count():
    return User.objects.count()


def last_audit_id():
    row = AuditLog.objects.order_by("-pk").first()
    return row.pk if row else 0


def userinvite_root():
    for plugin in registry.get_plugins():
        if plugin.plugin_id == "userinvite" and plugin.plugin_type == "extension" and not plugin.legacy:
            return plugin.root
    return None


def stand_in_userinvite_call(fn, **kwargs):
    """Run fn from code whose file lies in userinvite's folder, so Core sees the module as the caller (the stand-in for its own view)."""
    filename = str(userinvite_root() / "runtime_probe.py")
    ns: dict = {"__name__": "userinvite_probe"}
    exec(compile("def call(fn, kw):\n    return fn(**kw)\n", filename, "exec"), ns)  # noqa: S102 - runtime probe only
    return ns["call"](fn, kwargs)


try:
    with transaction.atomic():
        before = user_count()
        accounts_cap = None  # set by the first step, used by the rest

        def capability_registered():
            global accounts_cap
            check(has_capability("core.accounts", version="1.0.0", module_id="core"), "core.accounts 1.0.0 is registered")
            accounts_cap = get_capability("core.accounts")
            check(callable(accounts_cap.create_user) and callable(accounts_cap.list_grantable_roles), "both operations are on the provider")

        def shell_create_refused():
            expect_refusal("caller_not_allowed", lambda: accounts_cap.create_user(
                username=f"{MARK}-shell", email=f"{MARK}@probe.invalid", first_name="A", last_name="B",
                role_id=1, password=PASSWORD, invited_by_id=1))
            check(user_count() == before, "the refused call created no user")

        def shell_list_refused():
            expect_refusal("caller_not_allowed", lambda: accounts_cap.list_grantable_roles(None))

        step("core.accounts 1.0.0 is registered with both operations", capability_registered)
        step("a call with no module's code on the stack creates nothing (caller_not_allowed)", shell_create_refused)
        step("list_grantable_roles refuses a caller with no module's code on the stack", shell_list_refused)

        if userinvite_root() is None:
            print("SKIP the userinvite stand-in checks: no enabled userinvite extension is installed on this server")
        else:
            inviter = User.objects.filter(is_superuser=True, is_active=True).first()
            role = Role.objects.filter(is_superuser=False).order_by("name", "id").first()
            superuser_role = Role.objects.filter(is_superuser=True).first()

            def stand_in_create():
                since = last_audit_id()
                created = stand_in_userinvite_call(
                    accounts_cap.create_user, username=f"{MARK}-invitee", email=f"{MARK}@probe.invalid", first_name="Ada",
                    last_name="Probe", role_id=role.pk, password=PASSWORD, invited_by_id=inviter.pk)
                new = User.objects.get(pk=created.user_id)
                check(created.username == f"{MARK}-invitee" and created.role_id == role.pk, "returns the id, the name and the role")
                check(new.role_id == role.pk and new.first_name == "Ada", "the role and the name are set")
                check(new.check_password(PASSWORD) and new.password != PASSWORD, "a usable hashed password")
                check(not new.totp_key, "no TOTP key: the first sign-in set-up applies")
                rows = list(AuditLog.objects.filter(pk__gt=since).order_by("pk"))
                check(len(rows) == 1, f"one audit row, got {len(rows)}")
                blob = repr(rows[0].__dict__)
                check("accept-invite" in blob and "userinvite" in blob, "the row names the purpose and the caller")
                check(PASSWORD not in blob and new.password not in blob and f"{MARK}" not in blob, "the row holds no secret, hash, username or email")

            def stand_in_duplicate_and_superuser():
                expect_refusal("username_taken", lambda: stand_in_userinvite_call(
                    accounts_cap.create_user, username=f"{MARK}-INVITEE", email=f"{MARK}2@probe.invalid", first_name="A", last_name="B",
                    role_id=role.pk, password=PASSWORD, invited_by_id=inviter.pk))
                if superuser_role is not None:
                    expect_refusal("role_not_grantable", lambda: stand_in_userinvite_call(
                        accounts_cap.create_user, username=f"{MARK}-root", email=f"{MARK}3@probe.invalid", first_name="A", last_name="B",
                        role_id=superuser_role.pk, password=PASSWORD, invited_by_id=inviter.pk))

            def stand_in_roles():
                roles = stand_in_userinvite_call(accounts_cap.list_grantable_roles, inviter=inviter)
                check(all(set(row) == {"id", "name", "is_superuser"} for row in roles), "row keys are id, name and is_superuser")

            if inviter is None or role is None:
                print("SKIP the userinvite stand-in create: needs an active superuser and a non-superuser role on this server")
            else:
                step("a userinvite frame creates one user with a usable password, no TOTP key and one audit row", stand_in_create)
                step("a duplicate username and a superuser role are refused on the real tables", stand_in_duplicate_and_superuser)
                step("list_grantable_roles returns id, name and is_superuser from a userinvite frame", stand_in_roles)

        raise Rollback()
except Rollback:
    pass

after_rollback = user_count()
print("account count before the run:", ACCOUNTS_BEFORE, "after the rollback:", after_rollback)
check_result = after_rollback == ACCOUNTS_BEFORE
print("PASS the rollback left no account" if check_result else "FAIL the rollback left an account behind")
RESULTS.append(check_result)
print("RESULT:", "PASS" if all(RESULTS) else "FAIL", f"({sum(RESULTS)}/{len(RESULTS)})")
sys.exit(0 if all(RESULTS) else 1)

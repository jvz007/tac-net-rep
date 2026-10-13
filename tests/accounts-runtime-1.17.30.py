"""Runtime check for Core 1.17.30: core.accounts check_available (inviter re-check and Core limit) and the userinvite service context on real
tables. DEV SERVER ONLY. It did NOT run on the development PC (Django, Tactical and the database are not installed there).

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/accounts-runtime-1.17.30.py

Database writes run inside one transaction that is ROLLED BACK at the end, so no account or audit row is kept. The rate limit lives in Django's
cache, which a rollback does not undo, so the script clears the limit keys of the inviter it uses before and after. Prints PASS, FAIL or SKIP for
each step.

Checks: core.accounts 1.2.0 is registered with check_available; a call from the shell (no module's code on the stack) is refused with
caller_not_allowed; core.resources 1.9.0 is registered. If the enabled userinvite extension is installed, calls made from a stand-in frame whose
code file lies in userinvite's own folder: an inviter who holds can_manage_accounts (a real user, found through Core's own permission check) gets
free, username_taken, email_taken and both, with no audit row and no user; a missing inviter id, an inactive user, an installer user and a user
without can_manage_accounts get inviter_not_allowed; a bad invited_by_id gets invalid_input; the 31st call inside the window gets rate_limited
against the real cache, a second inviter is unaffected and the keys hold no username or email; and trusted_service_context(actor='userinvite',
global_access=False) from that stand-in frame returns a context that is_service, is not trusted_global and cannot list clients, while the same
call with the actor 'alerts', and the same call from the shell, is refused. The rule-level behaviour is pinned by
tests/accounts-check-available-1.17.30.py, tests/resource-service-context-1.17.30.py and tests/audit-server-module-deny-1.17.30.py.
"""
import sys
import uuid

from accounts.models import User
from django.core.cache import cache
from django.db import transaction
from logs.models import AuditLog
from tec_tac import accounts as core_accounts
from tec_tac import registry, resources
from tec_tac.accounts import AccountsError
from tec_tac.capabilities import get_capability, has_capability
from tec_tac.rbac import tactical_permission_flags

RESULTS = []
ACCOUNTS_BEFORE = User.objects.count()
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
KEY_BASE = core_accounts.CHECK_CACHE_PREFIX


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


def refused_with(code, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except AccountsError as exc:
        check(exc.code == code, f"expected {code}, got {exc.code}")
        return
    raise AssertionError(f"expected {code}, the call was answered")


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


def clear_limit(inviter_id):
    for suffix in ("window", "day"):
        cache.delete(f"{KEY_BASE}{inviter_id}:{suffix}")


def can_manage(user):
    return bool(tactical_permission_flags(user, (core_accounts.MANAGE_FLAG,))[core_accounts.MANAGE_FLAG])


cleanup_ids = []
try:
    with transaction.atomic():
        before = User.objects.count()
        accounts_cap = None

        def capability_registered():
            global accounts_cap
            check(has_capability("core.accounts", version="1.2.0", module_id="core"), "core.accounts 1.2.0 is registered")
            check(has_capability("core.resources", version="1.9.0", module_id="core"), "core.resources 1.9.0 is registered")
            accounts_cap = get_capability("core.accounts")
            check(callable(accounts_cap.check_available), "check_available is on the provider")

        def shell_refused():
            refused_with("caller_not_allowed", accounts_cap.check_available, "someone", "someone@probe.invalid", 1)

        step("core.accounts 1.2.0 and core.resources 1.9.0 are registered", capability_registered)
        step("check_available refuses a caller with no module's code on the stack", shell_refused)

        def shell_service_context_refused():
            try:
                resources.trusted_service_context(actor="userinvite", purpose="probe", global_access=False)
            except resources.ResourcePermissionDenied:
                return
            raise AssertionError("a shell call got a service context")

        step("trusted_service_context(global_access=False) refuses a shell caller", shell_service_context_refused)

        invite_root = module_root("userinvite")
        if invite_root is None:
            print("SKIP the userinvite stand-in checks: no enabled userinvite extension is installed on this server")
        else:
            users = list(User.objects.order_by("pk"))
            managers = [u for u in users if u.is_active and not u.is_installer_user and can_manage(u)]
            others = [u for u in users if u.is_active and not u.is_installer_user and not can_manage(u)]
            inactive = [u for u in users if not u.is_active]
            installers = [u for u in users if u.is_installer_user]
            existing = users[0] if users else None
            inviter = managers[0] if managers else None
            if inviter is None:
                print("SKIP the inviter and limit checks: no active user holds can_manage_accounts on this server")
            else:
                clear_limit(inviter.pk)
                cleanup_ids.append(inviter.pk)

                def availability():
                    since = last_audit_id()
                    call = accounts_cap.check_available
                    free = stand_in_call(invite_root, call, f"{MARK}-free", f"{MARK}@probe.invalid", inviter.pk)
                    check(free.status == "free" and not free.username_taken and not free.email_taken, free)
                    if existing is not None and existing.username and existing.email:
                        name = stand_in_call(invite_root, call, existing.username.swapcase(), f"{MARK}@probe.invalid", inviter.pk)
                        check(name.status == "username_taken" and name.username_taken and not name.email_taken, name)
                        mail = stand_in_call(invite_root, call, f"{MARK}-free", existing.email.upper(), inviter.pk)
                        check(mail.status == "email_taken" and mail.email_taken and not mail.username_taken, mail)
                        both = stand_in_call(invite_root, call, existing.username, existing.email, inviter.pk)
                        check(both.status == "username_taken" and both.username_taken and both.email_taken, both)
                    check(AuditLog.objects.filter(pk__gt=since).count() == 0, "a read writes no audit row")
                    check(User.objects.count() == before, "a read creates no user")

                step("check_available answers free, username_taken, email_taken and both for an allowed inviter, with no write", availability)

                def inviter_refusals():
                    call = accounts_cap.check_available
                    clear_limit(inviter.pk)
                    refused_with("inviter_not_allowed", stand_in_call, invite_root, call, f"{MARK}-x", f"{MARK}@probe.invalid", 2**31 - 1)
                    for group in (others[:1], inactive[:1], installers[:1]):
                        for user in group:
                            clear_limit(user.pk)
                            refused_with("inviter_not_allowed", stand_in_call, invite_root, call, f"{MARK}-x", f"{MARK}@probe.invalid", user.pk)
                            check(cache.get(f"{KEY_BASE}{user.pk}:window") is None, "a refused inviter is not counted")
                    for bad in (True, 0, -1, "3", None, 1.5):
                        refused_with("invalid_input", stand_in_call, invite_root, call, f"{MARK}-x", f"{MARK}@probe.invalid", bad)

                step("check_available refuses a missing, inactive, installer or unprivileged inviter and a bad id, without counting them", inviter_refusals)

                def limit_steps():
                    call = accounts_cap.check_available
                    clear_limit(inviter.pk)
                    for index in range(core_accounts.CHECK_WINDOW_LIMIT):
                        stand_in_call(invite_root, call, f"{MARK}-{index}", f"{MARK}-{index}@probe.invalid", inviter.pk)
                    refused_with("rate_limited", stand_in_call, invite_root, call, f"{MARK}-over", f"{MARK}-over@probe.invalid", inviter.pk)
                    if len(managers) > 1:
                        clear_limit(managers[1].pk)
                        cleanup_ids.append(managers[1].pk)
                        stand_in_call(invite_root, call, f"{MARK}-b", f"{MARK}-b@probe.invalid", managers[1].pk)  # another inviter is unaffected
                    keys = [k for k in (f"{KEY_BASE}{inviter.pk}:window", f"{KEY_BASE}{inviter.pk}:day") if cache.get(k) is not None]
                    check(len(keys) == 2 and all(MARK not in k and "@" not in k for k in keys), keys)

                step("check_available stops the 31st call in the window with rate_limited, per inviter, with no name in the key", limit_steps)
                clear_limit(inviter.pk)

            def service_context():
                ctx = stand_in_call(invite_root, resources.trusted_service_context, actor="userinvite", purpose="runtime probe", global_access=False)
                check(ctx.is_service and ctx.trusted_global is False and ctx.service_actor == "userinvite", ctx)
                try:
                    resources.list_clients(context=ctx)
                except resources.ResourcePermissionDenied:
                    pass
                else:
                    raise AssertionError("a non-global service context listed clients")
                try:
                    stand_in_call(invite_root, resources.trusted_service_context, actor="alerts", purpose="runtime probe", global_access=False)
                except resources.ResourcePermissionDenied:
                    pass
                else:
                    raise AssertionError("the actor alerts was accepted from userinvite")

            since_service = last_audit_id()
            step("trusted_service_context(global_access=False) from userinvite gives a context that sees nothing and writes no row", service_context)
            step("that call wrote no audit row", lambda: check(AuditLog.objects.filter(pk__gt=since_service).count() == 0, "no audit row"))

        raise Rollback()
except Rollback:
    pass
finally:
    for pk in cleanup_ids:
        clear_limit(pk)

after_rollback = User.objects.count()
print("account count before the run:", ACCOUNTS_BEFORE, "after the rollback:", after_rollback)
check_result = after_rollback == ACCOUNTS_BEFORE
print("PASS the rollback left no account" if check_result else "FAIL the rollback left an account behind")
RESULTS.append(check_result)
print("RESULT:", "PASS" if all(RESULTS) else "FAIL", f"({sum(RESULTS)}/{len(RESULTS)})")
sys.exit(0 if all(RESULTS) else 1)

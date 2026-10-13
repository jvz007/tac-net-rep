"""Runtime check for Core 1.17.23: a role create is matched to its new role by the id set, and never skipped silently. DEV SERVER ONLY.
It did NOT run on the development PC (Django, Tactical and its database are not installed there).

Run it on the dev server through Tactical's manage.py shell:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/role-create-runtime-1.17.23.py

It POSTs a role through Tactical's own GetAddRoles view (wrapped by Core's account guard) and proves that one strict role_scope row
names the new role's id, that a role created with a blank name is found by the id set, and that a failing audit write rolls the
create back inside the real transaction. Everything runs inside one transaction that is rolled back at the end. Prints PASS or FAIL.
"""
import sys
import uuid

from accounts.models import Role, User
from accounts.views import GetAddRoles
from clients.models import Client
from django.db import transaction
from logs.models import AuditLog
from rest_framework.test import APIRequestFactory, force_authenticate
from tec_tac import audit

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


def check(cond, message=""):
    if not cond:
        raise AssertionError(message)


def scope_rows(role_id):
    return AuditLog.objects.filter(object_type="role_scope", debug_info__object_id=str(role_id))


try:
    with transaction.atomic():
        admin = User(username=f"{MARK}-admin", is_superuser=True)
        admin.set_password(uuid.uuid4().hex)
        admin.save()
        client = Client.objects.create(name=f"{MARK}-c1")
        factory = APIRequestFactory()

        def post(data):
            request = factory.post("/accounts/roles/", data, format="json")
            force_authenticate(request, user=admin)
            return GetAddRoles.as_view()(request)

        def create_names_the_new_id():
            response = post({"name": f"{MARK}-new", "can_list_clients": True, "can_view_clients": [client.pk]})
            check(response.status_code == 200, response.data)
            created = Role.objects.get(name=f"{MARK}-new")
            check(scope_rows(created.pk).count() == 1, "one add row naming the new role id")

        def failing_audit_rolls_the_create_back():
            real = audit.record
            audit.record = lambda **kw: (_ for _ in ()).throw(RuntimeError("audit store down"))
            try:
                try:
                    with transaction.atomic():
                        post({"name": f"{MARK}-doomed", "can_list_clients": True, "can_view_clients": [client.pk]})
                    raise AssertionError("the create was accepted without an audit row")
                except RuntimeError:
                    pass
            finally:
                audit.record = real
            check(not Role.objects.filter(name=f"{MARK}-doomed").exists(), "the create was rolled back")

        for name, fn in (
            ("role create writes one role_scope row naming the new id", create_names_the_new_id),
            ("a failing audit write rolls the create back", failing_audit_rolls_the_create_back),
        ):
            step(name, fn)
        raise Rollback()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
print("PASS" if all(RESULTS) else "FAIL")
if not all(RESULTS):
    sys.exit(1)

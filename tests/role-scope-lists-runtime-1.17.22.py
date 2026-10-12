"""Runtime check for Core 1.17.22: a role's client and site lists are saved by Tactical's real view and audited by Core. DEV SERVER ONLY.
It did NOT run on the development PC (Django, Tactical and its database are not installed there).

Run it on the dev server through Tactical's manage.py shell:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/role-scope-lists-runtime-1.17.22.py

It PUTs a role through Tactical's own GetUpdateDeleteRole view (wrapped by Core's account guard) and proves that both lists are saved, that
one strict Core audit row (object_type role_scope) is written with the sorted id lists, that a PUT that changes nothing writes no row, and
that a failing audit write rolls the save back. Everything runs inside one transaction that is rolled back at the end. Prints PASS or FAIL.
"""
import sys
import uuid

from accounts.models import Role, User
from accounts.views import GetAddRoles, GetUpdateDeleteRole
from clients.models import Client, Site
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
        c1 = Client.objects.create(name=f"{MARK}-c1")
        c2 = Client.objects.create(name=f"{MARK}-c2")
        s1 = Site.objects.create(client=c1, name=f"{MARK}-s1")
        s2 = Site.objects.create(client=c2, name=f"{MARK}-s2")
        role = Role.objects.create(name=f"{MARK}-role", can_list_clients=True, can_list_sites=True)
        role.can_view_clients.set([c1])
        factory = APIRequestFactory()

        def put(data):
            request = factory.put(f"/accounts/roles/{role.pk}/", data, format="json")
            force_authenticate(request, user=admin)
            return GetUpdateDeleteRole.as_view()(request, pk=role.pk)

        def full_payload(**lists):
            return {"name": role.name, "can_list_clients": True, "can_list_sites": True, **lists}

        def a_change_is_saved_and_audited():
            response = put(full_payload(can_view_clients=[c1.pk, c2.pk], can_view_sites=[s1.pk]))
            check(response.status_code == 200, response.data)
            check(sorted(role.can_view_clients.values_list("pk", flat=True)) == sorted([c1.pk, c2.pk]), "clients saved")
            check(list(role.can_view_sites.values_list("pk", flat=True)) == [s1.pk], "sites saved")
            rows = scope_rows(role.pk)
            check(rows.count() == 1, f"one audit row: {rows.count()}")
            text = repr(rows.first().debug_info)
            check(str(c2.pk) in text and f"{MARK}-c2" not in text, "ids only, never names")

        def no_change_no_row():
            before = scope_rows(role.pk).count()
            response = put(full_payload(can_view_clients=[c2.pk, c1.pk], can_view_sites=[s1.pk]))
            check(response.status_code == 200 and scope_rows(role.pk).count() == before, "no new row for an unchanged pair")

        def clearing_is_audited():
            before = scope_rows(role.pk).count()
            response = put(full_payload(can_view_clients=[], can_view_sites=[]))
            check(response.status_code == 200 and scope_rows(role.pk).count() == before + 1, "clearing both lists writes a row")
            check(not role.can_view_clients.exists() and not role.can_view_sites.exists(), "unrestricted again")

        def failing_audit_rolls_back():
            real = audit.record
            audit.record = lambda **kw: (_ for _ in ()).throw(RuntimeError("audit store down"))
            try:
                try:
                    with transaction.atomic():
                        put(full_payload(can_view_clients=[c1.pk], can_view_sites=[s2.pk]))
                    raise AssertionError("the save was accepted without an audit row")
                except RuntimeError:
                    pass
            finally:
                audit.record = real
            check(not role.can_view_clients.exists() and not role.can_view_sites.exists(), "the role save was rolled back")

        def create_is_audited():
            request = factory.post("/accounts/roles/", {"name": f"{MARK}-new", "can_list_clients": True, "can_view_clients": [c2.pk]}, format="json")
            force_authenticate(request, user=admin)
            response = GetAddRoles.as_view()(request)
            check(response.status_code == 200, response.data)
            created = Role.objects.get(name=f"{MARK}-new")
            check(scope_rows(created.pk).count() == 1, "an add row for the new role's lists")

        for name, fn in (
            ("a PUT saves both lists and writes one role_scope audit row with ids only", a_change_is_saved_and_audited),
            ("a PUT that changes nothing writes no row", no_change_no_row),
            ("clearing both lists is audited", clearing_is_audited),
            ("a failing audit write rolls the role save back", failing_audit_rolls_back),
            ("role create audits the new role's lists", create_is_audited),
        ):
            step(name, fn)
        raise Rollback()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
print("PASS" if all(RESULTS) else "FAIL")
if not all(RESULTS):
    sys.exit(1)

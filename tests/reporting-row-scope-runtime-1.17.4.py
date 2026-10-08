"""1.17.4 runtime regression for the reporting row-scope hook.

Run on the dev server through Tactical's manage.py shell, so Django, Tactical's models and EE Report Manager are loaded:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < tests/reporting-row-scope-runtime-1.17.4.py

It could NOT be run on the development PC (Django is not installed there). It builds a real scoped model over
Tactical's own ``clients_site`` table, so no migration is needed, and checks three things for a client-restricted user, a
site-restricted user, an unrestricted user and a user with no role:

1. ``filter_by_role`` returns exactly the rows Tactical's own Site manager returns (parity with Tactical's rule).
2. Tactical's real ``build_queryset`` uses it, including before an ``aggregate``-style operation (the count is scoped).
3. ``model_row_scope`` reports the model as enforced, and a plain model as not.

All rows are created inside a transaction that is rolled back.
"""
from django.db import models, transaction

from accounts.models import Role, User
from clients.models import Client, Site
from ee.reporting.utils import build_queryset
from tec_tac.reporting import model_row_scope, reporting_bridge_status, scoped_report_manager


class RollbackProbe(Exception):
    pass


class ScopeProbeSite(models.Model):
    """An unmanaged view of Tactical's clients_site table. The site path is the row's own id."""

    client = models.ForeignKey("clients.Client", db_column="client_id", on_delete=models.DO_NOTHING, related_name="+")
    name = models.CharField(max_length=255)
    objects = scoped_report_manager(client="client_id", site="id")

    class Meta:
        app_label = "tec_tac"
        managed = False
        db_table = Site._meta.db_table


def ids(queryset):
    return set(queryset.values_list("pk", flat=True))


def make_user(name, role):
    user = User(username=name, email=f"{name}@example.invalid", role=role)
    user.set_unusable_password()
    user.save()
    return User.objects.get(pk=user.pk)


try:
    with transaction.atomic():
        client_a = Client.objects.create(name="scope-probe-a")
        client_b = Client.objects.create(name="scope-probe-b")
        site_a1 = Site.objects.create(client=client_a, name="a1")
        site_a2 = Site.objects.create(client=client_a, name="a2")
        site_b1 = Site.objects.create(client=client_b, name="b1")
        site_b2 = Site.objects.create(client=client_b, name="b2")

        client_role = Role.objects.create(name="scope-probe-client")
        client_role.can_view_clients.add(client_a)
        site_role = Role.objects.create(name="scope-probe-site")
        site_role.can_view_sites.add(site_b1)
        open_role = Role.objects.create(name="scope-probe-open")  # neither relation: full scope
        super_role = Role.objects.create(name="scope-probe-super", is_superuser=True)

        users = {
            "client-restricted": make_user("scope-probe-client", client_role),
            "site-restricted": make_user("scope-probe-site", site_role),
            "unrestricted": make_user("scope-probe-open", open_role),
            "role-superuser": make_user("scope-probe-super", super_role),
            "no-role": make_user("scope-probe-none", None),
        }
        probe_ids = {site_a1.pk, site_a2.pk, site_b1.pk, site_b2.pk}

        # 1. parity with Tactical's own rule for the Site model
        for label, user in users.items():
            ours = ids(ScopeProbeSite.objects.filter_by_role(user))
            native = ids(Site.objects.filter_by_role(user))
            assert ours == native, f"{label}: scoped model {sorted(ours)} != Tactical's Site rule {sorted(native)}"

        # the restricted users really are restricted
        assert ids(ScopeProbeSite.objects.filter_by_role(users["client-restricted"])) & probe_ids == {site_a1.pk, site_a2.pk}
        assert ids(ScopeProbeSite.objects.filter_by_role(users["site-restricted"])) & probe_ids == {site_b1.pk}
        assert probe_ids <= ids(ScopeProbeSite.objects.filter_by_role(users["unrestricted"]))
        assert probe_ids <= ids(ScopeProbeSite.objects.filter_by_role(users["role-superuser"]))
        assert ids(ScopeProbeSite.objects.filter_by_role(users["no-role"])) == set()

        # 2. Tactical's real report engine uses the hook before any other operation
        for label, user in users.items():
            expected = len(ids(Site.objects.filter_by_role(user)))
            counted = build_queryset(data_source={"model": ScopeProbeSite, "count": True}, user=user)
            assert counted == expected, f"{label}: build_queryset counted {counted}, expected {expected}"
            filtered = build_queryset(
                data_source={"model": ScopeProbeSite, "filter": {"name__in": ["a1", "a2", "b1", "b2"]}, "count": True}, user=user
            )
            assert filtered == len(ids(Site.objects.filter_by_role(user)) & probe_ids), f"{label}: a filter must not widen the scope"

        # 3. what Core reports
        scope = model_row_scope("tec_tac", "ScopeProbeSite")
        assert scope["enforced"] is True and scope["source"] == "core", scope
        assert scope["client_field"] == "client_id" and scope["site_field"] == "id", scope
        assert model_row_scope("clients", "Site")["enforced"] is False, "Tactical's own Site manager is not Core's"
        assert reporting_bridge_status()["row_scope_enforced"] is True

        raise RollbackProbe()
except RollbackProbe:
    pass

assert not Client.objects.filter(name__startswith="scope-probe-").exists(), "the probe rows must be rolled back"
print("reporting row scope runtime 1.17.4: ok")

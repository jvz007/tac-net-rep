"""Runtime check for Core 1.17.40: failing_checks, agent_count and maintenance_mode on client and site records (core.resources 1.10.0).
DEV SERVER ONLY. It did NOT run on the development PC (Django, Tactical and its database are not installed there).

Run it on the dev server through Tactical's manage.py shell:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/resource-live-state-runtime-1.17.40.py

It proves what the stub test (tests/resource-live-state-1.17.40.py) cannot: that the three values equal Tactical's own ClientSerializer and
SiteSerializer output, built the way Tactical's GET /clients/ builds it (the same annotations), for one real client and one real site, for an
unrestricted caller; that a role limited to one site gets a client record counted from that site only; and that the grouped agent query
stays at one query per page. A real client and site that already hold agents are used when there are any, otherwise a client and a site are
created. Everything runs inside one database transaction that is rolled back at the end. It prints PASS or FAIL for each step and exits with
status 1 when any step fails.
"""
import sys
import uuid

from accounts.models import Role, User
from agents.models import Agent
from clients.models import Client, Site
from clients.serializers import ClientSerializer, SiteSerializer
from django.db import connection, transaction
from django.db.models import Count, Exists, OuterRef, Prefetch
from django.test.utils import CaptureQueriesContext
from tec_tac import rbac, resources

RESULTS = []
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
KEYS = ("failing_checks", "agent_count", "maintenance_mode")


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


def make_role(suffix, *, clients=(), sites=()):
    role = Role.objects.create(
        name=f"{MARK}-{suffix}", can_list_clients=True, can_list_sites=True, can_list_agents=False,
        can_manage_clients=True, can_manage_sites=True,
    )
    role.can_view_clients.set(clients)
    role.can_view_sites.set(sites)
    for code in ("core.resources.clients.manage", "core.resources.sites.manage"):
        rbac.grant_extension_permission(role, code)
    return role


def make_user(suffix, role):
    user = User(username=f"{MARK}-{suffix}", role=role)
    user.set_password(uuid.uuid4().hex)
    user.save()
    return user


def tactical_client(pk):
    """The client as Tactical's own GET /clients/ serializes it (same annotations)."""
    return ClientSerializer(
        Client.objects.filter(pk=pk)
        .prefetch_related(Prefetch("sites", queryset=Site.objects.order_by("name").select_related("client")
                                   .annotate(maintenance_mode=Exists(Agent.objects.filter(site=OuterRef("pk"), maintenance_mode=True)))
                                   .annotate(agent_count=Count("agents")), to_attr="filtered_sites"))
        .annotate(maintenance_mode=Exists(Agent.objects.filter(site__client=OuterRef("pk"), maintenance_mode=True)))
        .annotate(agent_count=Count("sites__agents")).get()
    ).data


def tactical_site(pk):
    return SiteSerializer(
        Site.objects.filter(pk=pk).select_related("client")
        .annotate(maintenance_mode=Exists(Agent.objects.filter(site=OuterRef("pk"), maintenance_mode=True)))
        .annotate(agent_count=Count("agents")).get()
    ).data


try:
    with transaction.atomic():
        site = Site.objects.filter(agents__isnull=False).distinct().first()
        if site is None:
            client = Client.objects.create(name=f"{MARK}-A")
            site = Site.objects.create(client=client, name=f"{MARK}-A1")
        client = site.client
        other = Site.objects.create(client=client, name=f"{MARK}-extra")
        admin = make_user("admin", make_role("admin"))
        ctx = resources.user_context(admin)

        def same_as_tactical_client():
            theirs = tactical_client(client.pk)
            ours = resources.get_client(client.pk, context=ctx)
            check(tuple(ours)[-3:] == KEYS, tuple(ours))
            check(ours["agent_count"] == theirs["agent_count"], (ours["agent_count"], theirs["agent_count"]))
            check(ours["maintenance_mode"] == theirs["maintenance_mode"], (ours["maintenance_mode"], theirs["maintenance_mode"]))
            stored = theirs["failing_checks"]
            check(ours["failing_checks"] == {"error": stored.get("error") is True, "warning": stored.get("warning") is True}, (ours["failing_checks"], stored))
            listed = next(r for r in resources.list_clients(context=ctx, search=client.name, page_size=500)["items"] if r["id"] == client.pk)
            check({k: listed[k] for k in KEYS} == {k: ours[k] for k in KEYS}, "list equals get")

        def same_as_tactical_site():
            theirs = tactical_site(site.pk)
            ours = resources.get_site(site.pk, context=ctx)
            check(tuple(ours)[-3:] == KEYS, tuple(ours))
            check(ours["agent_count"] == theirs["agent_count"], (ours["agent_count"], theirs["agent_count"]))
            check(ours["maintenance_mode"] == theirs["maintenance_mode"], (ours["maintenance_mode"], theirs["maintenance_mode"]))
            stored = theirs["failing_checks"]
            check(ours["failing_checks"] == {"error": stored.get("error") is True, "warning": stored.get("warning") is True}, (ours["failing_checks"], stored))
            nested = next(s for s in resources.get_client(client.pk, context=ctx)["sites"] if s["id"] == site.pk)
            check({k: nested[k] for k in KEYS} == {k: ours[k] for k in KEYS}, "nested equals read")

        def limited_role_counts_only_its_site():
            Client.objects.filter(pk=client.pk).update(failing_checks={"error": True, "warning": True})
            Site.objects.filter(pk=other.pk).update(failing_checks={"error": True, "warning": True})
            Site.objects.filter(pk=site.pk).update(failing_checks={"error": False, "warning": False})
            limited = make_user("limited", make_role("limited", sites=[site.pk]))
            got = resources.get_client(client.pk, context=resources.user_context(limited))
            check([s["id"] for s in got["sites"]] == [site.pk], got["sites"])
            check(got["agent_count"] == tactical_site(site.pk)["agent_count"], got["agent_count"])
            check(got["failing_checks"] == {"error": False, "warning": False}, got["failing_checks"])  # the hidden failing site does not show
            full = resources.get_client(client.pk, context=ctx)
            check(full["failing_checks"] == {"error": True, "warning": True}, full["failing_checks"])   # an unrestricted caller sees Tactical's stored value

        def one_agent_query_per_page():
            with CaptureQueriesContext(connection) as page:
                resources.list_sites(context=ctx, page_size=500)
            agent_sql = [q["sql"] for q in page.captured_queries if 'FROM "agents_agent"' in q["sql"] and "COUNT(" in q["sql"]]
            check(len(agent_sql) == 1, agent_sql)
            with CaptureQueriesContext(connection) as clients_page:
                resources.list_clients(context=ctx, page_size=500)
            agent_sql = [q["sql"] for q in clients_page.captured_queries if 'FROM "agents_agent"' in q["sql"] and "COUNT(" in q["sql"]]
            check(len(agent_sql) == 1, agent_sql)

        for name, fn in (
            ("a client record carries Tactical's own agent_count, maintenance_mode and failing_checks for an unrestricted caller", same_as_tactical_client),
            ("a site record carries Tactical's own three values; the nested site equals the site read", same_as_tactical_site),
            ("a site-only role gets a client counted from its own site; a hidden failing site does not show", limited_role_counts_only_its_site),
            ("a page of clients and a page of sites each run one grouped agent query", one_agent_query_per_page),
        ):
            step(name, fn)
        raise Rollback()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
print("PASS" if all(RESULTS) else "FAIL")
if not all(RESULTS):
    sys.exit(1)

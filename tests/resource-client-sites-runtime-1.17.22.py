"""Runtime check for Core 1.17.22: nested client sites, client_name on sites, and Add client / Add site as Tactical does. DEV SERVER ONLY.
It did NOT run on the development PC (Django, Tactical and its database are not installed there).

Run it on the dev server through Tactical's manage.py shell:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/resource-client-sites-runtime-1.17.22.py

It proves what the stub tests (tests/resource-client-sites-1.17.22.py, tests/resource-create-client-site-1.17.22.py) cannot: real Role,
Client and Site rows. The sites nested in a client record equal Tactical's own ``Site.objects.filter_by_role(user)`` for every kind of
role, the sites read carries ``client_name`` from the join, a role limited to one client with List clients and no List sites gets that
client and its sites from the client read (and a refusal from the sites read), and a created client or site joins the creator's lists
only when those lists are not empty. Everything runs inside one database transaction that is rolled back at the end. It prints PASS or
FAIL for each step and exits with status 1 when any step fails.
"""
import sys
import uuid

from accounts.models import Role, User
from clients.models import Client, Site
from django.db import transaction
from tec_tac import rbac, resources

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


def make_role(suffix, *, clients=(), sites=(), list_clients=True, list_sites=True):
    role = Role.objects.create(
        name=f"{MARK}-{suffix}", can_list_clients=list_clients, can_list_sites=list_sites, can_list_agents=True,
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


try:
    with transaction.atomic():
        client_a = Client.objects.create(name=f"{MARK}-A")
        client_b = Client.objects.create(name=f"{MARK}-B")
        a1 = Site.objects.create(client=client_a, name=f"{MARK}-A1")
        a2 = Site.objects.create(client=client_a, name=f"{MARK}-A2")
        b1 = Site.objects.create(client=client_b, name=f"{MARK}-B1")
        roles = {
            "client-only": make_role("client-only", clients=[client_a], list_sites=False),
            "site-only": make_role("site-only", sites=[a1], list_clients=False),
            "mixed": make_role("mixed", clients=[client_b], sites=[a1]),
            "unrestricted": make_role("unrestricted"),
        }
        users = {key: make_user(key, role) for key, role in roles.items()}

        def nested_equals_filter_by_role():
            for key in ("client-only", "mixed", "unrestricted"):
                user = users[key]
                ctx = resources.user_context(user)
                visible = {pk: set() for pk in Client.objects.filter_by_role(user).values_list("pk", flat=True)}
                for pk, client_id in Site.objects.filter_by_role(user).values_list("pk", "client_id"):
                    visible.setdefault(client_id, set()).add(pk)
                page = resources.list_clients(context=ctx, search=MARK)
                for row in page["items"]:
                    nested = {s["id"] for s in row["sites"]}
                    check(nested == visible.get(row["id"], set()), (key, row["id"], nested, visible.get(row["id"])))
                    check(all(s["client_id"] == row["id"] and s["client_name"] == row["name"] for s in row["sites"]), (key, row))
                    check([s["name"] for s in row["sites"]] == sorted(s["name"] for s in row["sites"]), "ordered by name")

        def client_limited_role_without_list_sites():
            ctx = resources.user_context(users["client-only"])
            page = resources.list_clients(context=ctx, search=MARK)
            check([r["name"] for r in page["items"]] == [client_a.name], page)
            check({s["id"] for s in page["items"][0]["sites"]} == {a1.pk, a2.pk}, page["items"][0]["sites"])
            try:
                resources.list_sites(context=ctx)
                raise AssertionError("the sites read was accepted without List sites")
            except resources.ResourcePermissionDenied:
                pass

        def site_only_role():
            ctx = resources.user_context(users["site-only"])
            listed = resources.list_sites(context=ctx, search=MARK)
            check([s["id"] for s in listed["items"]] == [a1.pk] and listed["items"][0]["client_name"] == client_a.name, listed)
            try:
                resources.list_clients(context=ctx)
                raise AssertionError("the clients read was accepted without List clients")
            except resources.ResourcePermissionDenied:
                pass
            got = resources.get_client(client_a.pk, context=resources.user_context(make_user("site-reader", make_role("site-reader", sites=[a1]))))
            check([s["id"] for s in got["sites"]] == [a1.pk], got)

        def create_extends_only_non_empty_lists():
            limited = make_user("creator", make_role("creator", clients=[client_a]))
            made = resources.create_client(name=f"{MARK}-new", site_name=f"{MARK}-new-hq", context=resources.user_context(limited))
            check([s["name"] for s in made["sites"]] == [f"{MARK}-new-hq"], made)
            check(limited.role.can_view_clients.filter(pk=made["id"]).exists(), "a role listing clients gets the new client")
            site_only_user = make_user("site-creator", make_role("site-creator", sites=[a1]))
            made2 = resources.create_client(name=f"{MARK}-new2", site_name=f"{MARK}-new2-hq", context=resources.user_context(site_only_user))
            check(not site_only_user.role.can_view_clients.exists(), "a site-only role is not widened")
            check(made2["sites"][0]["name"] == f"{MARK}-new2-hq", made2)
            site = resources.create_site(client_id=client_a.pk, name=f"{MARK}-A3", context=resources.user_context(make_user("mixed-writer", make_role("mixed-writer", clients=[client_a], sites=[a1]))))
            check(site["client_name"] == client_a.name, site)

        for name, fn in (
            ("nested sites equal Tactical's filter_by_role for client-only, mixed and unrestricted roles", nested_equals_filter_by_role),
            ("a role with List clients and no List sites gets its client and sites; the sites read is refused", client_limited_role_without_list_sites),
            ("a site-only role gets site records with client_name; the clients read is refused", site_only_role),
            ("a created client or site joins a creator's lists only when those lists are not empty", create_extends_only_non_empty_lists),
        ):
            step(name, fn)
        raise Rollback()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
print("PASS" if all(RESULTS) else "FAIL")
if not all(RESULTS):
    sys.exit(1)

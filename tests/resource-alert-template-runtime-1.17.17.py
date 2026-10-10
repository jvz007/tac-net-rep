"""Runtime check for Core 1.17.17 alert_template_id on clients and sites, and the role scope descriptor (core.resources 1.4.0).
It did NOT run on the development PC (Django, Tactical and its database are not installed there). DEV SERVER ONLY.

Run it on the dev server through Tactical's manage.py shell:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/resource-alert-template-runtime-1.17.17.py

It proves what the stub tests (tests/resource-alert-template-1.17.17.py, tests/resource-scope-descriptor-1.17.17.py) cannot: Tactical's real
Client, Site, Role and AlertTemplate models. The foreign key of ``alert_template`` refuses an id that names no template, ``obj.save`` runs
Tactical's own hook (``cache_agents_alert_template``), the scope descriptor follows the real ``can_view_clients`` and ``can_view_sites``
relations and agrees with ``filter_by_role``, and a role limited to one site cannot change its client's template.

Everything runs inside one database transaction that is rolled back at the end. ``cache_agents_alert_template.delay`` is replaced in this
shell by a recorder, so no Celery broker is needed. It prints PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import sys
import uuid

from accounts.models import Role, User
from alerts.models import AlertTemplate
from alerts import tasks as alert_tasks
from clients.models import Client, Site
from django.db import transaction
from tec_tac import rbac, resources
from tec_tac import resources_adapter as adapter

RESULTS = []
MARK = "tectac-probe-" + uuid.uuid4().hex[:8]
HOOKS = []


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


def make_role(suffix, *, clients=(), sites=(), manage=True):
    role = Role.objects.create(
        name=f"{MARK}-{suffix}", can_list_clients=True, can_list_sites=True, can_list_agents=True,
        can_manage_clients=manage, can_manage_sites=manage,
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
        original_delay = alert_tasks.cache_agents_alert_template.delay
        alert_tasks.cache_agents_alert_template.delay = lambda *a, **k: HOOKS.append((a, k))

        admin = User(username=f"{MARK}-admin", is_superuser=True)
        admin.set_password(uuid.uuid4().hex)
        admin.save()
        ctx = resources.user_context(admin)
        template = AlertTemplate.objects.create(name=f"{MARK}-template")
        other_template = AlertTemplate.objects.create(name=f"{MARK}-template-2")
        client = Client.objects.create(name=f"{MARK}-client")
        site = Site.objects.create(client=client, name=f"{MARK}-site")
        second_site = Site.objects.create(client=client, name=f"{MARK}-site-2")

        def rows_carry_the_field():
            row = resources.get_client(client.pk, context=ctx)
            check(tuple(row) == resources.CLIENT_FIELDS and row["alert_template_id"] is None, row)
            check(tuple(resources.get_site(site.pk, context=ctx)) == resources.SITE_FIELDS, "site row")
            listed = [r for r in resources.list_clients(context=ctx, search=MARK)["items"] if r["id"] == client.pk]
            check(listed and "alert_template_id" in listed[0], "list row")

        def client_set_change_clear():
            row = resources.update_client(client.pk, alert_template_id=template.pk, context=ctx)
            check(row["alert_template_id"] == template.pk, row)
            client.refresh_from_db()
            check(client.alert_template_id == template.pk, "persisted")
            check(len(HOOKS) == 1, f"Tactical's own cache_agents_alert_template hook ran through obj.save: {HOOKS}")
            check(resources.update_client(client.pk, name=f"{MARK}-client", context=ctx)["alert_template_id"] == template.pk, "a rename keeps it")
            check(resources.update_client(client.pk, alert_template_id=other_template.pk, context=ctx)["alert_template_id"] == other_template.pk, "change")
            check(resources.update_client(client.pk, alert_template_id=None, context=ctx)["alert_template_id"] is None, "clear")
            client.refresh_from_db()
            check(client.alert_template_id is None, "cleared in the database")

        def site_set_and_clear():
            check(resources.update_site(site.pk, alert_template_id=template.pk, context=ctx)["alert_template_id"] == template.pk, "set")
            site.refresh_from_db()
            check(site.alert_template_id == template.pk, "persisted")
            check(resources.update_site(site.pk, alert_template_id=None, context=ctx)["alert_template_id"] is None, "clear")

        def a_missing_template_is_refused():
            for call in (lambda: resources.update_client(client.pk, alert_template_id=2**31 - 1, context=ctx),
                         lambda: resources.update_site(site.pk, alert_template_id=2**31 - 1, context=ctx)):
                try:
                    with transaction.atomic():
                        call()
                    raise AssertionError("a template that does not exist was accepted")
                except resources.ResourceValidationError as exc:
                    check("alert template" in str(exc), str(exc))
            client.refresh_from_db()
            check(client.alert_template_id is None, "nothing was written")

        def audit_rows():
            from logs.models import AuditLog

            rows = AuditLog.objects.filter(object_type="resource_client", message__icontains="modify").order_by("-pk")[:5]
            check(rows, "an audit row was written")

        def scope_descriptor_follows_the_real_relations():
            clients_role = make_role("clients", clients=[client])
            sites_role = make_role("sites", sites=[site])
            mixed_role = make_role("mixed", clients=[client], sites=[second_site])
            for role, mode, clients_n, sites_n in ((clients_role, "clients", 1, 0), (sites_role, "sites", 0, 1), (mixed_role, "mixed", 1, 1)):
                user = make_user(mode, role)
                scope = resources.scope_descriptor(context=resources.user_context(user))
                check(scope["mode"] == mode and scope["whole_client_count"] == clients_n and scope["site_count"] == sites_n and not scope["unrestricted"], (mode, scope))
                snapshot = adapter.scheduler_scope_snapshot(user=user)
                check(set(snapshot["client_ids"]) == set(scope["whole_client_ids"]), (mode, snapshot, scope))
                visible_sites = set(Site.objects.filter_by_role(user).values_list("pk", flat=True))
                check(set(snapshot["site_ids"]) == visible_sites, (mode, snapshot, visible_sites))
            sites_user = make_user("sites2", sites_role)
            check(resources.has_whole_client_access(client.pk, context=resources.user_context(sites_user)) is False, "a site-only role never holds the whole client")
            clients_user = make_user("clients2", clients_role)
            check(resources.has_whole_client_access(client.pk, context=resources.user_context(clients_user)) is True, "a granted client")
            check(resources.has_whole_client_access(2**31 - 1, context=resources.user_context(clients_user)) is False, "a client that does not exist")
            check(resources.scope_unrestricted(ctx) is True, "a superuser")
            check(resources.user_context(admin).scope["mode"] == "unrestricted", "context.scope")
            empty_user = make_user("empty", make_role("empty"))
            check(resources.scope_descriptor(context=resources.user_context(empty_user))["mode"] == "unrestricted", "both relations empty is Tactical's unrestricted rule")

        def site_role_cannot_change_the_client_template():
            role = make_role("site-writer", sites=[site])
            user = make_user("site-writer", role)
            context = resources.user_context(user)
            check(resources.update_site(site.pk, alert_template_id=template.pk, context=context)["alert_template_id"] == template.pk, "its own site")
            try:
                resources.update_client(client.pk, alert_template_id=template.pk, context=context)
                raise AssertionError("a site grant became client write authority")
            except resources.ResourceNotFound:
                pass
            try:
                resources.update_site(second_site.pk, alert_template_id=template.pk, context=context)
                raise AssertionError("another site was changed")
            except resources.ResourceNotFound:
                pass
            whole = make_user("client-writer", make_role("client-writer", clients=[client]))
            check(resources.update_client(client.pk, alert_template_id=template.pk, context=resources.user_context(whole))["alert_template_id"] == template.pk, "a whole-client role")

        for name, fn in (
            ("rows carry alert_template_id in the documented order", rows_carry_the_field),
            ("client: set, rename keeps it, change, clear, through Tactical's own save hook", client_set_change_clear),
            ("site: set and clear", site_set_and_clear),
            ("a template id that does not exist is refused by the foreign key", a_missing_template_is_refused),
            ("an audit row was written", audit_rows),
            ("the scope descriptor follows the real relations and agrees with filter_by_role", scope_descriptor_follows_the_real_relations),
            ("a role limited to one site cannot change its client's template", site_role_cannot_change_the_client_template),
        ):
            step(name, fn)
        alert_tasks.cache_agents_alert_template.delay = original_delay
        raise Rollback()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)

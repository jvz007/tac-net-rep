"""Runtime check for Core 1.17.24: policy fields on clients and sites, and the site move (core.resources 1.7.0). DEV SERVER ONLY.
It did NOT run on the development PC (Django, Tactical and its database are not installed there).

Run it on the dev server through Tactical's manage.py shell:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/resource-policy-runtime-1.17.24.py

It proves what tests/resource-policy-fields-1.17.24.py and tests/resource-move-site-1.17.24.py cannot: Tactical's real Client, Site and
Policy models. The ForeignKey refuses a policy id that names no policy, ``obj.save`` runs Tactical's own hooks
(``cache_agents_alert_template`` and the policy cache purge), the list filters run as real queries, and a site move keeps the one-site rule.

Everything runs inside one database transaction that is rolled back at the end. ``cache_agents_alert_template.delay`` is replaced in this
shell by a recorder, so no Celery broker is needed. It prints PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import sys
import uuid

from accounts.models import User
from alerts import tasks as alert_tasks
from automation.models import Policy
from clients.models import Client, Site
from django.db import transaction
from tec_tac import resources

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


POLICY_KEYS = ("workstation_policy_id", "server_policy_id", "block_policy_inheritance")

try:
    with transaction.atomic():
        original_delay = alert_tasks.cache_agents_alert_template.delay
        alert_tasks.cache_agents_alert_template.delay = lambda *a, **k: HOOKS.append((a, k))

        admin = User(username=f"{MARK}-admin", is_superuser=True)
        admin.set_password(uuid.uuid4().hex)
        admin.save()
        ctx = resources.user_context(admin)
        workstation_policy = Policy.objects.create(name=f"{MARK}-ws")
        server_policy = Policy.objects.create(name=f"{MARK}-srv")
        client = Client.objects.create(name=f"{MARK}-client")
        other_client = Client.objects.create(name=f"{MARK}-other")
        site = Site.objects.create(client=client, name=f"{MARK}-site")
        second_site = Site.objects.create(client=client, name=f"{MARK}-site-2")
        other_site = Site.objects.create(client=other_client, name=f"{MARK}-other-site")

        def rows_carry_the_fields():
            row = resources.get_client(client.pk, context=ctx)
            check(tuple(row) == resources.CLIENT_FIELDS and row["workstation_policy_id"] is None and row["block_policy_inheritance"] is False, row)
            check(tuple(resources.get_site(site.pk, context=ctx)) == resources.SITE_FIELDS, "site row")
            check(all(tuple(s) == resources.SITE_FIELDS for s in row["sites"]), "nested sites")

        def client_set_change_clear():
            row = resources.update_client(client.pk, workstation_policy_id=workstation_policy.pk, block_policy_inheritance=True, context=ctx)
            check(row["workstation_policy_id"] == workstation_policy.pk and row["block_policy_inheritance"] is True, row)
            client.refresh_from_db()
            check(client.workstation_policy_id == workstation_policy.pk and client.block_policy_inheritance is True, "persisted")
            check(len(HOOKS) == 1, f"Tactical's own cache_agents_alert_template hook ran through obj.save: {HOOKS}")
            resources.update_client(client.pk, server_policy_id=server_policy.pk, context=ctx)
            client.refresh_from_db()
            check(client.server_policy_id == server_policy.pk and client.workstation_policy_id == workstation_policy.pk, "second policy, first kept")
            row = resources.update_client(client.pk, workstation_policy_id=None, server_policy_id=None, block_policy_inheritance=False, context=ctx)
            check(row["workstation_policy_id"] is None and row["server_policy_id"] is None and row["block_policy_inheritance"] is False, row)
            client.refresh_from_db()
            check(client.workstation_policy_id is None and client.server_policy_id is None, "cleared in the database")

        def site_set_and_clear():
            del HOOKS[:]
            row = resources.update_site(site.pk, server_policy_id=server_policy.pk, block_policy_inheritance=True, context=ctx)
            check(row["server_policy_id"] == server_policy.pk and row["block_policy_inheritance"] is True, row)
            site.refresh_from_db()
            check(site.server_policy_id == server_policy.pk, "persisted")
            check(len(HOOKS) == 1, f"Site.save hook ran: {HOOKS}")
            check(resources.update_site(site.pk, server_policy_id=None, block_policy_inheritance=False, context=ctx)["server_policy_id"] is None, "clear")

        def a_missing_policy_is_refused():
            for key in ("workstation_policy_id", "server_policy_id"):
                for call in (lambda key=key: resources.update_client(client.pk, context=ctx, **{key: 2**31 - 1}),
                             lambda key=key: resources.update_site(site.pk, context=ctx, **{key: 2**31 - 1})):
                    try:
                        with transaction.atomic():
                            call()
                        raise AssertionError("a policy that does not exist was accepted")
                    except resources.ResourceValidationError as exc:
                        check(str(exc) == f"{key} does not name an existing policy.", str(exc))
            client.refresh_from_db()
            check(client.workstation_policy_id is None and client.server_policy_id is None, "nothing was written")

        def an_unchanged_value_writes_no_row():
            from logs.models import AuditLog

            resources.update_client(client.pk, workstation_policy_id=workstation_policy.pk, context=ctx)
            before = AuditLog.objects.filter(object_type="resource_client").count()
            resources.update_client(client.pk, workstation_policy_id=workstation_policy.pk, context=ctx)
            check(AuditLog.objects.filter(object_type="resource_client").count() == before, "no row for an unchanged value")
            resources.update_client(client.pk, workstation_policy_id=None, context=ctx)

        def list_filters_are_real_queries():
            resources.update_client(client.pk, workstation_policy_id=workstation_policy.pk, context=ctx)
            resources.update_site(other_site.pk, server_policy_id=workstation_policy.pk, context=ctx)
            clients = [r["id"] for r in resources.list_clients(context=ctx, policy_id=workstation_policy.pk)["items"]]
            check(client.pk in clients and other_client.pk not in clients, clients)
            sites = [r["id"] for r in resources.list_sites(context=ctx, policy_id=workstation_policy.pk)["items"]]
            check(other_site.pk in sites and site.pk not in sites, sites)
            check(resources.list_clients(context=ctx, policy_id=server_policy.pk)["items"] == [], "unused policy")
            check(resources.list_sites(context=ctx, alert_template_id=2**31 - 1)["items"] == [], "unused template")

        def site_move():
            from logs.models import AuditLog

            del HOOKS[:]
            row = resources.update_site(second_site.pk, client_id=other_client.pk, context=ctx)
            check(row["client_id"] == other_client.pk and row["client_name"] == other_client.name, row)
            second_site.refresh_from_db()
            check(second_site.client_id == other_client.pk, "persisted")
            check(len(HOOKS) == 1, f"Tactical's Site.save hook ran on a move: {HOOKS}")
            last = AuditLog.objects.filter(object_type="resource_site", object_id=str(second_site.pk)).order_by("-pk").first()
            check(last is not None, "an audit row was written")
            try:
                resources.update_site(site.pk, client_id=other_client.pk, context=ctx)
                raise AssertionError("the last site of a client moved away")
            except resources.ResourceValidationError as exc:
                check(str(exc) == "A client must retain at least one site.", str(exc))
            Site.objects.filter(pk=site.pk).update(name=second_site.name)
            try:
                with transaction.atomic():
                    resources.update_site(second_site.pk, client_id=client.pk, context=ctx)
                raise AssertionError("a name clash was accepted")
            except resources.ResourceConflict as exc:
                check(str(exc) == "A site with that name already exists for the selected client.", str(exc))

        for name, fn in (
            ("rows carry the policy fields in the documented order", rows_carry_the_fields),
            ("client: set, keep, clear, through Tactical's own save hook", client_set_change_clear),
            ("site: set and clear, through Tactical's own save hook", site_set_and_clear),
            ("a policy id that does not exist is refused by the foreign key", a_missing_policy_is_refused),
            ("an unchanged value writes no audit row", an_unchanged_value_writes_no_row),
            ("the alert_template_id and policy_id filters are real queries", list_filters_are_real_queries),
            ("a site move, the last-site rule and a name clash", site_move),
        ):
            step(name, fn)
        alert_tasks.cache_agents_alert_template.delay = original_delay
        raise Rollback()
except Rollback:
    pass

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)

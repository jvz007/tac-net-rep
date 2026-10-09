"""Runtime check for Core 1.17.7 Tactical operations. It did NOT run on the development PC (Django is not installed there).

Run it on the dev server through Tactical's manage.py shell, so Django, Tactical's real URL resolver, DRF and Tactical's
real views are loaded:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/tactical-operations-runtime-1.17.7.py

It proves what the stub test (tests/tactical-operations-1.17.7.py) cannot: that Tactical's own resolver finds a real
route, that DRF's forced authentication carries the signed-in user into Tactical's own view with no Authorization
header, that Core's audit row reaches Tactical's AuditLog with the right user and module, that a denied user gets a
deny row, and that an unknown route gives the typed refusal.

It prints PASS or FAIL for each step and exits with status 1 when any step fails. It registers a throwaway GET
operation (GET core/version/, can_view_core_settings), creates throwaway roles and users inside a transaction that is
rolled back, deletes every audit row it wrote and clears the registry of this shell process. It makes no change to Tactical.
"""
import sys

from accounts.models import Role, User
from django.conf import settings as django_settings
from django.db import transaction
from django.test import RequestFactory
from logs.models import AuditLog
from tec_tac import tactical_operations as ops
from tec_tac.audit import AuditContractError, record
from tec_tac.registry import get_plugins

PROBE_TYPE = "tectac_runtime_probe"
RESULTS = []


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


def refused(fn, status, code):
    try:
        fn()
    except ops.TacticalOperationError as exc:
        assert exc.status == status and exc.code == code, (exc.status, exc.code)
        return
    raise AssertionError(f"expected {status} {code}")


def rows(action=None):
    query = AuditLog.objects.filter(object_type=PROBE_TYPE)
    return query.filter(action=action) if action else query


def left_behind():
    assert not rows().exists(), "probe audit rows remain"
    assert not User.objects.filter(username__startswith="tectac-runtime-").exists(), "probe users remain"
    assert not Role.objects.filter(name__startswith="tectac-runtime-").exists(), "probe roles remain"
    assert ops.get_operation(OWNER, "runtime-version") is None, "the throwaway operation was not cleared"


# Since 1.17.7-1 Core only accepts an operation from the core module that owns the route's Tactical group.
enabled = [p for p in get_plugins() if p.plugin_type == "extension" and p.category == "core" and p.plugin_id in ops.GROUP_OWNERS["core"]]
if not enabled:
    print("FAIL setup: no installed core module that owns Tactical's core/ group (globalsettings, reportmanager, scriptmanager) to declare the probe operation under")
    sys.exit(1)
OWNER = enabled[0].plugin_id
factory = RequestFactory()


def request_for(user):
    request = factory.get("/api/tfd/tactical-operations/probe/probe/")  # no Authorization header at all
    request.user = user
    return request


try:
    ops.register_tactical_operation(
        "runtime-version", OWNER, "GET", "core/version/", ["can_view_core_settings"], [], [],
        {"action": "view", "object_type": PROBE_TYPE, "audit_fields": []}, message="Core runtime probe read the Tactical version.",
    )
    ops.register_tactical_operation(
        "runtime-renamed", OWNER, "GET", "core/versionx-does-not-exist/", ["can_view_core_settings"], [], [],
        {"action": "view", "object_type": PROBE_TYPE, "audit_fields": []},
    )

    with transaction.atomic():
        role_ok = Role.objects.create(name="tectac-runtime-ok", can_view_core_settings=True)
        role_no = Role.objects.create(name="tectac-runtime-no")
        allowed = User.objects.create(username="tectac-runtime-allowed", email="a@example.invalid", role=role_ok)
        denied = User.objects.create(username="tectac-runtime-denied", email="d@example.invalid", role=role_no)
        installer = User.objects.create(username="tectac-runtime-installer", email="i@example.invalid", role=role_ok, is_installer_user=True)

        def s1_dispatch():
            result = ops.run_tactical_operation(request_for(allowed), OWNER, "runtime-version")
            assert result.status == 200, result
            assert result.data == django_settings.APP_VER, (result.data, django_settings.APP_VER)
            assert result.audit.get("recorded") is True, result.audit

        def s2_row():
            row = rows("view").order_by("-id").first()
            assert row is not None and row.username == "tectac-runtime-allowed", row
            info = row.debug_info
            assert info["module_id"] == OWNER and info["actor_identity"] == "tectac-runtime-allowed", info
            ctx = info["operation_context"]
            assert ctx["server_provenance"] == "tactical-operation" and ctx["operation"] == "runtime-version" and ctx["tactical_status"] == 200, ctx

        def s3_denied():
            before = rows("deny").count()
            refused(lambda: ops.run_tactical_operation(request_for(denied), OWNER, "runtime-version"), 403, "tactical_permission_denied")
            deny = rows("deny").order_by("-id").first()
            assert rows("deny").count() == before + 1 and deny.username == "tectac-runtime-denied", deny
            assert deny.debug_info["operation_context"]["core_refusal"] is True, deny.debug_info

        def s4_installer():
            refused(lambda: ops.run_tactical_operation(request_for(installer), OWNER, "runtime-version"), 403, "tactical_permission_denied")

        def s5_unknown_route():
            before = rows().count()
            refused(lambda: ops.run_tactical_operation(request_for(allowed), OWNER, "runtime-renamed"), 502, "tactical_route_changed")
            assert rows().count() == before, "an unreachable route writes no row"

        def s6_unknown_operation():
            refused(lambda: ops.run_tactical_operation(request_for(allowed), OWNER, "no-such-operation"), 404, "tactical_operation_not_found")

        def s7_forged_keys():
            for key in ("browser_provenance", "server_provenance", "core_refusal"):
                try:
                    record(actor=allowed, module_id=OWNER, action="view", object_type=PROBE_TYPE, operation_context={key: "x"})
                except AuditContractError:
                    continue
                raise AssertionError(f"record() accepted {key}")

        def s8_capability_and_contract():
            from tec_tac.capabilities import capability_status
            from tec_tac.contracts import build_contract_catalog

            assert capability_status("core.tactical_operations", version=">=1,<2")["available"]
            catalog = build_contract_catalog()
            assert any(c["name"] == "run_tactical_operation" for c in catalog["core"]), "python contract row missing"
            assert any(r["route"].startswith("/api/tfd/tactical-operations/") for r in catalog["http"]), "http contract row missing"

        for name, fn in (
            ("1 dispatch through Tactical's own view as the signed-in user, no Authorization header", s1_dispatch),
            ("2 audit row names the user, the module, the operation and Tactical's status", s2_row),
            ("3 a role without the flag gets a Core deny row", s3_denied),
            ("4 an installer user is denied", s4_installer),
            ("5 a route Tactical does not serve gives tactical_route_changed and no row", s5_unknown_route),
            ("6 an unknown operation gives the typed refusal", s6_unknown_operation),
            ("7 record() refuses the three Core-owned provenance keys", s7_forged_keys),
            ("8 the capability and the contract export list the executor", s8_capability_and_contract),
        ):
            step(name, fn)
        transaction.set_rollback(True)  # throwaway roles, users and the rows written in this transaction
finally:
    ops._clear_operations_for_tests()
    AuditLog.objects.filter(object_type=PROBE_TYPE).delete()

step("9 nothing is left behind", left_behind)

print("tactical operations runtime 1.17.7: " + ("PASS" if all(RESULTS) else "FAIL"))
if not all(RESULTS):
    sys.exit(1)

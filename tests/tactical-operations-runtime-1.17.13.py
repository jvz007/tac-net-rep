"""Runtime check for Core 1.17.13 Tactical operations. It did NOT run on the development PC (Django is not installed there).

Run it on the dev server through Tactical's manage.py shell, so Django, Tactical's real URL resolver, DRF, Tactical's real views
and Tactical's real AuditLog are loaded:

    cd /rmm/api/tacticalrmm && ../env/bin/python manage.py shell < /path/to/tests/tactical-operations-runtime-1.17.13.py

It proves what the stub tests (tests/tactical-operations-audit-object-1.17.13.py, tests/tactical-operations-query-upload-1.17.13.py)
cannot:

1. the real `GET agents/notes/<pk>/` read through Tactical's own view as the signed-in user, and the whitelisted before value;
2. `object_id` equal to the note pk on the real AuditLog row, and the before value in `before_value`;
3. the role's client limit applied to the agent of the note (and the fail-closed answer when the read does not answer 200, which
   includes a role that may manage notes but not list them, CQ37);
4. a scope type taken from the body (`POST agents/maintenance/bulk/`, Client and Site) with `scope_type` in the row metadata;
5. the query string reaching DRF's `request.query_params` (`GET reporting/assets/?path=`);
6. a real multipart upload parsed by Tactical's own MultiPartParser (`POST reporting/assets/upload/`, the part named after the file),
   and an audit row that holds the file name, size and type, never the content;
7. what Core does with Tactical's `FileResponse` for `GET reporting/assets/download/?path=` (a streamed answer, which Core refuses
   today: see the release notes);
8. the status rows read the real root config (module category fields).

It prints PASS, FAIL or SKIP for each step and exits with status 1 when any step fails. Steps that need an installed module (agents,
reportmanager) are skipped when it is not installed. It creates a throwaway client, site, agent, note, roles and users inside a
transaction that is rolled back, deletes every audit row it wrote, deletes the report asset it uploaded, and clears the registry of this
shell process. The agent and its note are never reachable by a real user, and no message is sent to any agent.
"""
import json
import sys

from accounts.models import Role, User
from agents.models import Agent, Note
from clients.models import Client, Site
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction
from django.test import RequestFactory
from rest_framework.test import APIRequestFactory, force_authenticate
from logs.models import AuditLog
from tec_tac import module_category, tactical_operations as ops
from tec_tac.registry import get_plugins

PROBE_TYPE = "tectac_runtime_probe"
RESULTS = []
SKIPPED = []
factory = RequestFactory()


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


def skip(name, why):
    SKIPPED.append(name)
    print(f"SKIP {name}: {why}")


def refused(fn, status, code):
    try:
        fn()
    except ops.TacticalOperationError as exc:
        assert exc.status == status and exc.code == code, (exc.status, exc.code, exc.message)
        return exc
    raise AssertionError(f"expected {status} {code}")


def rows(action=None):
    query = AuditLog.objects.filter(object_type=PROBE_TYPE)
    return query.filter(action=action) if action else query


def request_for(user):
    request = factory.get("/api/tfd/tactical-operations/probe/probe/")  # no Authorization header at all
    request.user = user
    return request


def installed_owner(rule):
    """The installed core module that owns a Tactical route rule (module id), or None."""
    owners = ops.ROUTE_OWNERS[rule]
    for plugin in get_plugins():
        if plugin.plugin_type == "extension" and plugin.category == "core" and plugin.plugin_id in owners:
            return plugin.plugin_id
    return None


AGENTS = installed_owner(("agents",))
REPORTS = installed_owner(("reporting",))
UPLOADED = []

try:
    if AGENTS:
        ops.register_tactical_operation(
            "runtime-note-edit", AGENTS, "PUT", "agents/notes/{pk:int}/", ["can_manage_notes"], [{"type": "agent", "source": "before:agent_id"}], ["note"],
            {"action": "modify", "object_type": PROBE_TYPE, "audit_fields": [], "object_param": "pk",
             "before": {"route": "agents/notes/{pk:int}/", "fields": ["agent_id", "note", "username", "entry_time"]}},
        )
        ops.register_tactical_operation(
            "runtime-maintenance", AGENTS, "POST", "agents/maintenance/bulk/", ["can_edit_agent"],
            [{"type": "body:type", "source": "body:id", "type_map": {"Client": "client", "Site": "site"}}], ["type", "id", "action"],
            {"action": "modify", "object_type": PROBE_TYPE, "audit_fields": ["action"]},
        )
    if REPORTS:
        ops.register_tactical_operation(
            "runtime-assets-list", REPORTS, "GET", "reporting/assets/", ["can_manage_reports"], [], [],
            {"action": "view", "object_type": PROBE_TYPE, "audit_fields": ["path"]}, query_params=["path"],
        )
        ops.register_tactical_operation(
            "runtime-assets-download", REPORTS, "GET", "reporting/assets/download/", ["can_manage_reports"], [], [],
            {"action": "export", "object_type": PROBE_TYPE, "audit_fields": ["path"]}, query_params=["path"],
        )
        ops.register_tactical_operation(
            "runtime-assets-upload", REPORTS, "POST", "reporting/assets/upload/", ["can_manage_reports"], [], ["parentPath"],
            {"action": "add", "object_type": PROBE_TYPE, "audit_fields": ["parentPath"]},
            upload={"field": ops.FILE_NAME_FIELD, "max_bytes": 100000, "extensions": ["png"]},
        )

    with transaction.atomic():
        client = Client.objects.create(name="tectac-runtime-client")
        other = Client.objects.create(name="tectac-runtime-other")
        site = Site.objects.create(client=client, name="tectac-runtime-site")
        other_site = Site.objects.create(client=other, name="tectac-runtime-other-site")
        agent = Agent.objects.create(agent_id="tectacruntimeprobe" + "0" * 10, hostname="tectac-runtime-host", site=site)
        note = Note.objects.create(agent=agent, note="original note", user=None)
        role_in = Role.objects.create(name="tectac-runtime-in", can_manage_notes=True, can_list_notes=True, can_edit_agent=True, can_manage_reports=True)
        role_in.can_view_clients.add(client)
        role_in.can_view_sites.add(site)
        role_out = Role.objects.create(name="tectac-runtime-out", can_manage_notes=True, can_list_notes=True, can_edit_agent=True)
        role_out.can_view_clients.add(other)
        role_out.can_view_sites.add(other_site)
        role_nolist = Role.objects.create(name="tectac-runtime-nolist", can_manage_notes=True)
        role_nolist.can_view_clients.add(client)
        role_nolist.can_view_sites.add(site)
        user_in = User.objects.create(username="tectac-runtime-in", email="i@example.invalid", role=role_in)
        user_out = User.objects.create(username="tectac-runtime-out", email="o@example.invalid", role=role_out)
        user_nolist = User.objects.create(username="tectac-runtime-nolist", email="n@example.invalid", role=role_nolist)

        def run(user, operation, module=None, **kwargs):
            return ops.run_tactical_operation(request_for(user), module or AGENTS, operation, **kwargs)

        def n1_note_edit():
            result = run(user_in, "runtime-note-edit", params={"pk": note.pk}, body={"note": "edited note"})
            assert result.status == 200, (result.status, result.data)
            note.refresh_from_db()
            assert note.note == "edited note", note.note
            assert result.audit.get("recorded") is True, result.audit

        def n2_row_object_and_before():
            row = rows("modify").filter(debug_info__object_id=str(note.pk)).order_by("-id").first()
            assert row is not None, "no row with object_id equal to the note pk"
            assert row.username == "tectac-runtime-in" and row.debug_info["module_id"] == AGENTS, row.debug_info
            before = row.before_value
            assert before["agent_id"] == agent.agent_id and before["note"] == "original note", before
            assert set(before) <= {"agent_id", "note", "username", "entry_time"}, before
            assert row.debug_info["metadata"]["before"] == "recorded", row.debug_info["metadata"]

        def n3_out_of_scope():
            before_count = rows("deny").count()
            refused(lambda: run(user_out, "runtime-note-edit", params={"pk": note.pk}, body={"note": "x"}), 404, "object_not_found")
            deny = rows("deny").order_by("-id").first()
            assert rows("deny").count() == before_count + 1 and deny.debug_info["object_id"] == str(note.pk), deny.debug_info
            note.refresh_from_db()
            assert note.note == "edited note", "an out-of-scope user changed the note"

        def n4_cannot_list_fails_closed():
            # Tactical's GET agents/notes/<pk>/ needs can_list_notes, so the read answers 403 and Core refuses (CQ37, assumption a)
            refused(lambda: run(user_nolist, "runtime-note-edit", params={"pk": note.pk}, body={"note": "x"}), 404, "object_not_found")
            note.refresh_from_db()
            assert note.note == "edited note", note.note

        def n5_missing_note():
            refused(lambda: run(user_in, "runtime-note-edit", params={"pk": 2147483000}, body={"note": "x"}), 404, "object_not_found")

        def n6_body_scope_type():
            result = run(user_in, "runtime-maintenance", body={"type": "Client", "id": client.pk, "action": True})
            assert result.status == 200, (result.status, result.data)
            row = rows("modify").filter(debug_info__metadata__scope_type="client").order_by("-id").first()
            assert row is not None and row.debug_info["object_id"] == str(client.pk), "no client row"
            result = run(user_in, "runtime-maintenance", body={"type": "Site", "id": site.pk, "action": False})
            assert result.status == 200, (result.status, result.data)
            assert rows("modify").filter(debug_info__metadata__scope_type="site").exists(), "no site row"
            refused(lambda: run(user_in, "runtime-maintenance", body={"type": "Site", "id": other_site.pk, "action": True}), 404, "object_not_found")
            refused(lambda: run(user_in, "runtime-maintenance", body={"type": "Agent", "id": site.pk, "action": True}), 400, "scope_field_required")

        if AGENTS:
            for name, fn in (
                ("1 a note edit reads the note through Tactical's own view and runs", n1_note_edit),
                ("2 the real row carries object_id equal to the note pk and a whitelisted before value", n2_row_object_and_before),
                ("3 a role limited to another client is refused with a deny row, the note is unchanged", n3_out_of_scope),
                ("4 a role that may manage but not list notes fails closed (CQ37)", n4_cannot_list_fails_closed),
                ("5 a note that does not exist gives the same 404", n5_missing_note),
                ("6 the scope type comes from the body (Client, Site) and scope_type is in the row", n6_body_scope_type),
            ):
                step(name, fn)
        else:
            skip("1 to 6 note and maintenance operations", "no installed core module owns agents/")

        def q1_query_string():
            listing = run(user_in, "runtime-assets-list", module=REPORTS, query={"path": ""})
            assert listing.status == 200 and isinstance(listing.data, list), (listing.status, listing.data)
            missing = run(user_in, "runtime-assets-list", module=REPORTS, query={"path": "tectac-runtime-no-such-folder"})
            assert missing.status == 400, ("Tactical did not read the path from query_params", missing.status, missing.data)
            row = rows("view").order_by("-id").first()
            assert row is not None and row.after_value == {"path": ""}, row

        def q2_upload():
            content = b"\x89PNG\r\n\x1a\nTECTAC-RUNTIME-PROBE-CONTENT"
            result = run(user_in, "runtime-assets-upload", module=REPORTS, body={"parentPath": ""},
                         upload={"name": "tectac-runtime-probe.png", "content_type": "image/png", "content": content})
            UPLOADED.append("tectac-runtime-probe.png")
            assert result.status == 200, (result.status, result.data)
            assert "tectac-runtime-probe.png" in result.data, result.data
            from ee.reporting.models import ReportAsset

            assert ReportAsset.objects.filter(file="tectac-runtime-probe.png").exists(), "Tactical's own parser did not store the file"
            row = rows("add").order_by("-id").first()
            assert row.after_value["upload"] == {"file_name": "tectac-runtime-probe.png", "size": len(content), "content_type": "image/png"}, row.after_value
            assert "TECTAC-RUNTIME-PROBE-CONTENT" not in json.dumps(row.after_value) + json.dumps(row.debug_info, default=str), "file content in the row"
            refused(lambda: run(user_in, "runtime-assets-upload", module=REPORTS, body={"parentPath": ""},
                                upload={"name": "evil.exe", "content_type": "image/png", "content": content}), 400, "upload_type_not_allowed")
            refused(lambda: run(user_in, "runtime-assets-upload", module=REPORTS, body={"parentPath": ""},
                                upload={"name": "big.png", "content_type": "image/png", "content": b"x" * 100001}), 413, "upload_too_large")

        def q2b_multipart_through_the_view():
            # The HTTP view with a real multipart request: DRF puts the file part into request.data, which the view must not refuse.
            from ee.reporting.models import ReportAsset
            from tec_tac.tactical_operation_views import TacticalOperationView

            content = b"\x89PNG\r\n\x1a\nTECTAC-RUNTIME-VIEW-PROBE"
            name = "tectac-runtime-view-probe.png"
            http = APIRequestFactory().post(
                f"/api/tfd/tactical-operations/{REPORTS}/runtime-assets-upload/",
                {"params": "{}", "body": json.dumps({"parentPath": ""}), "query": "", name: SimpleUploadedFile(name, content, content_type="image/png")},
                format="multipart",
            )
            force_authenticate(http, user=user_in)
            response = TacticalOperationView.as_view()(http, module_id=REPORTS, operation_id="runtime-assets-upload")
            UPLOADED.append(name)
            assert response.status_code == 200, (response.status_code, getattr(response, "data", None))
            assert ReportAsset.objects.filter(file=name).exists(), "the view did not store the uploaded asset"
            row = rows("add").order_by("-id").first()
            assert row.after_value["upload"]["file_name"] == name and row.after_value["upload"]["size"] == len(content), row.after_value

        def q3_download_is_streamed():
            # Tactical answers with a FileResponse. Core refuses a streamed answer (a separate request), so this is a 502 today.
            exc = refused(lambda: run(user_in, "runtime-assets-download", module=REPORTS, query={"path": "tectac-runtime-probe.png"}), 502, "tactical_response_refused")
            assert exc.audit is None, "a refused GET writes no row"

        if REPORTS:
            step("7 the query string reaches Tactical's request.query_params", q1_query_string)
            step("8 a real multipart upload is parsed by Tactical, stored, and audited without its content", q2_upload)
            step("8b a real multipart POST through the HTTP view is accepted, stored and audited", q2b_multipart_through_the_view)
            step("9 a streamed file answer is refused today (the download is held for the streamed-file relay)", q3_download_is_streamed)
        else:
            skip("7 to 9 report asset operations", "no installed core module owns reporting/")

        def c1_status_rows_read_root_config():
            from tec_tac import trust_policy
            from tec_tac.module_runtime import module_runtime_snapshot

            environment = trust_policy._server_environment()
            print(f"INFO the root config says TEC_TAC_ENVIRONMENT is {environment}")
            assert module_category.is_development_server() is (environment == "development")
            for row in module_runtime_snapshot():
                assert {"category", "effective_category", "category_missing", "category_refused", "category_warning"} <= set(row), row
                if row["category"] is None and not row["legacy"]:
                    assert row["effective_category"] == "test" and row["category_missing"] is True and row["category_warning"], row
                    assert row["category_refused"] is (environment != "development"), row

        step("10 the status rows carry the category fields and read the real root config", c1_status_rows_read_root_config)
        transaction.set_rollback(True)  # throwaway client, site, agent, note, roles, users and the rows written in this transaction
finally:
    ops._clear_operations_for_tests()
    AuditLog.objects.filter(object_type=PROBE_TYPE).delete()
    if UPLOADED:
        from ee.reporting.models import ReportAsset

        for asset in ReportAsset.objects.filter(file__in=UPLOADED):
            asset.file.delete()
            asset.delete()


def left_behind():
    assert not rows().exists(), "probe audit rows remain"
    assert not User.objects.filter(username__startswith="tectac-runtime-").exists(), "probe users remain"
    assert not Role.objects.filter(name__startswith="tectac-runtime-").exists(), "probe roles remain"
    assert not Client.objects.filter(name__startswith="tectac-runtime-").exists(), "probe clients remain"
    assert not Agent.objects.filter(hostname="tectac-runtime-host").exists(), "the probe agent remains"
    if AGENTS:
        assert ops.get_operation(AGENTS, "runtime-note-edit") is None, "the throwaway operation was not cleared"


step("11 nothing is left behind", left_behind)

print("tactical operations runtime 1.17.13: " + ("PASS" if all(RESULTS) else "FAIL") + (f" ({len(SKIPPED)} skipped)" if SKIPPED else ""))
if not all(RESULTS):
    sys.exit(1)

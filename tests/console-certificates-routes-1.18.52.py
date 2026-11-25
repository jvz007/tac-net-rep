#!/usr/bin/env python3
"""Regression: Core 1.18.52 (C3). The management routes, their permissions and the audit rows.

Real Django on a temporary SQLite file and the real views. Checks every route's permission rule (a refusal is a 403 with one deny row), the
answer shapes key by key, paging, self-service, the strict audit rows rolling the change back, the nine row types and the contract surface.
"""
import ast
import importlib.util
import re
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cc_harness", Path(__file__).with_name("console_certificates_harness.py"))
harness = importlib.util.module_from_spec(spec)
sys.modules["cc_harness"] = harness
spec.loader.exec_module(harness)
must, rows_of = harness.must, harness.rows_of
h = harness.boot()
if h is None:
    print("console certificates routes 1.18.52 regression: SKIPPED (Django is not installed on this PC)")
    sys.exit(0)

cc, M, V = h.cc, h.models, h.views
VIEW, MANAGE = "core.console_certificates.view", "core.console_certificates.manage"
BASE = "/api/tfd/console-certificates/"


def call(view, method, path, user, data=None, **kw):
    return h.call(view, method, BASE + path, user, data, **kw)


def denies():
    return rows_of(h, "deny")


def issue_cert(admin, engineer, label):
    _u, _c, _code, r = h.full_flow(admin, engineer, pc_label=label)
    must(r.status_code == 201, f"{label}: {r.status_code} {getattr(r, 'data', '')}")
    return r.data["serial"]


h.reset()
admin = h.new_user("admin", superuser=True)
manager = h.new_user("manager", perms=(MANAGE,))
viewer = h.new_user("viewer", perms=(VIEW,))
plain = h.new_user("plain")
other = h.new_user("other")

# ---- permission refusals: 403 and one deny row, for each route
issue_target = {"user_id": plain.pk}
refusals = [
    ("issue by a viewer", V.ConsoleCertificateIssueView, "POST", "issue/", viewer, issue_target, {}, "console_certificate"),
    ("issue by nobody", V.ConsoleCertificateIssueView, "POST", "issue/", plain, issue_target, {}, "console_certificate"),
    ("cancel by a viewer", V.ConsoleCertificateEnrolmentCancelView, "POST", "enrolments/00000000-0000-0000-0000-000000000001/cancel/", viewer, {},
     {"url_kwargs": {"enrolment_id": "00000000-0000-0000-0000-000000000001"}}, "console_certificate"),
    ("ca read by nobody", V.ConsoleCertificateCaView, "GET", "ca/", plain, None, {}, "console_ca"),
    ("ca replace by a manager", V.ConsoleCertificateCaReplaceView, "POST", "ca/replace/", manager, {"confirm": True}, {}, "console_ca"),
    ("ca replace by a viewer", V.ConsoleCertificateCaReplaceView, "POST", "ca/replace/", viewer, {"confirm": True}, {}, "console_ca"),
]
for name, view, method, path, user, data, extra, object_type in refusals:
    before = len(denies())
    r = call(view, method, path, user, data, **extra)
    must(r.status_code == 403, f"{name}: {r.status_code}")
    must(len(denies()) == before + 1, f"{name}: one deny row")
    row = denies()[-1]
    must(row["module_id"] == "core" and row["object_type"] == object_type and row["metadata"] == {"reason": "permission_required"} and row["strict"] is False,
         f"{name}: deny row shape {row}")
    must(row["operation_context"] == {"server_provenance": "console-certificates", "core_refusal": True}, f"{name}: refusal marker")
must(not M.TecTacConsoleCA.objects.exists() and not M.TecTacConsoleEnrolment.objects.exists(), "no refusal changed anything")
must(call(V.ConsoleCertificateCaView, "GET", "ca/", viewer).status_code == 200, "view may read the CA status")
must(call(V.ConsoleCertificateCaView, "GET", "ca/", manager).status_code == 200, "manage may read the CA status too")

# ---- issue: a manager may, to anyone including themselves; the answer shape
r = call(V.ConsoleCertificateIssueView, "POST", "issue/", manager, {"user_id": manager.pk})
must(r.status_code == 201 and set(r.data) == {"id", "engineer_id", "username", "authorised_at", "expires_at"}, f"issue shape: {r.status_code} {r.data}")
must(r["Cache-Control"] == "no-store", "no-store")
must(len(rows_of(h, "custom:console-cert-issue-authorised")) == 1 and len(rows_of(h, "custom:console-ca-created")) == 1, "issue wrote its rows (and created the CA)")
authorised = rows_of(h, "custom:console-cert-issue-authorised")[0]
must(authorised["strict"] is True and authorised["actor"] is manager and authorised["metadata"]["engineer_id"] == manager.pk, "audited, by the manager, for themselves")
must("code" not in str(r.data).lower().replace("engineer", ""), "the administrator never sees a code")
for body, why in (({"user_id": "5"}, "a text id"), ({"user_id": True}, "a bool id"), ({"user_id": 0}, "zero"), ({}, "no id"), ({"user_id": 1, "x": 1}, "an unknown key")):
    must(call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, body).status_code == 400, f"issue refuses {why}")
must(call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": 99999}).data["code"] == "user_not_found", "user_not_found")
must(call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": 99999}).status_code == 404, "404")
sleeper = h.new_user("sleeper", active=False)
must(call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": sleeper.pk}).status_code == 409, "an inactive account: 409")
blocked = h.new_user("blocked", block_dashboard_login=True)
must(call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": blocked.pk}).data["code"] == "account_inactive", "a blocked account")
installer = h.new_user("inst", is_installer_user=True)
must(call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": installer.pk}).data["code"] == "account_inactive", "an installer account")

# issuing again cancels the earlier open enrolment and keeps one
first_id = M.TecTacConsoleEnrolment.objects.get(user_id=manager.pk, state="open").id
call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": manager.pk})
must(M.TecTacConsoleEnrolment.objects.filter(user_id=manager.pk, state="open").count() == 1, "one open enrolment")
must(M.TecTacConsoleEnrolment.objects.get(pk=first_id).state == "cancelled", "the earlier one is cancelled")

# ---- cancel
open_row = M.TecTacConsoleEnrolment.objects.get(user_id=manager.pk, state="open")
r = call(V.ConsoleCertificateEnrolmentCancelView, "POST", f"enrolments/{open_row.id}/cancel/", manager, {}, url_kwargs={"enrolment_id": open_row.id})
must(r.status_code == 200 and set(r.data) == {"id", "engineer_id", "state"} and r.data["state"] == "cancelled", f"cancel shape: {r.data}")
must(len(rows_of(h, "custom:console-cert-enrolment-cancelled")) == 1, "cancel row")
r = call(V.ConsoleCertificateEnrolmentCancelView, "POST", "x", manager, {}, url_kwargs={"enrolment_id": open_row.id})
must(r.status_code == 409 and r.data["code"] == "enrolment_not_open", "cancelling twice is 409")
r = call(V.ConsoleCertificateEnrolmentCancelView, "POST", "x", manager, {}, url_kwargs={"enrolment_id": "11111111-1111-1111-1111-111111111111"})
must(r.status_code == 404, "an unknown enrolment is 404")

# ---- mine, the code route and the list
r = call(V.ConsoleCertificateMineView, "GET", "mine/", plain)
must(set(r.data) == {"certificates", "enrolment", "host", "server_id", "validity_days"}, f"mine keys: {sorted(r.data)}")
must(r.data["certificates"] == [] and r.data["enrolment"] is None and r.data["host"] == harness.HOST and r.data["validity_days"] == 365, "mine values")
must(r.data["server_id"] == cc.active_ca().server_id, "mine shows the server id")
r = call(V.ConsoleCertificateEnrolmentCodeView, "POST", "mine/enrolment-code/", plain, {})
must(r.status_code == 409 and r.data["detail"] == "Ask your administrator to issue you a Console certificate.", f"no enrolment: {r.status_code} {r.data}")
call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": plain.pk})
r = call(V.ConsoleCertificateEnrolmentCodeView, "POST", "mine/enrolment-code/", plain, {})
must(r.status_code == 200 and set(r.data) == {"code", "code_expires_at", "expires_in_seconds", "host", "server_id", "enrolment_id"}, f"code shape: {r.data}")
must(r["Cache-Control"] == "no-store" and len(r.data["code"]) == 43 and r.data["expires_in_seconds"] == 600, "code answer")
must(M.TecTacConsoleEnrolment.objects.get(user_id=plain.pk, state="open").code_hash != r.data["code"], "only the hash is stored")
must(call(V.ConsoleCertificateEnrolmentCodeView, "POST", "mine/enrolment-code/", plain, {"x": 1}).status_code == 400, "a body with keys is refused")
r = call(V.ConsoleCertificateEnrolmentCodeView, "POST", "mine/enrolment-code/", plain, {}, HTTP_HOST="tec.example.com:8443")
must(r.status_code == 400 and r.data["code"] == "host_unusable", "host_unusable on another port")
h.cache.clear()
must(len(rows_of(h, "custom:console-cert-enrol-code")) == 1 and rows_of(h, "custom:console-cert-enrol-code")[0]["strict"] is False, "one non-strict code row")
for _ in range(6):
    r = call(V.ConsoleCertificateEnrolmentCodeView, "POST", "mine/enrolment-code/", plain, {})
must(r.status_code == 429, "the code route is limited to 5 a minute")
h.cache.clear()

# certificates for the list tests
h.reset()
admin = h.new_user("admin", superuser=True)
manager = h.new_user("manager", perms=(MANAGE,))
viewer = h.new_user("viewer", perms=(VIEW,))
alice, bob = h.new_user("alice"), h.new_user("bob")
alice_serial = issue_cert(admin, alice, "Alice PC")
bob_serial = issue_cert(admin, bob, "Bob PC")
ca = cc.active_ca()
now = cc._now()
for i in range(55):  # rows straight in the table: the paging checks need more than three
    M.TecTacConsoleCertificate.objects.create(serial=f"{i + 1:032x}", ca=ca, user_id=manager.pk, username_snapshot="manager", pc_label=f"PC {i}", spki_sha256="0" * 64,
                                              cert_der=b"x", not_before=now - timedelta(days=1), not_after=now + timedelta(days=100), state="active")
r = call(V.ConsoleCertificateListView, "GET", "", alice)
must([row["serial"] for row in r.data["results"]] == [alice_serial], "a person with no permission sees only their own rows")
must(r.data["count"] == 1 and r.data["page"] == 1 and r.data["page_size"] == 50, "list envelope")
must(set(r.data["results"][0]) == {"serial", "short_serial", "pc_label", "username", "engineer_id", "issued_at", "not_after", "state", "expiring", "revoked_at",
                                   "revoked_reason", "last_used_at"}, f"row keys: {sorted(r.data['results'][0])}")
must(r.data["results"][0]["state"] == "active" and r.data["results"][0]["expiring"] is False and r.data["results"][0]["last_used_at"] is None, "row values")
r = call(V.ConsoleCertificateListView, "GET", "", alice, query=f"?engineer={bob.pk}")
must(r.data["results"] == [] and r.data["count"] == 0, "another engineer's rows are an empty page")
must(denies() == [], "reading the list never writes a deny row")
r = call(V.ConsoleCertificateListView, "GET", "", viewer)
must(r.data["count"] == 57 and len(r.data["results"]) == 50, f"a viewer sees everything, 50 a page: {r.data['count']}")
r2 = call(V.ConsoleCertificateListView, "GET", "", viewer, query="?page=2")
must(len(r2.data["results"]) == 7 and not ({x["serial"] for x in r.data["results"]} & {x["serial"] for x in r2.data["results"]}), "page 2 holds the rest")
must(len(call(V.ConsoleCertificateListView, "GET", "", viewer, query="?page_size=500").data["results"]) == 57, "page_size is capped at 100")
must(call(V.ConsoleCertificateListView, "GET", "", viewer, query=f"?engineer={bob.pk}").data["count"] == 1, "the engineer filter")
for bad in ("?page=0", "?page=x", "?state=maybe", "?engineer=-1", "?page_size=0"):
    must(call(V.ConsoleCertificateListView, "GET", "", viewer, query=bad).status_code == 400, f"{bad} is a 400")
M.TecTacConsoleCertificate.objects.filter(serial=f"{3:032x}").update(not_after=now - timedelta(days=1))
M.TecTacConsoleCertificate.objects.filter(serial=f"{4:032x}").update(not_after=now + timedelta(days=10))
M.TecTacConsoleCertificate.objects.filter(serial=f"{5:032x}").update(state="revoked", revoked_at=now, revoked_reason="lost")
by_state = {s: call(V.ConsoleCertificateListView, "GET", "", viewer, query=f"?state={s}&page_size=100").data for s in ("active", "expired", "revoked")}
must(by_state["expired"]["count"] == 1 and by_state["revoked"]["count"] == 1 and by_state["active"]["count"] == 55, f"state filters: {[(k, v['count']) for k, v in by_state.items()]}")
must(by_state["revoked"]["results"][0]["revoked_reason"] == "lost" and by_state["revoked"]["results"][0]["state"] == "revoked", "revoked row")
must(any(x["serial"] == f"{4:032x}" and x["expiring"] is True for x in by_state["active"]["results"]), "expiring from 30 days")
M.TecTacConsoleCertificate.objects.filter(user_id=manager.pk).update(state="revoked", revoked_at=now, revoked_reason="other")

# the enrolments list: open and unexpired only, capped, own only without view
call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": alice.pk})
r = call(V.ConsoleCertificateListView, "GET", "", viewer)
must(len(r.data["enrolments"]) == 1 and r.data["enrolments"][0]["engineer_id"] == alice.pk and r.data["enrolments"][0]["username"] == "alice", "open enrolment listed")
must(set(r.data["enrolments"][0]) == {"id", "engineer_id", "username", "authorised_by", "authorised_by_username", "authorised_at", "expires_at", "state", "code_active"}, "enrolment keys")
must(call(V.ConsoleCertificateListView, "GET", "", bob).data["enrolments"] == [], "another person's enrolment is not shown to a person without view")
must(len(call(V.ConsoleCertificateListView, "GET", "", alice).data["enrolments"]) == 1, "their own is")
M.TecTacConsoleEnrolment.objects.filter(user_id=alice.pk).update(expires_at=now - timedelta(seconds=1))
must(call(V.ConsoleCertificateListView, "GET", "", viewer).data["enrolments"] == [], "an expired enrolment is not listed")

# ---- revoke
h.rows.clear()
r = call(V.ConsoleCertificateRevokeView, "POST", "x", bob, {"reason": "lost"}, url_kwargs={"serial": alice_serial})
must(r.status_code == 403 and len(denies()) == 1 and denies()[0]["object_id"] == alice_serial, "someone else's serial without manage: 403 and a deny row")
r = call(V.ConsoleCertificateRevokeView, "POST", "x", bob, {"reason": "lost"}, url_kwargs={"serial": "f" * 32})
must(r.status_code == 403, "an unknown serial looks the same to a non-manager")
r = call(V.ConsoleCertificateRevokeView, "POST", "x", viewer, {"reason": "lost"}, url_kwargs={"serial": alice_serial})
must(r.status_code == 403, "view is not enough to revoke")
must(M.TecTacConsoleCertificate.objects.get(serial=alice_serial).state == "active", "nothing was revoked")
r = call(V.ConsoleCertificateRevokeView, "POST", "x", alice, {"reason": "lost"}, url_kwargs={"serial": alice_serial})
must(r.status_code == 200 and set(r.data) == {"serial", "state", "revoked_reason", "changed"} and r.data["state"] == "revoked" and r.data["changed"] is True, f"self revoke: {r.data}")
r = call(V.ConsoleCertificateRevokeView, "POST", "x", alice, {"reason": "lost"}, url_kwargs={"serial": alice_serial})
must(r.status_code == 200 and r.data["changed"] is False, "revoking twice answers 200")
must(len(rows_of(h, "custom:console-cert-revoked")) == 1, "revoke twice writes one row")
r = call(V.ConsoleCertificateRevokeView, "POST", "x", manager, {"reason": "left"}, url_kwargs={"serial": bob_serial})
must(r.status_code == 200 and M.TecTacConsoleCertificate.objects.get(serial=bob_serial).revoked_reason == "left", "a manager revokes any")
must(call(V.ConsoleCertificateRevokeView, "POST", "x", manager, {"reason": "left"}, url_kwargs={"serial": "e" * 32}).status_code == 404, "unknown serial: 404 for a manager")
for bad, why in (({"reason": "replaced"}, "an internal reason"), ({"reason": "ca_replaced"}, "ca_replaced"), ({}, "no reason"), ({"reason": "lost", "x": 1}, "an unknown key"), ({"reason": 3}, "a number")):
    must(call(V.ConsoleCertificateRevokeView, "POST", "x", manager, bad, url_kwargs={"serial": bob_serial}).status_code == 400, f"revoke refuses {why}")
for serial in ("ABC", "g" * 32, "A" * 32, "a" * 31, "../" + "a" * 29):
    must(call(V.ConsoleCertificateRevokeView, "POST", "x", manager, {"reason": "lost"}, url_kwargs={"serial": serial}).status_code == 400, f"serial {serial!r} refused")

# ---- the CA status and replace
r = call(V.ConsoleCertificateCaView, "GET", "ca/", viewer)
must(set(r.data) == {"exists", "server_id", "not_before", "not_after", "expires_in_days", "expiring", "active_certificates", "retired_cas", "master_key_available"}, f"ca keys: {sorted(r.data)}")
must(r.data["exists"] and r.data["expiring"] is False and r.data["expires_in_days"] > 3600 and r.data["master_key_available"] is True and r.data["retired_cas"] == 0, "ca values")
h.master_fault = "missing"
must(call(V.ConsoleCertificateCaView, "GET", "ca/", viewer).data["master_key_available"] is False, "master_key_available says false when the key is unusable")
h.master_fault = None
M.TecTacConsoleCA.objects.update(not_after=cc._now() + timedelta(days=200))
must(call(V.ConsoleCertificateCaView, "GET", "ca/", viewer).data["expiring"] is True, "expiring from 365 days")
r = call(V.ConsoleCertificateCaReplaceView, "POST", "ca/replace/", admin, {})
must(r.status_code == 400 and r.data["code"] == "confirmation_required", "replace needs confirm")
must(call(V.ConsoleCertificateCaReplaceView, "POST", "ca/replace/", admin, {"confirm": "yes"}).status_code == 400, "confirm must be true")
must(call(V.ConsoleCertificateCaReplaceView, "POST", "ca/replace/", admin, {"confirm": True, "x": 1}).status_code == 400, "an unknown key")
old_server = cc.active_ca().server_id
r = call(V.ConsoleCertificateCaReplaceView, "POST", "ca/replace/", admin, {"confirm": True})
must(r.status_code == 200 and set(r.data) == {"server_id", "old_server_id", "not_after", "revoked_certificates", "cancelled_enrolments"} and r.data["old_server_id"] == old_server, f"replace shape: {r.data}")
must(call(V.ConsoleCertificateMineView, "GET", "mine/", alice).data["server_id"] == r.data["server_id"], "mine shows the new id")

# ---- strict rows roll the change back
h.reset()
admin = h.new_user("admin", superuser=True)
engineer = h.new_user("rolled")
h.fail_actions.add("custom:console-cert-issue-authorised")
r = call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": engineer.pk})
must(r.status_code == 503 and r.data["code"] == "audit_failed" and not M.TecTacConsoleEnrolment.objects.exists(), "a failed issue row: no enrolment")
h.fail_actions.clear()
serial = issue_cert(admin, engineer, "Rolled PC")
issue_row = call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": engineer.pk})
enrolment_id = M.TecTacConsoleEnrolment.objects.get(user_id=engineer.pk, state="open").id
h.fail_actions.add("custom:console-cert-enrolment-cancelled")
r = call(V.ConsoleCertificateEnrolmentCancelView, "POST", "x", admin, {}, url_kwargs={"enrolment_id": enrolment_id})
must(r.status_code == 503 and M.TecTacConsoleEnrolment.objects.get(pk=enrolment_id).state == "open", "a failed cancel row: still open")
h.fail_actions.clear()
h.fail_actions.add("custom:console-cert-revoked")
r = call(V.ConsoleCertificateRevokeView, "POST", "x", admin, {"reason": "lost"}, url_kwargs={"serial": serial})
must(r.status_code == 503 and M.TecTacConsoleCertificate.objects.get(serial=serial).state == "active", "a failed revoke row: still active")
h.fail_actions.clear()
h.fail_actions.add("custom:console-ca-replaced")
before_server = cc.active_ca().server_id
r = call(V.ConsoleCertificateCaReplaceView, "POST", "ca/replace/", admin, {"confirm": True})
must(r.status_code == 503 and cc.active_ca().server_id == before_server, "a failed replace row: the CA is unchanged")
must(M.TecTacConsoleCA.objects.count() == 1 and M.TecTacConsoleCertificate.objects.get(serial=serial).state == "active" and M.TecTacConsoleEnrolment.objects.filter(state="open").exists(),
     "a failed replace row: nothing revoked, nothing cancelled, no second CA")
h.fail_actions.clear()
h.reset()
admin = h.new_user("admin", superuser=True)
h.fail_actions.add("custom:console-ca-created")
r = call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": h.new_user("x").pk})
must(r.status_code == 503 and not M.TecTacConsoleCA.objects.exists(), "a failed created row: no CA")
h.fail_actions.clear()

# ---- the nine row types, once each, module core with the provenance marker
h.reset()
admin = h.new_user("admin", superuser=True)
engineer, nobody = h.new_user("typed"), h.new_user("nobody")
user, console, code, ok = h.full_flow(admin, engineer, pc_label="Typed PC")
h.enrol("Z" * 43, console)  # an unknown code: one refusal row
call(V.ConsoleCertificateIssueView, "POST", "issue/", nobody, {"user_id": 1})  # a deny row
open_id = call(V.ConsoleCertificateIssueView, "POST", "issue/", admin, {"user_id": nobody.pk}).data["id"]
call(V.ConsoleCertificateEnrolmentCancelView, "POST", "x", admin, {}, url_kwargs={"enrolment_id": open_id})
call(V.ConsoleCertificateRevokeView, "POST", "x", admin, {"reason": "admin"}, url_kwargs={"serial": ok.data["serial"]})
call(V.ConsoleCertificateCaReplaceView, "POST", "ca/replace/", admin, {"confirm": True})
expected = {
    "custom:console-ca-created": ("console_ca", True), "custom:console-ca-replaced": ("console_ca", True),
    "custom:console-cert-issue-authorised": ("console_certificate", True), "custom:console-cert-enrolment-cancelled": ("console_certificate", True),
    "custom:console-cert-issued": ("console_certificate", True), "custom:console-cert-revoked": ("console_certificate", True),
    "custom:console-cert-enrol-code": ("console_certificate", False), "custom:console-cert-enrol-refused": ("console_certificate", False),
    "deny": ("console_certificate", False),
}
for action, (object_type, strict) in expected.items():
    found = rows_of(h, action)
    must(len(found) >= 1, f"{action} was written")
    row = found[0]
    must(row["module_id"] == "core" and row["object_type"] == object_type and row["strict"] is strict, f"{action}: module, type, strictness")
    must(row["operation_context"]["server_provenance"] == "console-certificates", f"{action}: provenance marker")
    must(("core_refusal" in row["operation_context"]) == (action in ("deny", "custom:console-cert-enrol-refused")), f"{action}: the refusal marker only on a refusal")
    must(row["authority"] is h.audit._TACTICAL_OPERATION_AUTHORITY, f"{action}: the Core-internal authority")
for action in ("custom:console-ca-created", "custom:console-cert-issued", "custom:console-ca-replaced"):
    must(len(rows_of(h, action)) == 1, f"{action} exactly once")

# ---- the public writer still refuses the provenance marker, and the private one is not a module's tool
import tec_tac.audit as audit  # noqa: E402

try:
    audit.record(actor=admin, module_id="core", action="custom:x", object_type="console_certificate", operation_context={"server_provenance": "console-certificates"})
    raise AssertionError("the public record() must refuse server_provenance")
except audit.AuditContractError:
    pass
provider = audit.get_audit_provider()
must(not hasattr(provider, "_record_console_certificates") and not hasattr(provider, "record_console_certificates"), "the audit provider does not offer the private writer")
must("_record_console_certificates" not in getattr(audit, "__all__", ()), "the private writer is not exported")

# ---- the permissions are in the catalogue
from tec_tac import rbac  # noqa: E402

catalog = rbac.permission_catalog()[0]
group = next((g for g in catalog["groups"] if g["name"] == "Console certificates"), None)
must(group is not None and group["permissions"] == [VIEW, MANAGE], f"the permission group: {group}")
must(VIEW in catalog["permissions"] and MANAGE in catalog["permissions"], "in permission_catalog()")
must({VIEW, MANAGE} <= set(rbac.registered_permissions()), "in registered_permissions()")
must(rbac.can_view_console_certificates(h.new_user("v1", perms=(VIEW,))) and rbac.can_view_console_certificates(h.new_user("v2", perms=(MANAGE,))), "view or manage can view")
must(not rbac.can_manage_console_certificates(h.new_user("v3", perms=(VIEW,))) and rbac.can_manage_console_certificates(h.new_user("v4", perms=(MANAGE,))), "only manage manages")
must(rbac.can_manage_console_certificates(h.new_user("v5", superuser=True)) and not rbac.can_view_console_certificates(h.new_user("v6")), "a superuser manages, nobody views")
must(not rbac.can_manage_console_certificates(None), "fails closed on no user")

# ---- the URL map: enrol/ is the only unauthenticated route, and every route has a contract row and an OpenAPI group
urls = ast.parse((ROOT / "framwork" / "tec_tac" / "urls.py").read_text(encoding="utf-8"))
patterns = []
for node in ast.walk(urls):
    if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "path" and isinstance(node.args[0], ast.Constant) and str(node.args[0].value).startswith("console-certificates/"):
        patterns.append((node.args[0].value, ast.unparse(node.args[1])))
must(len(patterns) == 9, f"nine routes: {len(patterns)}")
views_tree = ast.parse((ROOT / "framwork" / "tec_tac" / "console_certificate_views.py").read_text(encoding="utf-8"))
classes = {n.name: n for n in views_tree.body if isinstance(n, ast.ClassDef)}
open_routes = []
for route, target in patterns:
    cls = classes[target.split(".")[0]]
    assigns = {t.id: ast.unparse(s.value) for s in cls.body if isinstance(s, ast.Assign) for t in s.targets if isinstance(t, ast.Name)}
    if assigns.get("permission_classes") != "[SessionAuthenticated]" or "authentication_classes" in assigns:
        open_routes.append((route, assigns.get("permission_classes"), assigns.get("authentication_classes")))
must(open_routes == [("console-certificates/enrol/", "[AllowAny]", "[]")], f"enrol/ is the only unauthenticated pattern: {open_routes}")
contracts_tree = ast.parse((ROOT / "framwork" / "tec_tac" / "contracts.py").read_bytes().decode("utf-8"))
details = next(n.value for n in contracts_tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in n.targets))
documented = {k.value for k in details.keys if isinstance(k, ast.Constant)}
for route, _target in patterns:
    must("/api/tfd/" + route in documented, f"{route} has an HTTP_CONTRACT_DETAILS row")
    row = details.values[[k.value if isinstance(k, ast.Constant) else None for k in details.keys].index("/api/tfd/" + route)]
    text = ast.unparse(row)
    must("1.18.52" in text and "'authorization'" in text, f"{route}: the row says added 1.18.52 and names its authorisation")
from tec_tac import openapi  # noqa: E402

must(openapi.CORE_CALLBACK_GROUPS["tec_tac.console_certificate_views"] == "Tec-Tac · Console Certificates", "OpenAPI callback group")
must(("/api/tfd/console-certificates/", "Tec-Tac · Console Certificates") in openapi.CORE_PATH_GROUPS, "OpenAPI path group")
must(re.search(r"Console certificates \(Core 1\.18\.52", (ROOT / "framwork" / "tec_tac" / "contracts.py").read_bytes().decode("utf-8")) is not None, "the RULES sentence is present")

print("console certificates routes 1.18.52 regression: PASS")

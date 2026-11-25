#!/usr/bin/env python3
"""Regression: Core 1.18.53 (held Medium of the 1.18.52 review). The three routes that start a Console enrolment need an interactive signed-in session.

Real Django on a temporary SQLite file (tests/console_certificates_harness.py). An API-key request (a string token, Tactical's APIAuthentication, an
X-API-KEY header) and a plain Django session (no Knox digest) to mine/enrolment-code/, issue/ and ca/replace/ get 403 interactive_session_required, one
non-strict deny row (reason api_key_refused, no key and no header in it), no stored code hash, no enrolment and no CA change. The same person with a Knox
token gets 200 or 201. The refusal comes first: before the body and before the permission. Revoke and the read routes are not changed.
"""
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("cc_harness", Path(__file__).with_name("console_certificates_harness.py"))
harness = importlib.util.module_from_spec(spec)
sys.modules["cc_harness"] = harness
spec.loader.exec_module(harness)
must, rows_of = harness.must, harness.rows_of
h = harness.boot()
if h is None:
    print("console certificates api key 1.18.53 regression: SKIPPED (Django is not installed on this PC)")
    sys.exit(0)

cc, M, V = h.cc, h.models, h.views
BASE = "/api/tfd/console-certificates/"
KEY_TEXT = "api-key-for-tests"

# ---- interactive_session: the pure rule
Knox = SimpleNamespace(digest="d")


class APIAuthentication:  # the class name is what Core looks at (Tactical's own lives in tacticalrmm.auth)
    pass


class Other:
    pass


Other.__module__ = "tacticalrmm.auth"


def fake(auth=Knox, authenticator=None, meta=None):
    return SimpleNamespace(auth=auth, successful_authenticator=authenticator, META=meta or {})


must(cc.interactive_session(fake()) is True, "a Knox token with a digest")
must(cc.interactive_session(fake(authenticator=SimpleNamespace())) is True, "another authenticator class")
must(cc.interactive_session(fake(auth=None)) is False, "no auth object")
must(cc.interactive_session(fake(auth=KEY_TEXT)) is False and cc.interactive_session(fake(auth=KEY_TEXT.encode())) is False, "a plain string")
must(cc.interactive_session(fake(auth=SimpleNamespace(digest=""))) is False and cc.interactive_session(fake(auth=SimpleNamespace())) is False, "no digest")
must(cc.interactive_session(fake(authenticator=APIAuthentication())) is False, "Tactical's APIAuthentication by class name")
must(cc.interactive_session(fake(authenticator=Other())) is False, "an authenticator from tacticalrmm.auth")
must(cc.interactive_session(fake(meta={"HTTP_X_API_KEY": "x"})) is False and cc.interactive_session(fake(meta={"HTTP_X_API_KEY": ""})) is False, "an X-API-KEY header, even empty")
must(cc.interactive_session(SimpleNamespace()) is False, "a request with nothing on it")

# ---- the routes
h.reset()
admin = h.new_user("admin", superuser=True)
engineer = h.new_user("engineer")
viewer = h.new_user("viewer")


def deny_rows():
    return [r for r in rows_of(h, "deny")]


def refused(response, object_type):
    must(response.status_code == 403 and response.data["code"] == "interactive_session_required", (response.status_code, response.data))
    must(response["Cache-Control"] == "no-store", "no-store")
    rows = deny_rows()
    must(len(rows) == 1, rows)
    row = rows[0]
    must(row["module_id"] == "core" and row["object_type"] == object_type and row["metadata"] == {"reason": "api_key_refused"} and row["strict"] is False
         and row["object_id"] is None and row["operation_context"] == {"server_provenance": "console-certificates", "core_refusal": True}, row)
    must(KEY_TEXT not in json.dumps(h.rows, default=str) and "x-api-key" not in json.dumps(h.rows, default=str).lower(), "no key and no header in the row")
    h.rows.clear()


# the enrolment code
issued = h.call(V.ConsoleCertificateIssueView, "POST", BASE + "issue/", admin, {"user_id": engineer.pk})
must(issued.status_code == 201, issued.data)
h.rows.clear()
open_row = M.TecTacConsoleEnrolment.objects.get(user_id=engineer.pk)
must(open_row.code_hash == "", "no code yet")
for mode, extra in (("api", {}), ("session", {}), (KEY_TEXT, {}), ("knox", {"HTTP_X_API_KEY": KEY_TEXT})):
    response = h.call(V.ConsoleCertificateEnrolmentCodeView, "POST", BASE + "mine/enrolment-code/", engineer, {}, auth=mode, **extra)
    refused(response, "console_certificate")
    must(M.TecTacConsoleEnrolment.objects.get(pk=open_row.pk).code_hash == "", f"{mode}: no code_hash stored")
# the refusal is first: a bad body from an API key is still the same 403
refused(h.call(V.ConsoleCertificateEnrolmentCodeView, "POST", BASE + "mine/enrolment-code/", engineer, {"junk": 1}, auth="api"), "console_certificate")
h.cache.clear()  # the refused requests count against the 5 a minute of the route, as any request does
good = h.call(V.ConsoleCertificateEnrolmentCodeView, "POST", BASE + "mine/enrolment-code/", engineer, {})
must(good.status_code == 200 and len(good.data["code"]) == 43, (good.status_code, good.data))
must(M.TecTacConsoleEnrolment.objects.get(pk=open_row.pk).code_hash == cc.code_hash(good.data["code"]), "a Knox session stores the hash")
must(len(rows_of(h, "custom:console-cert-enrol-code")) == 1 and not deny_rows(), "one code row, no deny")
h.rows.clear()
codes_before = M.TecTacConsoleEnrolment.objects.get(pk=open_row.pk).code_hash
refused(h.call(V.ConsoleCertificateEnrolmentCodeView, "POST", BASE + "mine/enrolment-code/", engineer, {}, auth="api"), "console_certificate")
must(M.TecTacConsoleEnrolment.objects.get(pk=open_row.pk).code_hash == codes_before, "an API key does not replace the person's live code either")

# issue
enrolments_before = M.TecTacConsoleEnrolment.objects.count()
for mode in ("api", "session"):
    refused(h.call(V.ConsoleCertificateIssueView, "POST", BASE + "issue/", admin, {"user_id": viewer.pk}, auth=mode), "console_certificate")
refused(h.call(V.ConsoleCertificateIssueView, "POST", BASE + "issue/", viewer, {"user_id": viewer.pk}, auth="api"), "console_certificate")  # before the permission
refused(h.call(V.ConsoleCertificateIssueView, "POST", BASE + "issue/", admin, {"user_id": "x"}, auth="api"), "console_certificate")  # and before the body
must(M.TecTacConsoleEnrolment.objects.count() == enrolments_before, "no enrolment was created")
ok = h.call(V.ConsoleCertificateIssueView, "POST", BASE + "issue/", admin, {"user_id": viewer.pk})
must(ok.status_code == 201, ok.data)
must(M.TecTacConsoleEnrolment.objects.count() == enrolments_before + 1, "a Knox session creates one")
h.rows.clear()
# a person who is not allowed, with a Knox session, still gets the permission refusal (a different row)
denied = h.call(V.ConsoleCertificateIssueView, "POST", BASE + "issue/", viewer, {"user_id": engineer.pk})
must(denied.status_code == 403 and deny_rows()[0]["metadata"] == {"reason": "permission_required"}, "the permission refusal is unchanged")
h.rows.clear()

# ca/replace: needs a CA, then the key must not change anything
ca_before = M.TecTacConsoleCA.objects.get(state="active").server_id
user, console, code, response = h.full_flow(admin, engineer, pc_label="Work PC")
must(response.status_code == 201, response.data)
h.rows.clear()
for mode in ("api", "session"):
    refused(h.call(V.ConsoleCertificateCaReplaceView, "POST", BASE + "ca/replace/", admin, {"confirm": True}, auth=mode), "console_ca")
refused(h.call(V.ConsoleCertificateCaReplaceView, "POST", BASE + "ca/replace/", viewer, {"confirm": True}, auth="api"), "console_ca")
must(M.TecTacConsoleCA.objects.get(state="active").server_id == ca_before and M.TecTacConsoleCA.objects.count() == 1, "no CA change")
must(M.TecTacConsoleCertificate.objects.filter(state="active").count() == 1 and not h.tunnel_calls, "no certificate revoked, no session ended")
replaced = h.call(V.ConsoleCertificateCaReplaceView, "POST", BASE + "ca/replace/", admin, {"confirm": True})
must(replaced.status_code == 200 and replaced.data["old_server_id"] == ca_before, replaced.data)

# revoke and the read routes are not changed: a key may still revoke (the safe direction) and read
h.reset()
admin = h.new_user("admin", superuser=True)
user, console, code, response = h.full_flow(admin, None, pc_label="Work PC")
serial = response.data["serial"]
h.rows.clear()
read = h.call(V.ConsoleCertificateMineView, "GET", BASE + "mine/", user, auth="api")
must(read.status_code == 200, "mine/ is open to a key")
listing = h.call(V.ConsoleCertificateListView, "GET", BASE, admin, auth="api")
must(listing.status_code == 200, "the list is open to a key")
revoked = h.call(V.ConsoleCertificateRevokeView, "POST", BASE + f"{serial}/revoke/", admin, {"reason": "lost"}, url_kwargs={"serial": serial}, auth="api")
must(revoked.status_code == 200 and revoked.data["state"] == "revoked", "revoke by key stays allowed")
must(not deny_rows(), "no deny row for them")

print("console certificates api key 1.18.53 regression: PASS")

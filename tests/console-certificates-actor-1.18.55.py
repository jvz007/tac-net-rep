#!/usr/bin/env python3
"""Regression: Core 1.18.55. The audit actor of the Console enrolment rows is the engineer, and the connect-refusal rows have their own limiter key.

Real Django on a temporary SQLite file and the real console_certificates.py (tests/console_certificates_harness.py). The audit row writer is
stubbed, so each row's actor object is captured as the module passed it.
"""
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("cc_harness", Path(__file__).with_name("console_certificates_harness.py"))
harness = importlib.util.module_from_spec(spec)
sys.modules["cc_harness"] = harness
spec.loader.exec_module(harness)
must, rows_of, captured_text = harness.must, harness.rows_of, harness.captured_text
h = harness.boot()
if h is None:
    print("console certificates actor 1.18.55 regression: SKIPPED (Django is not installed on this PC)")
    sys.exit(0)

cc, M = h.cc, h.models
HOST, IP, Console = harness.HOST, harness.IP, h.Console
h.reset()
ADMIN = h.new_user("admin", superuser=True)


def fresh(name=None, **flags):
    user = h.new_user(name)
    cc.authorise(ADMIN, user.pk)
    code = cc.create_enrolment_code(user, HOST)["code"]
    if flags:
        h.user_flags[user.pk] = flags
    return user, code


def is_service(actor):
    return getattr(actor, "identity", None) == "core.console-certificates"


def refused():
    return rows_of(h, "custom:console-cert-enrol-refused")


# ---- (a) a good enrolment: the issue row is under the engineer
user, code = fresh("engineer.a")
h.rows.clear()
r = h.enrol(code, Console())
must(r.status_code == 201, f"{r.status_code} {r.data}")
issued = rows_of(h, "custom:console-cert-issued")
must(len(issued) == 1, "one issued row")
row = issued[0]
must(row["actor"].pk == user.pk and row["actor"].username == "engineer.a", "the engineer is the audit actor")
must(row["metadata"]["via"] == "enrolment_code" and row["metadata"]["ip"] == IP and row["metadata"]["username"] == "engineer.a", row["metadata"])
must(not any(is_service(x.get("actor")) for x in h.rows), "no row of a good enrolment sits under the service actor")
serial_one = row["object_id"]

# ---- (b) the same PC label again: the replaced row is under the engineer too
cc.authorise(ADMIN, user.pk)
code2 = cc.create_enrolment_code(user, HOST)["code"]
h.rows.clear()
r = h.enrol(code2, Console())
must(r.status_code == 201, f"{r.status_code} {r.data}")
revoked = rows_of(h, "custom:console-cert-revoked")
must(len(revoked) == 1, "one replaced row")
rev = revoked[0]
must(rev["actor"].pk == user.pk and rev["metadata"]["reason"] == "replaced" and rev["metadata"]["via"] == "enrolment_code", rev["metadata"])
must(rev["metadata"]["replaced_by_serial"] == rows_of(h, "custom:console-cert-issued")[0]["object_id"] and rev["metadata"]["ip"] == IP, "replaced_by_serial and ip")
must(rev["object_id"] == serial_one, "the old certificate was revoked")

# ---- (f) one certificate's rows are found by its serial (the object id) and by the action names
first_rows = [x["action"] for x in rows_of(h, "custom:console-cert-revoked") if x["object_id"] == serial_one]
must(first_rows == ["custom:console-cert-revoked"], first_rows)
must(rows_of(h, "custom:console-cert-issued") and rows_of(h, "custom:console-cert-revoked"), "searchable by action name")


# ---- (c) code matched, then each refusal: under the engineer, with the enrolment id as the object id
def one_refusal(name, who, call, expected_reason):
    h.rows.clear()
    h.cache.clear()
    r = call()
    must(r.status_code >= 400 and r.data["code"] == expected_reason, f"{name}: {r.status_code} {r.data}")
    rows = refused()
    must(len(rows) == 1, f"{name}: one row ({len(rows)})")
    row = rows[0]
    enrolment = M.TecTacConsoleEnrolment.objects.filter(user_id=who.pk).order_by("-authorised_at").first()
    must(row["actor"].pk == who.pk, f"{name}: under the engineer")
    must(row["object_id"] == str(enrolment.id), f"{name}: the enrolment id is the object id")
    must(row["metadata"] == {"reason": expected_reason, "ip": IP, "via": "enrolment_code", "engineer_id": who.pk, "username": who.username},
         f"{name}: {row['metadata']}")


u, c = fresh("engineer.proof")
con = Console()
one_refusal("proof_invalid", u, lambda: h.enrol(c, con, body=con.body(c, HOST, "Work PC", proof=con.proof("other.example.com", c))), "proof_invalid")
u, c = fresh("engineer.key")
con = Console()
one_refusal("key_invalid", u, lambda: h.enrol(c, con, body=con.body(c, HOST, "Work PC", public_key="not base64!")), "key_invalid")
u, c = fresh("engineer.host")
con = Console()
one_refusal("host_unusable", u, lambda: h.enrol(c, con, host="tec.example.com:8443", body=con.body(c, "tec.example.com:8443")), "host_unusable")
busy = h.new_user("engineer.busy")
for label in ("A", "B", "C"):
    cc.authorise(ADMIN, busy.pk)
    must(h.enrol(cc.create_enrolment_code(busy, HOST)["code"], Console(), pc_label=label).status_code == 201, label)
cc.authorise(ADMIN, busy.pk)
bc = cc.create_enrolment_code(busy, HOST)["code"]
one_refusal("certificate_limit", busy, lambda: h.enrol(bc, Console(), pc_label="D"), "certificate_limit")
u, c = fresh("engineer.inactive")
h.User.objects.filter(pk=u.pk).update(is_active=False)
one_refusal("account_inactive", u, lambda: h.enrol(c, Console()), "account_inactive")

# ---- (d) no person known: unknown code, burnt code, malformed header stay under the service actor, no engineer in the metadata
u, c = fresh("engineer.burnt")
con = Console()
h.cache.clear()
h.enrol(c, con, body=con.body(c, HOST, "Work PC", public_key="not base64!"))  # burns the code
for name, call in (
    ("unknown code", lambda: h.enrol("A" * 43, Console())),
    ("burnt code", lambda: h.enrol(c, con)),
    ("malformed header", lambda: h.enrol(c, con, headers={"HTTP_AUTHORIZATION": "Bearer " + c})),
):
    h.rows.clear()
    h.cache.clear()
    r = call()
    must(r.status_code == 401, f"{name}: {r.status_code}")
    rows = refused()
    must(len(rows) == 1 and is_service(rows[0]["actor"]), f"{name}: service actor")
    must("engineer_id" not in rows[0]["metadata"] and "via" not in rows[0]["metadata"] and rows[0]["object_id"] is None, f"{name}: no engineer")

# ---- (e) a blank username falls back to the service actor and the enrol still succeeds
blank = h.new_user("placeholder")
h.User.objects.filter(pk=blank.pk).update(username="")
blank = h.User.objects.get(pk=blank.pk)
h.perms[blank.pk] = ()
must(is_service(cc.engineer_actor(blank)), "a blank username falls back")
must(is_service(cc.engineer_actor(None)), "no person falls back")
anonymous = type("A", (), {"is_authenticated": False, "username": "x"})()
must(is_service(cc.engineer_actor(anonymous)), "an unauthenticated object falls back")
must(cc.engineer_actor(user) is user, "a real person is the actor")
cc.authorise(ADMIN, blank.pk)
bcode = cc.create_enrolment_code(blank, HOST)["code"]
h.rows.clear()
h.cache.clear()
r = h.enrol(bcode, Console())
must(r.status_code == 201, f"{r.status_code} {r.data}")
issued = rows_of(h, "custom:console-cert-issued")
must(len(issued) == 1 and is_service(issued[0]["actor"]), "issued under the service actor, no AuditContractError")
# the real provenance function accepts the engineer actor for module core
from tec_tac import audit

name, details = audit._actor_provenance(user, {"id": "core"}, audit._TACTICAL_OPERATION_AUTHORITY)
must(name == user.username and details["actor_kind"] == "human", "the real audit contract takes the engineer as a human actor")

# ---- (g) no code, key, proof or header in any row or log
h.rows.clear()
h.logs.clear()
h.cache.clear()
u, c = fresh("engineer.secret")
con = Console()
body = con.body(c, HOST, "Work PC", proof=con.proof("other.example.com", c))
h.enrol(c, con, body=body)
text = captured_text(h)
for secret in (c, con.public_key, body["proof"], "Enrol "):
    must(secret not in text, f"a secret reached a row or a log: {secret[:12]}")
h.cache.clear()
u, c = fresh("engineer.ok")
con = Console()
h.rows.clear()
h.logs.clear()
h.enrol(c, con)
text = captured_text(h)
for secret in (c, con.public_key, "Enrol "):
    must(secret not in text, "a secret reached a row after a good enrolment")

# ---- the limiter: one row per address and per kind per minute
h.reset()
minute = [1000]
real_minute = cc._minute
cc._minute = lambda: minute[0]
try:
    h.rows.clear()
    must(cc._refusal_row_due(IP) is True, "an enrol refusal row is due")
    must(cc._refusal_row_due(IP) is False, "a second enrol one in the minute is not")
    must(cc.record_refusal("proof_invalid", IP) is True, "a connect refusal in the same minute still writes")
    must(cc.record_refusal("proof_stale", IP) is False, "a second connect one does not")
    must(h.cache.get(f"{cc.REFUSAL_ROW_PREFIX}{cc._address_key(IP)}:{minute[0]}") is not None, "the enrol key text equals the 1.18.54 key")
    must(h.cache.get(f"{cc.REFUSAL_ROW_PREFIX}connect:{cc._address_key(IP)}:{minute[0]}") is not None, "the connect key has its own text")
    minute[0] += 1
    must(cc._refusal_row_due(IP) is True and cc.record_refusal("proof_invalid", IP) is True, "a new minute writes again for both")
    # end to end: a refused enrolment and a refused connect in one minute each write their row
    h.cache.clear()
    h.rows.clear()
    h.enrol("A" * 43, Console())
    cc.record_refusal("proof_invalid", IP)
    must(len(refused()) == 1 and len(rows_of(h, "custom:console-cert-refused")) == 1, "one of each kind")

    class Broken:
        def add(self, *a, **k):
            raise RuntimeError("cache down")

    real_cache = cc._cache
    cc._cache = lambda: Broken()
    try:
        h.rows.clear()
        must(cc._refusal_row_due(IP) is False and cc.record_refusal("proof_invalid", IP) is False, "a cache fault writes no row for either kind")
        h.enrol("A" * 43, Console())
        must(not refused() and not rows_of(h, "custom:console-cert-refused"), "no rows")
    finally:
        cc._cache = real_cache
finally:
    cc._minute = real_minute

print("console certificates actor 1.18.55 regression: PASS")

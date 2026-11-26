#!/usr/bin/env python3
"""Regression: Core 1.18.52 (C3). The enrol route: the one-time code, the proof of the key, the bundle and every refusal.

Real Django on a temporary SQLite file, the real console_certificates.py and console_certificate_views.py, and a real P-256 key standing in for
the Console (cryptography). The enrol view is called the way nginx would: no session, the code in the Authorization header.
"""
import base64
import hashlib
import importlib.util
import json
import sys
import threading
from pathlib import Path

spec = importlib.util.spec_from_file_location("cc_harness", Path(__file__).with_name("console_certificates_harness.py"))
harness = importlib.util.module_from_spec(spec)
sys.modules["cc_harness"] = harness
spec.loader.exec_module(harness)
must, rows_of, captured_text, b64u = harness.must, harness.rows_of, harness.captured_text, harness.b64u
h = harness.boot()
if h is None:
    print("console certificates enrol 1.18.52 regression: SKIPPED (Django is not installed on this PC)")
    sys.exit(0)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

cc, M = h.cc, h.models
HOST, IP, Console = harness.HOST, harness.IP, h.Console
h.reset()
ADMIN = h.new_user("admin", superuser=True)


def fresh(**flags):
    """A new engineer with an open enrolment and a live code. Returns (user, code)."""
    user = h.new_user()
    cc.authorise(ADMIN, user.pk)
    code = cc.create_enrolment_code(user, HOST)["code"]
    if flags:  # the account changes after the administrator allowed it
        h.user_flags[user.pk] = flags
    return user, code


def refused_row_count():
    return len(rows_of(h, "custom:console-cert-enrol-refused"))


def enrolment_of(user):
    return M.TecTacConsoleEnrolment.objects.filter(user_id=user.pk).order_by("-authorised_at").first()


SAME_401 = {"detail": "The enrolment code is not valid.", "code": "code_invalid"}

# ---- the happy path and the bundle
user, code = fresh()
console = Console()
response = h.enrol(code, console)
must(response.status_code == 201, f"{response.status_code} {response.data}")
must(response["Cache-Control"] == "no-store", "the bundle is no-store")
bundle = response.data
must(set(bundle) == {"v", "host", "server_id", "ca_public_key", "ca_cert", "cert", "serial", "not_after", "engineer", "ui_url"}, f"bundle keys: {sorted(bundle)}")  # ui_url: 1.18.58, additive
must(bundle["ui_url"] is None or str(bundle["ui_url"]).startswith("https://"), "ui_url is an https address or None")
must(bundle["v"] == 1 and bundle["host"] == HOST and bundle["engineer"] == {"id": user.pk, "username": user.username}, "bundle values")


def der(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


leaf, ca_cert = x509.load_der_x509_certificate(der(bundle["cert"])), x509.load_der_x509_certificate(der(bundle["ca_cert"]))
must(leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == console.spki, "the certificate has the submitted key")
ca_cert.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
must(bundle["ca_public_key"] == b64u(ca_cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)), "ca_public_key is the CA SPKI")
must(hashlib.sha256(der(bundle["ca_public_key"])).digest()[:16].hex() == bundle["server_id"], "server_id matches the CA key")
san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
must(san == [f"tectac:server:{bundle['server_id']}", f"tectac:engineer:{user.pk}"], "SAN values")
must(len(bundle["serial"]) == 32 and f"{leaf.serial_number:032x}" == bundle["serial"], "serial shape")
must(leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == user.username, "CN is the username")
must(enrolment_of(user).state == "used" and enrolment_of(user).used_serial == bundle["serial"], "the enrolment is used")
issued = rows_of(h, "custom:console-cert-issued")
must(len(issued) == 1 and issued[0]["strict"] is True and issued[0]["module_id"] == "core", "one strict issued row")
must(issued[0]["actor"].pk == user.pk and issued[0]["metadata"]["engineer_id"] == user.pk and issued[0]["metadata"]["via"] == "enrolment_code", "1.18.55: the engineer is the actor, the engineer in the metadata")
must(issued[0]["operation_context"] == {"server_provenance": "console-certificates"}, "provenance marker")
must(refused_row_count() == 0, "no refusal row on success")

# ---- the code works once
again = h.enrol(code, Console())
must(again.status_code == 401 and dict(again.data) == SAME_401, "a used code gets the one 401 body")
user, code = fresh()
a, b = Console(), Console()
barrier = threading.Barrier(2)
statuses = []


def racer(console):
    try:
        barrier.wait(10)
        statuses.append(h.enrol(code, console).status_code)
    except Exception as exc:  # noqa: BLE001
        statuses.append(repr(exc))
    finally:
        h.connection.close()


threads = [threading.Thread(target=racer, args=(c,)) for c in (a, b)]
for t in threads:
    t.start()
for t in threads:
    t.join(60)
must(sorted(map(str, statuses)) == ["201", "401"], f"exactly one of two racing enrolments wins: {statuses}")
must(M.TecTacConsoleCertificate.objects.filter(user_id=user.pk).count() == 1, "one certificate")

# ---- pre-code failures all answer the same body
user, code = fresh()
M.TecTacConsoleEnrolment.objects.filter(user_id=user.pk).update(code_expires_at=cc._now() - cc.timedelta(seconds=1))
expired_code = h.enrol(code, Console())
user2, code2 = fresh()
M.TecTacConsoleEnrolment.objects.filter(user_id=user2.pk).update(expires_at=cc._now() - cc.timedelta(seconds=1))
expired_enrolment = h.enrol(code2, Console())
user3, code3 = fresh()
cc.cancel_enrolment(ADMIN, enrolment_of(user3).id)
cancelled = h.enrol(code3, Console())
unknown = h.enrol("A" * 43, Console())
for name, r in (("expired code", expired_code), ("expired enrolment", expired_enrolment), ("cancelled enrolment", cancelled), ("unknown code", unknown)):
    must(r.status_code == 401 and dict(r.data) == SAME_401, f"{name}: the same 401 body ({r.status_code} {r.data})")
    must(r["Cache-Control"] == "no-store", f"{name}: no-store")

# ---- a refusal after the code was taken: the code is burnt, the enrolment stays open, one row
h.rows.clear()
h.cache.clear()  # the earlier refusals used this address's one row for the minute
user, code = fresh()
console = Console()
bad = h.enrol(code, console, body=console.body(code, HOST, "Work PC", proof=console.proof("other.example.com", code)))
must(bad.status_code == 400 and bad.data["code"] == "proof_invalid", f"a proof for another host: {bad.status_code} {bad.data}")
must(enrolment_of(user).state == "open" and enrolment_of(user).code_hash == "", "the enrolment is still open and the code is gone")
retry = h.enrol(code, console)
must(retry.status_code == 401, "the burnt code does not work again")
must(refused_row_count() == 1, f"exactly one refusal row for the address in a minute: {refused_row_count()}")
must(rows_of(h, "custom:console-cert-enrol-refused")[0]["metadata"] == {"reason": "proof_invalid", "ip": IP, "via": "enrolment_code", "engineer_id": user.pk, "username": user.username}, "the row holds reason, address, via and the engineer")
new_code = cc.create_enrolment_code(user, HOST)["code"]
ok = h.enrol(new_code, console)
must(ok.status_code == 201, f"a new code on the same open enrolment works: {ok.status_code} {ok.data}")

# ---- proof, key and shape refusals
other_key = ec.generate_private_key(ec.SECP256R1())
p384 = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
console = Console()
off_curve = bytearray(console.spki)
off_curve[-1] ^= 0x55
compressed_point = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
compressed_spki = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200") + compressed_point
cases = [
    ("a proof signed by another key", lambda c, code: c.body(code, proof=c.proof(HOST, code, key=other_key)), 400, "proof_invalid"),
    ("a proof for another key hash", lambda c, code: c.body(code, proof=c.proof(HOST, code, spki_hash="0" * 64)), 400, "proof_invalid"),
    ("a proof of the wrong length", lambda c, code: c.body(code, proof=b64u(b"\x01" * 63)), 400, "proof_invalid"),
    ("a key that is not a point on the curve", lambda c, code: c.body(code, public_key=b64u(bytes(off_curve))), 400, "key_invalid"),
    ("a key on another curve", lambda c, code: c.body(code, public_key=b64u(p384)), 400, "key_invalid"),
    ("a key with trailing data", lambda c, code: c.body(code, public_key=b64u(c.spki + b"\x00")), 400, "key_invalid"),
    ("a compressed point", lambda c, code: c.body(code, public_key=b64u(compressed_spki)), 400, "key_invalid"),
    ("a key that is not base64url", lambda c, code: c.body(code, public_key="not base64!"), 400, "key_invalid"),
    ("a padded base64 key", lambda c, code: c.body(code, public_key=base64.urlsafe_b64encode(c.spki).decode()), 400, "key_invalid"),
]
for name, make, status, reason in cases:
    user, code = fresh()
    r = h.enrol(code, console, body=make(console, code))
    must(r.status_code == status and r.data["code"] == reason, f"{name}: {r.status_code} {r.data}")
    must(enrolment_of(user).state == "open" and enrolment_of(user).code_hash == "", f"{name}: code burnt, enrolment open")
    must(not M.TecTacConsoleCertificate.objects.filter(user_id=user.pk).exists(), f"{name}: no certificate")
    h.cache.clear()  # these refusals share one address: keep the limiter out of this loop

shape_cases = [
    ("wrong v", lambda c, code: c.body(code, v=2)),
    ("v as true", lambda c, code: c.body(code, v=True)),
    ("an unknown key", lambda c, code: {**c.body(code), "extra": 1}),
    ("a missing key", lambda c, code: {k: v for k, v in c.body(code).items() if k != "proof"}),
    ("a label of 65 characters", lambda c, code: c.body(code, pc_label="x" * 65)),
    ("an empty label", lambda c, code: c.body(code, pc_label="   ")),
    ("a label with a control character", lambda c, code: c.body(code, pc_label="PC\x00one")),
    ("a label with a zero-width character", lambda c, code: c.body(code, pc_label="PC​one")),
    ("a list body", lambda c, code: [1, 2]),
]
for name, make in shape_cases:
    user, code = fresh()
    r = h.enrol(code, console, body=make(console, code))
    must(r.status_code == 400 and r.data["code"] == "invalid_request", f"{name}: {r.status_code} {r.data}")
    h.cache.clear()
user, code = fresh()
r = h.enrol(code, console, raw=b"{not json")
must(r.status_code == 400, "a body that is not JSON")
user, code = fresh()
big = json.dumps({**console.body(code), "pad": "x" * 5000}).encode()
r = h.enrol(code, console, raw=big, headers={"CONTENT_LENGTH": str(len(big))})
must(r.status_code == 413 and r.data["code"] == "body_too_large", f"an oversize body: {r.status_code}")
r2 = h.enrol(code, console, raw=big, headers={"CONTENT_LENGTH": "10"})
must(r2.status_code in (400, 413), "a body longer than it says is still cut at 4 KiB")
h.cache.clear()

# the label is trimmed and NFC normalised
user, code = fresh()
r = h.enrol(code, console, body=console.body(code, pc_label="  Café  "))
must(r.status_code == 201 and M.TecTacConsoleCertificate.objects.get(serial=r.data["serial"]).pc_label == "Café", "the label is trimmed and NFC")

# ---- header shapes: all the same 401
user, code = fresh()
for name, value in (("short code", "Enrol " + code[:42]), ("long code", "Enrol " + code + "A"), ("wrong scheme", "Bearer " + code), ("two values", f"Enrol {code}, Enrol {code}"),
                    ("lower scheme", "enrol " + code), ("bad character", "Enrol " + code[:42] + "+"), ("no code", "Enrol ")):
    r = h.enrol(code, console, headers={"HTTP_AUTHORIZATION": value})
    must(r.status_code == 401 and dict(r.data) == SAME_401, f"{name}: {r.status_code} {r.data}")
r = h.enrol(code, console, headers={"HTTP_AUTHORIZATION": ""})
must(r.status_code == 401, "no header")
h.cache.clear()
good = h.enrol(code, console)
must(good.status_code == 201, "none of those header refusals burnt the live code")

# ---- the 4th certificate, inactive, blocked and installer accounts
engineer = h.new_user("busy")
for label in ("A", "B", "C"):
    cc.authorise(ADMIN, engineer.pk)
    r = h.enrol(cc.create_enrolment_code(engineer, HOST)["code"], Console(), pc_label=label)
    must(r.status_code == 201, f"certificate {label}")
cc.authorise(ADMIN, engineer.pk)
code = cc.create_enrolment_code(engineer, HOST)["code"]
r = h.enrol(code, Console(), pc_label="D")
must(r.status_code == 409 and r.data["code"] == "certificate_limit", f"the 4th: {r.status_code} {r.data}")
must(enrolment_of(engineer).state == "open" and enrolment_of(engineer).code_hash == "", "the 4th: code burnt, enrolment open")
h.cache.clear()
for name, flags, active in (("inactive", {}, False), ("blocked", {"block_dashboard_login": True}, True), ("installer", {"is_installer_user": True}, True)):
    user, code = fresh(**flags)
    if not active:
        h.User.objects.filter(pk=user.pk).update(is_active=False)
    r = h.enrol(code, Console())
    must(r.status_code == 403 and r.data["code"] == "account_inactive", f"{name}: {r.status_code} {r.data}")
    must(enrolment_of(user).state == "open" and enrolment_of(user).code_hash == "", f"{name}: code burnt, enrolment open")
    h.cache.clear()

# ---- the host: the proof is over Core's own host
user, code = fresh()
r = h.enrol(code, console, host="tec.example.com:8443", body=console.body(code, "tec.example.com:8443"))
must(r.status_code == 400 and r.data["code"] == "host_unusable", f"another port: {r.status_code} {r.data}")
h.cache.clear()
user, code = fresh()
r = h.enrol(code, console, host="TEC.Example.com:443", body=console.body(code, HOST))
must(r.status_code == 201 and r.data["host"] == HOST, f"upper case and :443 are normalised: {r.status_code} {r.data}")
h.cache.clear()

# ---- plain http and the failure limit
user, code = fresh()
r = h.enrol(code, console, headers={"HTTP_X_FORWARDED_PROTO": "http"})
must(r.status_code == 403, "plain http is refused")
must(enrolment_of(user).code_hash != "", "a plain-http refusal does not touch the code")
h.cache.clear()
for i in range(10):
    r = h.enrol("B" * 43, Console(), ip="198.51.100.9")
    must(r.status_code == 401, f"failure {i + 1} is a 401")
r = h.enrol("B" * 43, Console(), ip="198.51.100.9")
must(r.status_code == 429 and r["Retry-After"] == "60", f"the 11th failure: {r.status_code}")
must(h.enrol("B" * 43, Console(), ip="198.51.100.10").status_code == 401, "another address is not limited")
user, code = fresh()
must(h.enrol(code, console, ip="198.51.100.9").status_code == 429, "a good code from a limited address is refused too")
h.cache.clear()
for i in range(10):
    h.enrol("C" * 43, Console(), ip=f"2001:db8:1:2::{i + 1:x}")
r = h.enrol("C" * 43, Console(), ip="2001:db8:1:2:ffff::1")
must(r.status_code == 429, f"an IPv6 /64 counts as one address: {r.status_code}")
must(h.enrol("C" * 43, Console(), ip="2001:db8:1:3::1").status_code == 401, "another /64 is not limited")
h.cache.clear()

# ---- a cache fault reads as not limited
real_get = cc._cache
cc._cache = lambda: (_ for _ in ()).throw(ConnectionError("cache down"))
try:
    must(cc.rate_limited("198.51.100.9") is False, "a cache fault reads as not limited")
    cc.note_failure("198.51.100.9")  # does not raise
finally:
    cc._cache = real_get

# ---- a failed strict audit row rolls back the certificate and the used mark
h.reset()
ADMIN = h.new_user("admin", superuser=True)
user, code = fresh()
h.fail_actions.add("custom:console-cert-issued")
r = h.enrol(code, console)
must(r.status_code == 503 and r.data["code"] == "audit_failed", f"{r.status_code} {r.data}")
must(not M.TecTacConsoleCertificate.objects.exists(), "no certificate when the row cannot be written")
must(enrolment_of(user).state == "open", "the enrolment is not marked used")
h.fail_actions.clear()
h.cache.clear()
ok = h.enrol(cc.create_enrolment_code(user, HOST)["code"], console)
must(ok.status_code == 201, "a new code works after the audit fault")

# ---- nothing secret in a log line or an audit row
h.reset()
ADMIN = h.new_user("admin", superuser=True)
secrets_seen = []
for mutate in (None, "proof", "key"):
    user, code = fresh()
    console = Console()
    body = console.body(code)
    if mutate == "proof":
        body["proof"] = console.proof("x.example.com", code)
    if mutate == "key":
        body["public_key"] = b64u(p384)
    r = h.enrol(code, console, body=body)
    secrets_seen += [code, f"Enrol {code}", body["proof"], body["public_key"], hashlib.sha256(code.encode()).hexdigest()]
text = captured_text(h)
for needle in secrets_seen:
    must(needle not in text, "no code, header, proof, public key or code hash in a log line or audit row")

print("console certificates enrol 1.18.52 regression: PASS")

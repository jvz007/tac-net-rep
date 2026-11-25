#!/usr/bin/env python3
"""Regression: Core 1.18.52 (C3). The Console certificate authority (CA), its key protection and the certificate format.

Real Django on a temporary SQLite file, the real console_certificates.py and the real secret_store AES helpers. Checks: one CA however many
callers race; the private key stored only encrypted and never in an answer, log line or audit row; a wrong or missing master key refuses
every signing path; replace retires, revokes, cancels and writes one row; the CA and leaf certificates carry the fields the plan names.
"""
import base64
import importlib.util
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location("cc_harness", Path(__file__).with_name("console_certificates_harness.py"))
harness = importlib.util.module_from_spec(spec)
sys.modules["cc_harness"] = harness
spec.loader.exec_module(harness)
must, rows_of, captured_text = harness.must, harness.rows_of, harness.captured_text
h = harness.boot()
if h is None:
    print("console certificates CA 1.18.52 regression: SKIPPED (Django is not installed on this PC)")
    sys.exit(0)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

cc, M, store = h.cc, h.models, h.store
SCOPE = store._Scope("core:console-ca")


def plain_key(ca):
    return store._decrypt(h.master_key, SCOPE, f"ca-key:{ca.server_id}", bytes(ca.key_blob))


# ---- one CA: sequential and a two-thread race
h.reset()
first = cc.ensure_ca(h.new_user("a", superuser=True))
second = cc.ensure_ca()
must(first.pk == second.pk and first.server_id == second.server_id, "a second call returns the same CA")
must(M.TecTacConsoleCA.objects.filter(state="active").count() == 1, "one active CA")
must(len(rows_of(h, "custom:console-ca-created")) == 1, "one created row")

h.reset()
barrier = threading.Barrier(2)
results, errors = [], []


def racer():
    try:
        barrier.wait(10)
        results.append(cc.ensure_ca(None).server_id)
    except Exception as exc:  # noqa: BLE001
        errors.append(repr(exc))
    finally:
        h.connection.close()


threads = [threading.Thread(target=racer) for _ in range(2)]
for t in threads:
    t.start()
for t in threads:
    t.join(60)
must(not errors, f"the race raised: {errors}")
must(len(results) == 2 and results[0] == results[1], f"both callers got the winner: {results}")
must(M.TecTacConsoleCA.objects.count() == 1 and M.TecTacConsoleCA.objects.filter(state="active").count() == 1, "one CA row after the race")
must(len(rows_of(h, "custom:console-ca-created")) == 1, "one created row after the race")

# ---- the CA certificate and the server id
ca = M.TecTacConsoleCA.objects.get()
ca_cert = x509.load_der_x509_certificate(bytes(ca.cert_der))
must(ca_cert.version == x509.Version.v3, "v3")
must(ca_cert.subject == ca_cert.issuer and ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Tec-Tac Engineer Console CA", "self-signed, named")
basic = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
must(basic.critical and basic.value.ca is True and basic.value.path_length == 0, "CA:true pathlen 0")
usage = ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value
must(usage.key_cert_sign and not usage.digital_signature and not usage.crl_sign, "keyUsage keyCertSign only")
must(isinstance(ca_cert.public_key().curve, ec.SECP256R1) and isinstance(ca_cert.signature_hash_algorithm, hashes.SHA256), "ECDSA P-256 with SHA-256")
life = ca_cert.not_valid_after_utc - ca_cert.not_valid_before_utc
must(timedelta(days=3649) < life < timedelta(days=3651), f"valid 10 years: {life}")
spki = ca_cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
import hashlib  # noqa: E402

must(ca.server_id == hashlib.sha256(spki).digest()[:16].hex() and len(ca.server_id) == 32, "server_id is the SPKI hash")
must(bytes(ca.public_key_der) == spki, "stored SPKI matches the certificate")

# ---- the key is stored only encrypted
plain = plain_key(ca)
must(plain not in bytes(ca.key_blob) and len(bytes(ca.key_blob)) > len(plain), "the stored blob is not the key")
loaded = serialization.load_der_private_key(plain, password=None)
must(loaded.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == spki, "the encrypted key is the CA's key")
must(ca.key_id == store._key_id(h.master_key), "key_id recorded")
must(b"PRIVATE" not in bytes(ca.key_blob) and plain[:8] not in bytes(ca.key_blob), "no key bytes in the blob")

# ---- a full enrolment gives a certificate with the fields the plan names
h.reset()
admin = h.new_user("admin", superuser=True)
long_name = "engineer-" + "x" * 80
engineer = h.new_user(long_name)
user, console, code, response = h.full_flow(admin, engineer)
must(response.status_code == 201, f"{response.status_code} {response.data}")
bundle = response.data
ca = M.TecTacConsoleCA.objects.get(state="active")
leaf = x509.load_der_x509_certificate(base64.urlsafe_b64decode(bundle["cert"] + "=="))
must(leaf.version == x509.Version.v3, "leaf v3")
must(len(bundle["serial"]) == 32 and int(bundle["serial"], 16) < (1 << 127) and int(bundle["serial"], 16) > 0, "serial: 16 random bytes, top bit clear")
must(f"{leaf.serial_number:032x}" == bundle["serial"], "serial matches the certificate")
cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
must(len(cn) == 64 and long_name.startswith(cn), "the common name is cut to 64 characters")
must(M.TecTacConsoleCertificate.objects.get().username_snapshot == long_name, "the full name is kept in username_snapshot")
must(leaf.issuer == x509.load_der_x509_certificate(bytes(ca.cert_der)).subject, "issuer is the CA subject")
san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
must(san == [f"tectac:server:{ca.server_id}", f"tectac:engineer:{engineer.pk}"], f"SAN: {san}")
ku = leaf.extensions.get_extension_for_class(x509.KeyUsage)
must(ku.critical and ku.value.digital_signature and not ku.value.key_cert_sign, "keyUsage digitalSignature critical")
must(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), "EKU clientAuth")
bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
must(bc.value.ca is False, "CA:false")
now = datetime.now(timezone.utc)
must(abs((leaf.not_valid_before_utc - (now - timedelta(minutes=5))).total_seconds()) < 30, "not_before is now minus 5 minutes")
must(abs((leaf.not_valid_after_utc - (now + timedelta(days=365))).total_seconds()) < 60, "not_after is 365 days (the default)")
leaf_spki = leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
must(leaf_spki == console.spki, "the certificate carries the engineer's public key")
ca_cert = x509.load_der_x509_certificate(bytes(ca.cert_der))
ca_cert.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))  # raises on a bad signature

# ---- the validity setting and the CA end cap
row = M.TecTacConsoleCertificate.objects.get()
M.TecTacConsoleCA.objects.filter(pk=ca.pk).update(not_after=datetime.now(timezone.utc) + timedelta(days=30))
ca.refresh_from_db()
c2 = h.Console()
row2, _der = cc.issue_certificate(ca, user_id=engineer.pk, username="e", spki_der=c2.spki, spki_sha256=c2.spki_hash, pc_label="Other PC", actor=h.cc.service_actor())
must(abs((row2.not_after - (ca.not_after - timedelta(days=1))).total_seconds()) < 1, "not_after is capped at the CA end minus one day")
M.TecTacConsoleCA.objects.filter(pk=ca.pk).update(not_after=datetime.now(timezone.utc) + timedelta(hours=12))
ca.refresh_from_db()
try:
    cc.issue_certificate(ca, user_id=engineer.pk, username="e", spki_der=c2.spki, spki_sha256=c2.spki_hash, pc_label="Third PC", actor=h.cc.service_actor())
    raise AssertionError("an expiring CA must refuse")
except cc.ConsoleCertError as exc:
    must(exc.code == "ca_expired" and exc.status_code == 503, "ca_expired")

# ---- the limit of three, and replace on the same PC
h.reset()
admin = h.new_user("admin", superuser=True)
engineer = h.new_user("busy")
serials = []
for label in ("PC one", "PC two", "PC three"):
    _u, _c, _code, r = h.full_flow(admin, engineer, pc_label=label)
    must(r.status_code == 201, f"{label}: {r.status_code}")
    serials.append(r.data["serial"])
_u, _c, code, r = h.full_flow(admin, engineer, pc_label="PC four")
must(r.status_code == 409 and r.data["code"] == "certificate_limit", f"a 4th is refused: {r.status_code} {r.data}")
must(M.TecTacConsoleCertificate.objects.filter(user_id=engineer.pk, state="active").count() == 3, "still three active")
_u, _c, code, r = h.full_flow(admin, engineer, pc_label="pc TWO")
must(r.status_code == 201, f"the same PC (any case) replaces, not counts: {r.status_code} {r.data}")
old = M.TecTacConsoleCertificate.objects.get(serial=serials[1])
must(old.state == "revoked" and old.revoked_reason == "replaced", "the older certificate of that PC is revoked as replaced")
must(M.TecTacConsoleCertificate.objects.filter(user_id=engineer.pk, state="active").count() == 3, "three active after the replacement")
revoked_rows = [r for r in rows_of(h, "custom:console-cert-revoked") if r["metadata"]["reason"] == "replaced"]
must(len(revoked_rows) == 1 and revoked_rows[0]["strict"] is True, "one strict revoked row for the replacement")

# ---- replace the CA: retire, revoke all, cancel open enrolments, one row with counts
h.reset()
admin = h.new_user("admin", superuser=True)
e1, e2, e3 = h.new_user("e1"), h.new_user("e2"), h.new_user("e3")
h.full_flow(admin, e1)
h.full_flow(admin, e2)
h.call(h.views.ConsoleCertificateIssueView, "POST", "/x/", admin, {"user_id": e3.pk})  # an open enrolment with no certificate
cc_old = cc.active_ca()
result = cc.replace_ca(admin)
must(result["revoked_certificates"] == 2 and result["cancelled_enrolments"] == 1, f"counts: {result}")
must(M.TecTacConsoleCA.objects.filter(state="active").count() == 1 and M.TecTacConsoleCA.objects.filter(state="retired").count() == 1, "one active, one retired")
must(M.TecTacConsoleCA.objects.filter(pk=cc_old.pk, state="retired").exists(), "the old CA is kept, retired")
must(cc.active_ca().server_id != cc_old.server_id, "a new server id")
must(M.TecTacConsoleCertificate.objects.filter(state="active").count() == 0, "no active certificate")
must(set(M.TecTacConsoleCertificate.objects.values_list("revoked_reason", flat=True)) == {"ca_replaced"}, "reason ca_replaced")
must(M.TecTacConsoleEnrolment.objects.filter(state="open").count() == 0, "no open enrolment")
replaced_rows = rows_of(h, "custom:console-ca-replaced")
must(len(replaced_rows) == 1 and replaced_rows[0]["strict"] is True, "one strict replaced row")
meta = replaced_rows[0]["metadata"]
must(meta["revoked_certificates"] == 2 and meta["cancelled_enrolments"] == 1, "the row carries the counts")
try:
    h.reset()
    cc.replace_ca(admin)
    raise AssertionError("nothing to replace must be refused")
except cc.ConsoleCertError as exc:
    must(exc.code == "ca_not_created" and exc.status_code == 409, "ca_not_created")

# ---- a wrong or missing master key refuses ensure, issue, code and enrol
h.reset()
admin = h.new_user("admin", superuser=True)
engineer = h.new_user("keyed")
h.master_fault = "missing"
for call in (lambda: cc.ensure_ca(admin), lambda: cc.authorise(admin, engineer.pk)):
    try:
        call()
        raise AssertionError("a missing master key must refuse")
    except store.SecretStoreError as exc:
        must(exc.code == "master_key_unavailable" and exc.status_code == 503, "master_key_unavailable 503")
must(M.TecTacConsoleCA.objects.count() == 0, "no CA is made without a key")
issued = h.call(h.views.ConsoleCertificateIssueView, "POST", "/x/", admin, {"user_id": engineer.pk})
must(issued.status_code == 503 and issued.data["code"] == "master_key_unavailable", "the issue route answers 503")
h.master_fault = None
user, console, code, ok = h.full_flow(admin, engineer)
must(ok.status_code == 201, "works again with the key")
h.master_fault = "missing"
code_answer = h.call(h.views.ConsoleCertificateEnrolmentCodeView, "POST", "/x/", engineer, {})
must(code_answer.status_code == 503 and code_answer.data["code"] == "master_key_unavailable", "the code route checks the key first")
h.master_fault = None
h.call(h.views.ConsoleCertificateIssueView, "POST", "/x/", admin, {"user_id": engineer.pk})
fresh = h.call(h.views.ConsoleCertificateEnrolmentCodeView, "POST", "/x/", engineer, {}).data["code"]
good_key = h.master_key
h.master_key = __import__("os").urandom(32)  # a different key: the CA row cannot be decrypted
refused = h.enrol(fresh, h.Console(), pc_label="Second PC")
must(refused.status_code == 503 and refused.data["code"] == "master_key_unavailable", f"a wrong key refuses enrol: {refused.status_code} {refused.data}")
h.master_key = good_key

# ---- the key never appears in an answer, a log line or an audit row
ca = cc.active_ca()
plain = plain_key(ca)
needles = {
    "raw hex": plain.hex(), "base64": base64.b64encode(plain).decode(), "base64url": base64.urlsafe_b64encode(plain).decode().rstrip("="),
    "pem body": base64.b64encode(plain).decode()[:40],
}
answers = [str(refused.data), str(ok.data), str(code_answer.data), str(issued.data), str(h.call(h.views.ConsoleCertificateCaView, "GET", "/x/", admin).data)]
text = captured_text(h) + "\n" + "\n".join(answers)
for name, needle in needles.items():
    must(needle not in text, f"the CA private key ({name}) must not appear in any answer, log record or audit payload")
must(not any("PRIVATE KEY" in line for line in h.logs), "no PEM header in a log line")
M.TecTacConsoleCA.objects.filter(pk=ca.pk).update(key_blob=b"\x00" * 60)
h.logs.clear()
try:
    cc._sign(M.TecTacConsoleCA.objects.get(pk=ca.pk), x509.CertificateBuilder())
    raise AssertionError("an unreadable key row must refuse")
except store.SecretStoreError as exc:
    must(exc.code == "master_key_unavailable" and exc.reason == "ca_key_unreadable", "an undecryptable row is master_key_unavailable")
    must(needles["base64"] not in str(exc) and plain.hex() not in str(exc), "the exception text holds no key")
must(any("ca_key_unreadable" in line for line in h.logs), "the reason is in the log")

print("console certificates CA 1.18.52 regression: PASS")

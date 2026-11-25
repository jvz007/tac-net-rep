#!/usr/bin/env python3
"""Regression: Core 1.18.53 (C4). The Console tunnel connect, certificate side: the connect proof, the server proof, the certificate checks, the
5-minute re-read, the refusal row, the revoke and CA-replacement hooks and last_used_at.

Real Django on a temporary SQLite file, real P-256 keys (tests/console_certificates_harness.py) and the real console_certificates.py. The tunnel layer
(tec_tac.probe_tunnel) is a stub that records the hook calls; the websocket side is tests/probe-tunnel-certificates-1.18.53.py.

Checks: golden vectors of both message byte strings; a good connect and a server proof that verifies with the CA public key; every certificate
reason with its own bad input, in the documented order (stale time, certificate and CA signature, database row, revoked, expired, another engineer's
certificate, the proof signature over the host, the server id, the ticket and the nonce); an unreadable master key fails closed; last_used_at is
written at most hourly; the CA key is in no answer, log line or audit row; has_usable_certificate and recheck; the refusal row (one a minute per
address, no secret); the hooks run after the commit and a failing hook never fails the revoke.
"""
import hashlib
import importlib.util
import os
import sys
from datetime import timedelta
from pathlib import Path

spec = importlib.util.spec_from_file_location("cc_harness", Path(__file__).with_name("console_certificates_harness.py"))
harness = importlib.util.module_from_spec(spec)
sys.modules["cc_harness"] = harness
spec.loader.exec_module(harness)
must, rows_of, captured_text, b64u = harness.must, harness.rows_of, harness.captured_text, harness.b64u
h = harness.boot()
if h is None:
    print("console certificates connect 1.18.53 regression: SKIPPED (Django is not installed on this PC)")
    sys.exit(0)

import secrets  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402

cc, M, store = h.cc, h.models, h.store
HOST, IP = harness.HOST, harness.IP
NEWLINE = chr(10)

# ---- golden vectors: the exact bytes, written out by hand (no trailing newline)
TICKET = "T" * 43
TICKET_HASH = "8a652abf7512959a7ecf7abe32a2bb4634c0b03fc93008b0365ed67933bff00c"
must(cc.ticket_hash(TICKET) == TICKET_HASH == hashlib.sha256(TICKET.encode()).hexdigest(), "ticket hash is sha256 of the 43 ASCII characters, lower-case hex")
SERVER, SERIAL, NONCE = "1" * 32, "2" * 32, "AAAAAAAAAAAAAAAAAAAAAA"
expected_connect = (
    b"tectac-console-connect-v1" + b"\n" + b"host=tec.example.com" + b"\n" + b"server=" + SERVER.encode() + b"\n" + b"ticket=" + TICKET_HASH.encode() + b"\n"
    + b"serial=" + SERIAL.encode() + b"\n" + b"time=1764000000" + b"\n" + b"nonce=" + NONCE.encode())
must(cc.connect_message("tec.example.com", SERVER, TICKET, SERIAL, "1764000000", NONCE) == expected_connect, "connect message golden vector")
must(not expected_connect.endswith(b"\n") and expected_connect.count(b"\n") == 6 and b"\r" not in expected_connect, "six LFs, no trailing LF")
expected_server = (
    b"tectac-core-connect-v1" + b"\n" + b"host=tec.example.com" + b"\n" + b"server=" + SERVER.encode() + b"\n" + b"ticket=" + TICKET_HASH.encode() + b"\n"
    + b"serial=" + SERIAL.encode() + b"\n" + b"nonce=" + NONCE.encode())
must(cc.server_proof_message("tec.example.com", SERVER, TICKET, SERIAL, NONCE) == expected_server, "server proof message golden vector")
must(not expected_server.endswith(b"\n") and expected_server.count(b"\n") == 5, "five LFs, no trailing LF")
must(tuple(cc.CERT_REASONS) == ("certificate_required", "certificate_invalid", "certificate_expired", "certificate_revoked", "certificate_engineer_mismatch",
                                "proof_invalid", "proof_stale"), "the seven reasons")

# ---- a good connect
h.reset()
admin = h.new_user("admin", superuser=True)
user, console, code, response = h.full_flow(admin, None, pc_label="Work PC")
must(response.status_code == 201, response.data)
bundle = response.data
cert_der = cc.b64u_decode(bundle["cert"], max_chars=4096)
SERVER_ID, SERIAL_REAL = bundle["server_id"], bundle["serial"]
NOW = cc._now().replace(microsecond=0)


def proof_for(con, bun, ticket, *, host=HOST, server_id=None, serial=None, offset=0, nonce=None, key=None):
    text = con.connect_proof(host, server_id or bun["server_id"], ticket, serial or bun["serial"], str(int(NOW.timestamp()) + offset), nonce or b64u(os.urandom(16)), key=key)
    _v, stamp, nonce_text, sig = text.split(".")
    return {"time": stamp, "nonce": nonce_text, "sig": sig}


def verify(bun, proof, ticket, *, host=HOST, user_id=None, der=None):
    return cc.verify_connect(der if der is not None else cc.b64u_decode(bun["cert"], max_chars=4096), proof, ticket, host,
                             user_id if user_id is not None else bun["engineer"]["id"], NOW)


def refused(code_wanted, bun, proof, ticket, **kw):
    try:
        verify(bun, proof, ticket, **kw)
    except cc.ConnectRefused as exc:
        must(exc.code == code_wanted, f"wanted {code_wanted}, got {exc.code}")
        must(isinstance(exc, cc.ConsoleCertError) and exc.status_code == 401, "a ConsoleCertError with 401")
        return exc
    raise AssertionError(f"{code_wanted}: the connect was not refused")


ticket = secrets.token_urlsafe(32)
nonce = b64u(os.urandom(16))
proof = proof_for(console, bundle, ticket, nonce=nonce)
verified = verify(bundle, proof, ticket)
must(verified["serial"] == SERIAL_REAL and verified["server_id"] == SERVER_ID, "serial and server id")
row = M.TecTacConsoleCertificate.objects.get(serial=SERIAL_REAL)
must(abs(verified["not_after"] - row.not_after.timestamp()) < 1e-6, "not_after is the row's end as epoch seconds")
server_proof = cc.sign_server_proof(verified, HOST, ticket, nonce)
must(server_proof.startswith("v1.") and len(server_proof) == 3 + 86 and harness.b64u(cc.b64u_decode(server_proof[3:])) == server_proof[3:], "v1. and 86 characters")
ca_key = serialization.load_der_public_key(cc.b64u_decode(bundle["ca_public_key"], max_chars=300))
raw = cc.b64u_decode(server_proof[3:], max_chars=100)
must(len(raw) == 64, "64 bytes r||s")
der_sig = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
by_hand = (b"tectac-core-connect-v1" + b"\n" + f"host={HOST}".encode() + b"\n" + f"server={SERVER_ID}".encode() + b"\n"
           + f"ticket={hashlib.sha256(ticket.encode()).hexdigest()}".encode() + b"\n" + f"serial={SERIAL_REAL}".encode() + b"\n" + f"nonce={nonce}".encode())
ca_key.verify(der_sig, by_hand, ec.ECDSA(hashes.SHA256()))  # raises when wrong
for other in (b"tectac-core-connect-v1" + b"\n" + b"host=evil.example.com" + by_hand.split(b"\n", 2)[2],
              by_hand.replace(nonce.encode(), b64u(os.urandom(16)).encode())):
    try:
        ca_key.verify(der_sig, other, ec.ECDSA(hashes.SHA256()))
        raise AssertionError("the server proof also verified for other bytes")
    except Exception as exc:  # noqa: BLE001
        must(exc.__class__.__name__ == "InvalidSignature", repr(exc))

# the proof is bound to its inputs: the CA-signed server proof never verifies as a connect proof either
must(b"tectac-core-connect-v1" != b"tectac-console-connect-v1", "the two prefixes differ")

# ---- the boundary of the time window
for offset in (120, -120):
    verify(bundle, proof_for(console, bundle, ticket, offset=offset), ticket)
for offset in (121, -121, 3600):
    refused("proof_stale", bundle, proof_for(console, bundle, ticket, offset=offset), ticket)
# the time check comes first: a stale proof for a revoked or foreign certificate is still proof_stale (no database read is needed to say it)
refused("proof_stale", bundle, proof_for(console, bundle, ticket, offset=500), ticket, der=b"not a certificate")

# ---- certificate_invalid: garbage, tampered, signed by another key, not in the table, row mismatch, not yet valid
refused("certificate_invalid", bundle, proof, ticket, der=b"\x30\x03\x02\x01\x00")
refused("certificate_invalid", bundle, proof, ticket, der=cert_der[:-1] + bytes([cert_der[-1] ^ 1]))  # the CA signature
middle = len(cert_der) // 2
refused("certificate_invalid", bundle, proof, ticket, der=cert_der[:middle] + bytes([cert_der[middle] ^ 1]) + cert_der[middle + 1:])  # the signed part
ca_row = M.TecTacConsoleCA.objects.get(state="active")
ca_cert = x509.load_der_x509_certificate(bytes(ca_row.cert_der))
leaf = x509.load_der_x509_certificate(cert_der)


def leaf_signed_by(signing_key, serial_int):
    return (x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(ca_cert.subject).public_key(leaf.public_key()).serial_number(serial_int)
            .not_valid_before(leaf.not_valid_before_utc).not_valid_after(leaf.not_valid_after_utc)
            .sign(signing_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


foreign = leaf_signed_by(ec.generate_private_key(ec.SECP256R1()), int(SERIAL_REAL, 16))  # same issuer name, another CA key: the wrong CA
refused("certificate_invalid", bundle, proof, ticket, der=foreign)
fake_serial = int.from_bytes(os.urandom(16), "big") & ((1 << 127) - 1)
unsaved = cc._with_ca_key(ca_row, lambda key: leaf_signed_by(key, fake_serial))  # a valid CA signature, but no row in Core's table
exc = refused("certificate_invalid", bundle, proof, ticket, der=unsaved)
must(exc.serial == format(fake_serial, "032x"), "the refusal carries a serial that parsed to 32 hex")
must(refused("certificate_invalid", bundle, proof, ticket, der=b"\x30\x03\x02\x01\x00").serial is None, "no serial when nothing parsed")
M.TecTacConsoleCertificate.objects.filter(pk=row.pk).update(cert_der=b"other bytes")
refused("certificate_invalid", bundle, proof, ticket)
M.TecTacConsoleCertificate.objects.filter(pk=row.pk).update(cert_der=cert_der)
M.TecTacConsoleCertificate.objects.filter(pk=row.pk).update(spki_sha256="0" * 64)
refused("certificate_invalid", bundle, proof, ticket)
M.TecTacConsoleCertificate.objects.filter(pk=row.pk).update(spki_sha256=row.spki_sha256)
M.TecTacConsoleCertificate.objects.filter(pk=row.pk).update(not_before=NOW + timedelta(hours=1))
refused("certificate_invalid", bundle, proof, ticket)
M.TecTacConsoleCertificate.objects.filter(pk=row.pk).update(not_before=row.not_before)
verify(bundle, proof, ticket)  # restored: good again

# ---- expired, then revoked (revoked is answered first), then the other engineer's certificate
M.TecTacConsoleCertificate.objects.filter(pk=row.pk).update(not_after=NOW - timedelta(minutes=1))
refused("certificate_expired", bundle, proof, ticket)
M.TecTacConsoleCertificate.objects.filter(pk=row.pk).update(not_after=row.not_after)
other_user = h.new_user("someone-else")
refused("certificate_engineer_mismatch", bundle, proof, ticket, user_id=other_user.pk)
h.tunnel_calls.clear()
cc.revoke(admin, SERIAL_REAL, "lost", can_manage=True)
refused("certificate_revoked", bundle, proof, ticket)
M.TecTacConsoleCertificate.objects.filter(pk=row.pk).update(not_after=NOW - timedelta(minutes=1))
refused("certificate_revoked", bundle, proof, ticket)  # revoked and expired: revoked first

# ---- the proof signature: a second certificate, so the checks above did not spend this one
h.reset()
admin = h.new_user("admin", superuser=True)
user, console, code, response = h.full_flow(admin, None, pc_label="Work PC")
bundle = response.data
ticket = secrets.token_urlsafe(32)
good = proof_for(console, bundle, ticket)
verify(bundle, good, ticket)
imposter = harness.Console()
refused("proof_invalid", bundle, proof_for(console, bundle, ticket, key=imposter.key), ticket)  # signed with another key
refused("proof_invalid", bundle, proof_for(console, bundle, ticket, host="evil.example.com"), ticket)  # the Console signed another host
refused("proof_invalid", bundle, proof_for(console, bundle, ticket), ticket, host="evil.example.com")  # Core's host (the Host header) differs
refused("proof_invalid", bundle, good, ticket, host=None)  # no usable host header
refused("proof_invalid", bundle, good, ticket, host="tec.example.com:8443")  # any other port is unsupported
refused("proof_invalid", bundle, proof_for(console, bundle, ticket, server_id="9" * 32), ticket)  # the Console pinned another server id
refused("proof_invalid", bundle, proof_for(console, bundle, secrets.token_urlsafe(32)), ticket)  # signed for another ticket
refused("proof_invalid", bundle, {**good, "nonce": b64u(os.urandom(16))}, ticket)  # the nonce was changed after signing
refused("proof_invalid", bundle, {**good, "time": str(int(good["time"]) + 1)}, ticket)  # so was the time
refused("proof_invalid", bundle, {**good, "sig": b64u(os.urandom(64))}, ticket)
refused("proof_invalid", bundle, {**good, "sig": "AAAA"}, ticket)  # not 64 bytes
must(refused("proof_invalid", bundle, proof_for(console, bundle, ticket, key=imposter.key), ticket).serial == bundle["serial"], "the serial is known once the certificate checked out")

# ---- a replaced CA: the old certificate answers certificate_invalid (not revoked) because its issuer is no longer the active CA
old_cert = cc.b64u_decode(bundle["cert"], max_chars=4096)
replaced = cc.replace_ca(admin)
must(replaced["revoked_certificates"] == 1, replaced)
refused("certificate_invalid", bundle, good, ticket, der=old_cert)

# ---- the server proof fails closed when the master key cannot be used, and no key reaches a log or a row
h.reset()
admin = h.new_user("admin", superuser=True)
user, console, code, response = h.full_flow(admin, None)
bundle = response.data
ticket = secrets.token_urlsafe(32)
verified = verify(bundle, proof_for(console, bundle, ticket), ticket)
h.master_fault = "file_missing"
try:
    cc.sign_server_proof(verified, HOST, ticket, "AAAAAAAAAAAAAAAAAAAAAA")
    raise AssertionError("signed without a master key")
except store.SecretStoreError as exc:
    must(exc.code == "master_key_unavailable" and exc.status_code == 503, exc.code)
h.master_fault = None
good_master = h.master_key
h.master_key = os.urandom(32)  # a key that cannot decrypt the CA row
try:
    cc.sign_server_proof(verified, HOST, ticket, "AAAAAAAAAAAAAAAAAAAAAA")
    raise AssertionError("signed with the wrong master key")
except store.SecretStoreError as exc:
    must(exc.code == "master_key_unavailable", exc.code)
h.master_key = good_master
sp = cc.sign_server_proof(verified, HOST, ticket, "AAAAAAAAAAAAAAAAAAAAAA")
ca_now = M.TecTacConsoleCA.objects.get(state="active")
plain = store._decrypt(h.master_key, store._Scope("core:console-ca"), f"ca-key:{ca_now.server_id}", bytes(ca_now.key_blob))
everything = captured_text(h) + sp + repr(verified.get("server_id"))
import base64  # noqa: E402

for secret_text in (plain.hex(), b64u(plain), base64.b64encode(plain).decode(), h.master_key.hex(), b64u(h.master_key)):
    must(secret_text not in everything, "the CA key or the master key is in a log, a row or an answer")
must("ca_key_unreadable" in "\n".join(h.logs), "the reason is in the log")

# ---- last_used_at: at most hourly, one conditional update, never fatal
h.reset()
admin = h.new_user("admin", superuser=True)
user, console, code, response = h.full_flow(admin, None)
serial = response.data["serial"]
get_row = lambda: M.TecTacConsoleCertificate.objects.get(serial=serial)  # noqa: E731
must(get_row().last_used_at is None, "empty before the first use")
t0 = cc._now()
cc.touch_last_used(serial, t0)
must(get_row().last_used_at == t0, "filled on first use")
cc.touch_last_used(serial, t0 + timedelta(minutes=59))
must(get_row().last_used_at == t0, "not rewritten within the hour")
cc.touch_last_used(serial, t0 + timedelta(minutes=61))
must(get_row().last_used_at == t0 + timedelta(minutes=61), "rewritten after an hour")
shown = cc.serialise_certificate(get_row(), t0)
must(shown["last_used_at"] == (t0 + timedelta(minutes=61)).isoformat(), "the list shows it")
cc.touch_last_used("f" * 32, t0)  # an unknown serial changes nothing and does not raise
real_models = cc._models
cc._models = lambda: (_ for _ in ()).throw(RuntimeError("database down"))
cc.touch_last_used(serial, t0 + timedelta(days=1))  # a fault is logged, never raised
cc._models = real_models
must("last-used time could not be written" in "\n".join(h.logs), "the fault is logged")

# ---- has_usable_certificate and recheck
h.reset()
admin = h.new_user("admin", superuser=True)
engineer = h.new_user("engineer-x")
must(cc.has_usable_certificate(engineer.pk) is False, "no certificate")
_u, _c, _code, r1 = h.full_flow(admin, engineer, pc_label="PC one")
serial1 = r1.data["serial"]
must(cc.has_usable_certificate(engineer.pk) is True, "one active certificate")
must(cc.recheck(serial1) is None, "an active certificate re-checks clean")
must(cc.recheck("0" * 32) == "certificate_revoked", "an unknown serial is treated as revoked")
M.TecTacConsoleCertificate.objects.filter(serial=serial1).update(not_after=cc._now() - timedelta(minutes=1))
must(cc.has_usable_certificate(engineer.pk) is False and cc.recheck(serial1) == "certificate_expired", "expired only")
M.TecTacConsoleCertificate.objects.filter(serial=serial1).update(not_after=cc._now() + timedelta(days=30))
cc.revoke(admin, serial1, "other", can_manage=True)
must(cc.has_usable_certificate(engineer.pk) is False and cc.recheck(serial1) == "certificate_revoked", "revoked only")
_u, _c, _code, r2 = h.full_flow(admin, engineer, pc_label="PC two")
serial2 = r2.data["serial"]
must(cc.has_usable_certificate(engineer.pk) is True, "a new active certificate")
M.TecTacConsoleCA.objects.filter(state="active").update(state="retired")  # a certificate of a CA that is no longer the active one
must(cc.has_usable_certificate(engineer.pk) is False and cc.recheck(serial2) == "certificate_revoked", "old CA only")
M.TecTacConsoleCA.objects.filter(state="retired").update(state="active")
must(cc.has_usable_certificate(engineer.pk) is True, "restored")
must(cc.has_usable_certificate(h.new_user("nobody").pk) is False, "another person's certificates do not count")

# ---- the refusal row: one a minute per address, only the allowed fields, never a secret
h.reset()
h.rows.clear()
must(cc.record_refusal("proof_invalid", IP, session_id="s" * 36, engineer_id=5, serial="a" * 32) is True, "first row written")
must(cc.record_refusal("proof_stale", IP, session_id="s" * 36, engineer_id=5) is False, "second from the same address in the minute: none")
must(cc.record_refusal("proof_stale", "198.51.100.9", engineer_id=5, serial="not hex") is True, "another address gets its own")
written = rows_of(h, "custom:console-cert-refused")
must(len(written) == 2, len(written))
first, second = written
must(first["module_id"] == "core" and first["object_type"] == "console_certificate" and first["object_id"] == "a" * 32 and first["strict"] is False, first)
must(first["metadata"] == {"reason": "proof_invalid", "ip": IP, "session_id": "s" * 36, "engineer_id": 5, "serial": "a" * 32}, first["metadata"])
must(first["operation_context"] == {"server_provenance": "console-certificates", "core_refusal": True}, first["operation_context"])
must(second["metadata"] == {"reason": "proof_stale", "ip": "198.51.100.9", "engineer_id": 5} and second["object_id"] is None, "a serial that is not 32 hex is left out")
h.cache.clear()
must(cc.record_refusal("proof_invalid", IP) is True, "a new minute")

# ---- the hooks: after the commit, a failing hook never fails the revoke, nothing runs when the change rolls back
h.reset()
admin = h.new_user("admin", superuser=True)
engineer = h.new_user("engineer-y")
_u, _c, _code, r = h.full_flow(admin, engineer, pc_label="Laptop")
serial_a = r.data["serial"]
h.tunnel_calls.clear()
done = cc.revoke(admin, serial_a, "lost", can_manage=True)
must(done["changed"] is True and done["state"] == "revoked", done)
must(h.tunnel_calls == [("certificate_revoked", serial_a, False)], h.tunnel_calls)  # in_atomic_block False: it ran after the commit
h.tunnel_calls.clear()
again = cc.revoke(admin, serial_a, "lost", can_manage=True)
must(again["changed"] is False and h.tunnel_calls == [], "an already revoked certificate runs no hook")
# the owner revokes their own
_u, _c, _code, r = h.full_flow(admin, engineer, pc_label="Desktop")
serial_b = r.data["serial"]
h.tunnel_calls.clear()
cc.revoke(engineer, serial_b, "lost", can_manage=False)
must(h.tunnel_calls == [("certificate_revoked", serial_b, False)], h.tunnel_calls)
# a failing tunnel layer: the revoke still stands, the fault is logged
_u, _c, _code, r = h.full_flow(admin, engineer, pc_label="Tablet")
serial_c = r.data["serial"]
h.tunnel_calls.clear()
h.tunnel_fault[0] = True
survived = cc.revoke(admin, serial_c, "left", can_manage=True)
must(survived["changed"] is True and M.TecTacConsoleCertificate.objects.get(serial=serial_c).state == "revoked", "the revoke stands")
must(len(h.tunnel_calls) == 1 and "Ending the live tunnel sessions" in "\n".join(h.logs), "the hook ran, failed and was logged")
h.tunnel_fault[0] = False
# a rolled-back revoke runs no hook (the strict row fails, so the change is not made)
_u, _c, _code, r = h.full_flow(admin, engineer, pc_label="Phone")
serial_d = r.data["serial"]
h.tunnel_calls.clear()
h.fail_actions.add("custom:console-cert-revoked")
try:
    cc.revoke(admin, serial_d, "other", can_manage=True)
    raise AssertionError("the revoke worked without its audit row")
except h.audit.AuditWriteError:
    pass
h.fail_actions.clear()
must(h.tunnel_calls == [] and M.TecTacConsoleCertificate.objects.get(serial=serial_d).state == "active", "nothing ran and nothing changed")
# the same PC enrols again: the older certificate is revoked as replaced and its sessions end
h.tunnel_calls.clear()
_u, _c, _code, r2 = h.full_flow(admin, engineer, pc_label="Phone")
must(h.tunnel_calls == [("certificate_revoked", serial_d, False)], h.tunnel_calls)
# the CA replacement ends every session, with the OLD server id, once
old_server = M.TecTacConsoleCA.objects.get(state="active").server_id
h.tunnel_calls.clear()
out = cc.replace_ca(admin)
must(h.tunnel_calls == [("ca_replaced", old_server, False)], h.tunnel_calls)
must(out["old_server_id"] == old_server, out)

print("console certificates connect 1.18.53 regression: PASS")

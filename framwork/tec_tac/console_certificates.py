"""Engineer Console certificates (Core 1.18.52, C3 of the Engineer Console certificate plan, signed 25 November 2026).

A certificate is a small signed file that says "this key belongs to this engineer". Core runs its own certificate authority (CA): one key
pair whose private half signs every Console certificate. An engineer's Console makes its own key pair, proves it holds the private half, and
Core signs the public half. The private key never leaves the engineer's PC.

C3 (1.18.52) built the CA, the certificate, the enrolment and the management routes. C4 (1.18.53) makes the certificate the tunnel
credential: every Console connect carries the certificate and a proof signed with its key (``verify_connect``), Core answers with a server
proof signed with the CA key (``sign_server_proof``), the certificate is re-read every 5 minutes (``recheck``), and a revoke or a CA
replacement ends the live sessions (the after-commit hooks call probe_tunnel). See docs/console-certificates.md.

This file is pure logic. It has no DRF and imports ``cryptography``, Django's models and the secret store lazily inside functions, so a
fault there can never stop Tactical from starting (rule 1.13). ``console_certificate_views`` and ``probe_tunnel`` (lazily) call it.

The CA private key. 32 bytes of master key from the secret store encrypts it (AES-256-GCM, the secret store's own private helpers, scope
``core:console-ca``, name ``ca-key:<server_id>``) and only the encrypted blob is stored (table ``core_console_ca``). It is decrypted in memory
inside ``_sign`` and nowhere else. It never reaches a file, a log line, an audit row, an exception text or an answer. A missing or unsafe
master key, or a key that cannot decrypt the row, is the secret store's ``master_key_unavailable`` (503); the reason goes to the log only.

Audit rows go through ``audit._record_console_certificates`` (private). Allowed in a row: a serial, a key fingerprint, a PC label, a date, ids,
a reason, counts and the address. Never a code, a ticket, a key, a signature, a proof or a header value.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import os
import re
import secrets
import time
import unicodedata
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("tec_tac.console_certificates")

CA_COMMON_NAME = "Tec-Tac Engineer Console CA"
CA_VALID_DAYS = 3650
CLOCK_SKEW_MINUTES = 5
CA_SAFETY_DAYS = 1
MAX_ACTIVE_CERTIFICATES = 3
ENROLMENT_DAYS = 7
CODE_MINUTES = 10
EXPIRING_CERTIFICATE_DAYS = 30
EXPIRING_CA_DAYS = 365
MAX_BODY_BYTES = 4096
MAX_PC_LABEL = 64
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
MAX_ENROLMENTS_LISTED = 200
FAILURES_PER_ADDRESS_PER_MINUTE = 10  # the number AD-54 signed for the agent route; the same here (IPv6 grouped by its /64)
FAILURE_PREFIX = "tec-tac:cc:fail:"
REFUSAL_ROW_PREFIX = "tec-tac:cc:refrow:"
PROOF_PREFIX = b"tectac-console-enrol-v1\n"
SCOPE_NAME = "core:console-ca"
SERVER_URI = "tectac:server:"
ENGINEER_URI = "tectac:engineer:"

# The same pattern as the tunnel launch link (probe_tunnel.HOST_PATTERN); a test pins that the two stay equal.
HOST_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
CODE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")  # secrets.token_urlsafe(32)
SERIAL_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")

REVOKE_REASONS = ("lost", "left", "admin", "other")
ENROL_KEYS = frozenset({"v", "public_key", "pc_label", "proof"})

# C4 (1.18.53): the tunnel connect
CONNECT_PREFIX = b"tectac-console-connect-v1\n"
SERVER_PROOF_PREFIX = b"tectac-core-connect-v1\n"
PROOF_WINDOW_SECONDS = 120
LAST_USED_SECONDS = 3600
CERT_REASONS = ("certificate_required", "certificate_invalid", "certificate_expired", "certificate_revoked", "certificate_engineer_mismatch",
                "proof_invalid", "proof_stale")


class ConsoleCertError(Exception):
    """A refusal. ``code`` is the machine-readable reason, ``status_code`` the HTTP mapping. The message never holds a secret."""

    def __init__(self, code: str, message: str, status_code: int = 400, *, retry_after: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after
        self.counted = False  # True once _refuse has counted this refusal against the address


# ------------------------------------------------------------------------------------------------ small helpers
def _now() -> datetime:
    return datetime.now(timezone.utc)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64u_decode(text, *, max_chars: int = 4096) -> bytes | None:
    """Strict base64url without padding. ``None`` for anything else, including text that does not re-encode to itself."""
    if not isinstance(text, str) or not text or len(text) > max_chars or not _B64URL.fullmatch(text):
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        return None
    return raw if b64u(raw) == text else None


def _models():
    from . import models

    return models


def _store():
    from . import secret_store

    return secret_store


def _audit(actor, action, object_type, object_id, message, metadata=None, *, strict=True, refusal=False):
    """One Core audit row. Strict: raises AuditWriteError (no row means no change). Not strict: never raises."""
    from .audit import _record_console_certificates

    if strict:
        return _record_console_certificates(
            actor=actor, action=action, object_type=object_type, object_id=object_id, message=message, metadata=metadata, strict=True,
            refusal=refusal,
        )
    try:
        return _record_console_certificates(
            actor=actor, action=action, object_type=object_type, object_id=object_id, message=message, metadata=metadata, strict=False,
            refusal=refusal,
        )
    except Exception:
        logger.warning("A Console certificate audit row could not be written (%s).", action, exc_info=True)
        return None


def _tunnel():
    from . import probe_tunnel

    return probe_tunnel


def _after_commit(label: str, call) -> None:
    """Run ``call`` once the surrounding transaction has committed (at once outside one). A fault is logged and never undoes or blocks the
    change: the database row is the authority, the live end is best effort and backed by a marker and the 5-minute re-check."""
    from django.db import transaction

    def run():
        try:
            call()
        except Exception:
            logger.warning("Ending the live tunnel sessions after a Console certificate change failed (%s); the re-check will end them.", label, exc_info=True)

    try:
        transaction.on_commit(run)
    except Exception:
        logger.warning("The live tunnel end after a Console certificate change could not be scheduled (%s).", label, exc_info=True)


def service_actor():
    from .audit import service_audit_actor

    return service_audit_actor(module_id="core", service="console-certificates")


def deny(actor, object_type: str, object_id=None, reason: str = "permission_required") -> None:
    """The non-strict Core ``deny`` row for a refused permission (AD-12). Never raises."""
    _audit(actor, "deny", object_type, object_id, "Blocked a Console certificate action that needs a permission.", {"reason": reason},
           strict=False, refusal=True)


def own_host(request) -> str | None:
    """Core's own host, the way the tunnel launch link builds it: lower case, ``:443`` removed, and only a plain host name. Other ports and
    odd hosts give ``None`` (the callers refuse with host_unusable)."""
    try:
        host = str(request.get_host()).strip().lower()
    except Exception:
        logger.debug("The request host could not be read.", exc_info=True)
        return None
    host = host.removesuffix(":443")
    return host if HOST_PATTERN.fullmatch(host) else None


def client_address(request) -> str:
    """The address failures are counted against: REMOTE_ADDR, which nginx fills from $remote_addr. X-Real-IP is not used on this route (the
    uwsgi location does not set it, so a caller could choose it), and the leftmost X-Forwarded-For is client controlled."""
    value = request.META.get("REMOTE_ADDR")
    if isinstance(value, str) and value:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            return value[:64]
    return "unknown"


def forwarded_plaintext(request) -> bool:
    """True when the proxy says the client used a plain-text connection (X-Forwarded-Proto http or ws). Absent header: TLS is left to nginx."""
    value = request.META.get("HTTP_X_FORWARDED_PROTO")
    if not isinstance(value, str) or not value:
        return False
    return value.split(",")[0].strip().lower() in ("http", "ws")


# ------------------------------------------------------------------------------------------------ failure limit (address only)
def _cache():
    from django.core.cache import cache

    return cache


def _address_key(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return str(ip)
    if address.version == 6:
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


def _minute() -> int:
    return int(time.time() // 60)


def rate_limited(ip: str) -> bool:
    """True when this address (an IPv6 address by its /64) has had 10 failed enrolments this minute. A cache fault reads as not limited and
    is logged: the code has 256 bits, so a missing counter does not make guessing possible (the rule endpoint_transport accepts too)."""
    try:
        return int(_cache().get(f"{FAILURE_PREFIX}{_address_key(ip)}:{_minute()}", 0) or 0) >= FAILURES_PER_ADDRESS_PER_MINUTE
    except Exception:
        logger.warning("The Console enrolment failure counter could not be read.", exc_info=True)
        return False


def note_failure(ip: str) -> None:
    try:
        cache = _cache()
        key = f"{FAILURE_PREFIX}{_address_key(ip)}:{_minute()}"
        cache.add(key, 0, timeout=120)
        try:
            cache.incr(key)
        except ValueError:
            cache.add(key, 1, timeout=120)
    except Exception:
        logger.warning("The Console enrolment failure counter could not be written.", exc_info=True)


def _refusal_row_due(ip: str) -> bool:
    """At most one refusal row per address per minute. A cache fault writes none (a flood of rows would cost more than one lost row)."""
    try:
        return bool(_cache().add(f"{REFUSAL_ROW_PREFIX}{_address_key(ip)}:{_minute()}", 1, timeout=120))
    except Exception:
        logger.warning("The Console enrolment refusal row limiter could not be read.", exc_info=True)
        return False


# ------------------------------------------------------------------------------------------------ the CA
def _unavailable(reason: str):
    """The secret store's master_key_unavailable for a CA key that cannot be used. The reason goes to the log, never the key."""
    from .secret_store import SecretStoreError

    logger.error("The Console CA key cannot be used (%s). Nothing was signed. See docs/console-certificates.md.", reason)
    return SecretStoreError(
        "master_key_unavailable", "The Console certificate authority cannot use its key. An administrator must check the master key; see Troubleshooting.",
        503, reason=reason,
    )


def _spki_der(public_key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def server_id_for(spki_der: bytes) -> str:
    """The first 16 bytes of the SHA-256 of the CA's public key (SPKI DER), as 32 hex characters."""
    return hashlib.sha256(spki_der).digest()[:16].hex()


def _build_ca_material(now: datetime):
    """A new CA key pair and its self-signed certificate. Returns (private key, cert DER, SPKI DER, server_id, not_before, not_after)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME)])
    not_before = now - timedelta(minutes=CLOCK_SKEW_MINUTES)
    not_after = now + timedelta(days=CA_VALID_DAYS)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    spki = _spki_der(key.public_key())
    return key, certificate.public_bytes(serialization.Encoding.DER), spki, server_id_for(spki), not_before, not_after


def _new_ca_row(master_key: bytes, now: datetime, created_by):
    """Make the key pair and the unsaved CA row with the key encrypted. The private key lives only in this function's locals."""
    from cryptography.hazmat.primitives import serialization

    store = _store()
    key, cert_der, spki, server_id, not_before, not_after = _build_ca_material(now)
    plain = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    blob = store._encrypt(master_key, store._Scope(SCOPE_NAME), f"ca-key:{server_id}", plain)
    return _models().TecTacConsoleCA(
        server_id=server_id, public_key_der=spki, cert_der=cert_der, key_blob=blob, key_id=store._key_id(master_key), not_before=not_before,
        not_after=not_after, state="active", created_by=created_by,
    )


def active_ca():
    return _models().TecTacConsoleCA.objects.filter(state="active").first()


def ensure_ca(actor=None):
    """The one active CA, made at the first issue. One transaction; a partial unique constraint allows one active CA, and the loser of a race
    re-reads the winner. A missing or unsafe master key raises master_key_unavailable before anything is made. ``actor`` is the person whose
    action made it (the row custom:console-ca-created is strict)."""
    from django.db import IntegrityError, transaction

    existing = active_ca()
    if existing is not None:
        return existing
    store = _store()
    master = store._load_master_key()  # raises master_key_unavailable
    now = _now()
    row = _new_ca_row(master, now, getattr(actor, "pk", None))
    try:
        with transaction.atomic():
            row.save(force_insert=True)
            _audit(actor if actor is not None else service_actor(), "custom:console-ca-created", "console_ca", row.server_id,
                   "The Engineer Console certificate authority was created.",
                   {"server_id": row.server_id, "not_after": row.not_after.isoformat(), "key_id": row.key_id})
    except IntegrityError:
        winner = active_ca()
        if winner is None:
            raise
        return winner
    return row


def replace_ca(user):
    """Retire the active CA, make a new one, revoke every active certificate of the old CA (reason ca_replaced), cancel every open enrolment
    and write one strict row with the counts. The old CA is kept, retired. Effective superusers only (the view checks). Since 1.18.53 every live
    tunnel session ends (ca_replaced) once the change is committed."""
    from django.db import transaction

    models = _models()
    store = _store()
    master = store._load_master_key()
    now = _now()
    new = _new_ca_row(master, now, getattr(user, "pk", None))
    with transaction.atomic():
        old = models.TecTacConsoleCA.objects.select_for_update().filter(state="active").first()
        if old is None:
            raise ConsoleCertError("ca_not_created", "There is no certificate authority to replace yet.", 409)
        old.state = "retired"
        old.retired_at = now
        old.retired_by = getattr(user, "pk", None)
        old.save(update_fields=["state", "retired_at", "retired_by"])
        new.save(force_insert=True)
        revoked = models.TecTacConsoleCertificate.objects.filter(ca=old, state="active").update(
            state="revoked", revoked_at=now, revoked_by=getattr(user, "pk", None), revoked_reason="ca_replaced")
        cancelled = models.TecTacConsoleEnrolment.objects.filter(state="open").update(state="cancelled", code_hash="", code_expires_at=None)
        _audit(user, "custom:console-ca-replaced", "console_ca", new.server_id, "The Engineer Console certificate authority was replaced.",
               {"old_server_id": old.server_id, "new_server_id": new.server_id, "revoked_certificates": revoked, "cancelled_enrolments": cancelled,
                "not_after": new.not_after.isoformat()})
        old_server_id = old.server_id
        _after_commit("ca_replaced", lambda: _tunnel().ca_replaced(old_server_id))
    return {"server_id": new.server_id, "old_server_id": old.server_id, "not_after": new.not_after, "revoked_certificates": revoked,
            "cancelled_enrolments": cancelled}


def _with_ca_key(ca, use):
    """Call ``use(private key)`` and return its result. The key is decrypted here, in memory, and goes out of scope when this returns. It is the
    only place the CA key is decrypted: ``_sign`` (certificates) and ``sign_server_proof`` (the tunnel connect) both go through it."""
    from cryptography.hazmat.primitives import serialization

    store = _store()
    master = store._load_master_key()
    try:
        if ca.key_id != store._key_id(master):
            raise ValueError("key id differs")
        plain = store._decrypt(master, store._Scope(SCOPE_NAME), f"ca-key:{ca.server_id}", bytes(ca.key_blob))
        key = serialization.load_der_private_key(plain, password=None)
        return use(key)
    except Exception:
        raise _unavailable("ca_key_unreadable") from None


def _sign(ca, builder):
    """Sign a certificate builder with the CA key."""
    from cryptography.hazmat.primitives import hashes

    return _with_ca_key(ca, lambda key: builder.sign(key, hashes.SHA256()))


# ------------------------------------------------------------------------------------------------ certificates
def _ascii_cn(username: str) -> str:
    """The certificate's common name: the username cut to 64 characters (and 64 bytes). The row keeps the full name."""
    text = (username or "").strip() or "engineer"
    while len(text) > 64 or len(text.encode("utf-8")) > 64:
        text = text[:-1]
    return text or "engineer"


def normalise_pc_label(value) -> str | None:
    """NFC, trimmed, 1 to 64 characters, no control or format characters. ``None`` when it does not qualify."""
    if not isinstance(value, str):
        return None
    label = unicodedata.normalize("NFC", value).strip()
    if not label or len(label) > MAX_PC_LABEL or any(unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp") for ch in label):
        return None
    return label


def load_public_key(text):
    """The engineer's key from base64url (no padding) of SPKI DER. Returns (public key, DER, sha256 hex) or ``None``.

    It must load as a P-256 point and re-encode to the same bytes (so: no trailing data, uncompressed form, no odd parameters)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    der = b64u_decode(text, max_chars=300)
    if der is None:
        return None
    try:
        key = serialization.load_der_public_key(der)
    except Exception:
        return None
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        return None
    if _spki_der(key) != der:
        return None
    return key, der, hashlib.sha256(der).hexdigest()


def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("ascii")).hexdigest()


def proof_message(host: str, code: str, spki_sha256_hex: str) -> bytes:
    """The exact bytes the Console signs: no trailing newline, host lower case without a port."""
    return PROOF_PREFIX + f"host={host}\ncode={code_hash(code)}\nkey={spki_sha256_hex}".encode("ascii")


def verify_proof(public_key, host: str, code: str, spki_sha256_hex: str, proof_text) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    raw = b64u_decode(proof_text, max_chars=100)
    if raw is None or len(raw) != 64:
        return False
    signature = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        public_key.verify(signature, proof_message(host, code, spki_sha256_hex), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    except Exception:
        return False
    return True


def _cert_state(cert, now) -> str:
    if cert.state == "revoked":
        return "revoked"
    return "expired" if cert.not_after <= now else "active"


def _active_unexpired(user_id: int, now):
    return _models().TecTacConsoleCertificate.objects.filter(user_id=user_id, state="active", not_after__gt=now)


def check_certificate_limit(user_id: int, pc_label: str, now) -> None:
    """Refuse a 4th active certificate. A certificate for the same PC label (exact, case-insensitive) is replaced, so it is not counted."""
    count = _active_unexpired(user_id, now).exclude(pc_label__iexact=pc_label).count()
    if count >= MAX_ACTIVE_CERTIFICATES:
        raise ConsoleCertError("certificate_limit", f"This engineer already has {MAX_ACTIVE_CERTIFICATES} active Console certificates. Revoke one first.", 409)


def _revoke_row(cert, by, reason: str, now, actor, extra: dict | None = None) -> bool:
    """Revoke one active certificate (conditional update, strict audit row). Must run inside a transaction. True when this call revoked it."""
    models = _models()
    changed = models.TecTacConsoleCertificate.objects.filter(pk=cert.pk, state="active").update(
        state="revoked", revoked_at=now, revoked_by=by, revoked_reason=reason)
    if changed != 1:
        return False
    metadata = {"serial": cert.serial, "spki_sha256": cert.spki_sha256, "pc_label": cert.pc_label, "engineer_id": cert.user_id,
                "username": cert.username_snapshot, "reason": reason}
    if extra:
        metadata.update(extra)
    _audit(actor, "custom:console-cert-revoked", "console_certificate", cert.serial, "An Engineer Console certificate was revoked.", metadata)
    serial = cert.serial
    _after_commit("certificate_revoked", lambda: _tunnel().certificate_revoked(serial))
    return True


def issue_certificate(ca, *, user_id: int, username: str, spki_der: bytes, spki_sha256: str, pc_label: str, actor, now=None,
                      validity_days: int | None = None, ip: str = ""):
    """Sign and store one certificate. Run it inside the caller's transaction: it opens its own (nested) one, and every strict audit row
    belongs to the same unit, so no row means no certificate. Returns (row, cert DER).

    The database row is the authority and the CA signature the second lock: there is no CRL and no OCSP."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from django.db import transaction

    models = _models()
    now = now or _now()
    if validity_days is None:
        from .runtime_settings import get_console_certificate_validity_days

        validity_days = get_console_certificate_validity_days()
    not_after = min(now + timedelta(days=validity_days), ca.not_after - timedelta(days=CA_SAFETY_DAYS))
    if not_after <= now:
        raise ConsoleCertError("ca_expired", "The Console certificate authority has expired. An administrator must replace it.", 503)
    not_before = now - timedelta(minutes=CLOCK_SKEW_MINUTES)
    public_key = serialization.load_der_public_key(spki_der)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ConsoleCertError("key_invalid", "The public key is not usable.", 400)
    serial_int = 0
    while serial_int == 0:
        serial_int = int.from_bytes(os.urandom(16), "big") & ((1 << 127) - 1)  # 16 random bytes with the top bit cleared: a positive number
    serial = format(serial_int, "032x")
    ca_cert = x509.load_der_x509_certificate(bytes(ca.cert_der))
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _ascii_cn(username))]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial_int)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(f"{SERVER_URI}{ca.server_id}"),
            x509.UniformResourceIdentifier(f"{ENGINEER_URI}{user_id}"),
        ]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    certificate = _sign(ca, builder)
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    with transaction.atomic():
        replaced = list(models.TecTacConsoleCertificate.objects.filter(user_id=user_id, state="active", pc_label__iexact=pc_label))
        for older in replaced:
            _revoke_row(older, user_id, "replaced", now, actor, {"replaced_by_serial": serial, "ip": ip})
        check_certificate_limit(user_id, pc_label, now)
        row = models.TecTacConsoleCertificate.objects.create(
            serial=serial, ca=ca, user_id=user_id, username_snapshot=(username or "")[:150], pc_label=pc_label, spki_sha256=spki_sha256,
            cert_der=cert_der, not_before=not_before, not_after=not_after, state="active")
        _audit(actor, "custom:console-cert-issued", "console_certificate", serial, "An Engineer Console certificate was issued.",
               {"serial": serial, "spki_sha256": spki_sha256, "pc_label": pc_label, "not_after": not_after.isoformat(), "engineer_id": user_id,
                "username": username, "ip": ip, "replaced": len(replaced)})
    return row, cert_der


# ------------------------------------------------------------------------------------------------ accounts
def account_problem(user) -> str | None:
    """Why this account may not hold a Console certificate, or ``None``: inactive, blocked from the dashboard, or an installer user."""
    if user is None or getattr(user, "is_active", False) is not True:
        return "account_inactive"
    if bool(getattr(user, "block_dashboard_login", False)) or bool(getattr(user, "is_installer_user", False)):
        return "account_inactive"
    return None


def _find_user(user_id):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.filter(pk=user_id).first()


# ------------------------------------------------------------------------------------------------ enrolment
def authorise(actor, user_id, ip: str = "") -> dict:
    """An administrator lets one engineer enrol a Console PC. One open enrolment per engineer, valid 7 days; issuing again cancels the old
    open row and inserts a new one in one transaction. The administrator never sees a code."""
    from django.db import IntegrityError, transaction

    models = _models()
    user = _find_user(user_id)
    if user is None:
        raise ConsoleCertError("user_not_found", "No such person.", 404)
    if account_problem(user):
        raise ConsoleCertError("account_inactive", "That account is inactive, blocked or an installer account.", 409)
    ensure_ca(actor)
    now = _now()
    try:
        with transaction.atomic():
            models.TecTacConsoleEnrolment.objects.filter(user_id=user.pk, state="open", expires_at__lte=now).update(
                state="expired", code_hash="", code_expires_at=None)
            cancelled = models.TecTacConsoleEnrolment.objects.filter(user_id=user.pk, state="open").update(
                state="cancelled", code_hash="", code_expires_at=None)
            row = models.TecTacConsoleEnrolment.objects.create(user_id=user.pk, authorised_by=getattr(actor, "pk", 0) or 0,
                                                               expires_at=now + timedelta(days=ENROLMENT_DAYS))
            _audit(actor, "custom:console-cert-issue-authorised", "console_certificate", str(row.id),
                   "An administrator allowed an engineer to enrol a Console.",
                   {"enrolment_id": str(row.id), "engineer_id": user.pk, "username": user.get_username(), "authorised_by": getattr(actor, "pk", None),
                    "expires_at": row.expires_at.isoformat(), "cancelled_previous": cancelled, "ip": ip})
    except IntegrityError:
        raise ConsoleCertError("enrolment_conflict", "Another change to this engineer's enrolment ran at the same time. Try again.", 409) from None
    return {"id": str(row.id), "engineer_id": user.pk, "username": user.get_username(), "authorised_at": row.authorised_at, "expires_at": row.expires_at}


def cancel_enrolment(actor, enrolment_id) -> dict:
    from django.db import transaction

    models = _models()
    now = _now()
    row = models.TecTacConsoleEnrolment.objects.filter(pk=enrolment_id).first()
    if row is None:
        raise ConsoleCertError("enrolment_not_found", "No such enrolment.", 404)
    with transaction.atomic():
        changed = models.TecTacConsoleEnrolment.objects.filter(pk=row.pk, state="open", expires_at__gt=now).update(
            state="cancelled", code_hash="", code_expires_at=None)
        if changed != 1:
            raise ConsoleCertError("enrolment_not_open", "This enrolment is no longer open.", 409)
        _audit(actor, "custom:console-cert-enrolment-cancelled", "console_certificate", str(row.id), "An Engineer Console enrolment was cancelled.",
               {"enrolment_id": str(row.id), "engineer_id": row.user_id, "cancelled_by": getattr(actor, "pk", None)})
    return {"id": str(row.id), "engineer_id": row.user_id, "state": "cancelled"}


def create_enrolment_code(user, host: str | None, ip: str = "") -> dict:
    """A one-time code for the signed-in engineer's own open enrolment. Only its SHA-256 is stored; a new code voids the old one."""
    models = _models()
    store = _store()
    store._load_master_key()  # first: a missing or unsafe key is a fault, whatever else is true
    if host is None:
        raise ConsoleCertError("host_unusable", "This address cannot be used for a Console link. Open Tec-Tac on its normal address.", 400)
    now = _now()
    ca = active_ca()
    enrolment = models.TecTacConsoleEnrolment.objects.filter(user_id=user.pk, state="open", expires_at__gt=now).first()
    if enrolment is None or ca is None:
        raise ConsoleCertError("enrolment_required", "Ask your administrator to issue you a Console certificate.", 409)
    code = secrets.token_urlsafe(32)
    code_expires = now + timedelta(minutes=CODE_MINUTES)
    changed = models.TecTacConsoleEnrolment.objects.filter(pk=enrolment.pk, state="open", expires_at__gt=now).update(
        code_hash=code_hash(code), code_expires_at=code_expires)
    if changed != 1:
        raise ConsoleCertError("enrolment_required", "Ask your administrator to issue you a Console certificate.", 409)
    _audit(user, "custom:console-cert-enrol-code", "console_certificate", str(enrolment.id), "An engineer asked for a Console enrolment code.",
           {"enrolment_id": str(enrolment.id), "engineer_id": user.pk, "code_expires_at": code_expires.isoformat(), "ip": ip}, strict=False)
    return {"code": code, "code_expires_at": code_expires, "expires_in_seconds": CODE_MINUTES * 60, "host": host, "server_id": ca.server_id,
            "enrolment_id": str(enrolment.id)}


def parse_enrol_request(authorization, raw: bytes, content_length) -> tuple[str, dict]:
    """The code from the header and the checked body fields. Raises ConsoleCertError: a bad header is the same 401 as an unknown code."""
    invalid = ConsoleCertError("code_invalid", "The enrolment code is not valid.", 401)
    if not isinstance(authorization, str) or not authorization.startswith("Enrol ") or "," in authorization:
        raise invalid
    code = authorization[len("Enrol "):]
    if not CODE_PATTERN.fullmatch(code):
        raise invalid
    try:
        declared = int(content_length) if content_length not in (None, "") else 0
    except (TypeError, ValueError):
        declared = 0
    if declared > MAX_BODY_BYTES or len(raw) > MAX_BODY_BYTES:
        raise ConsoleCertError("body_too_large", "The request is too large.", 413)
    import json

    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ConsoleCertError("invalid_request", "The body must be a JSON object.", 400) from None
    if not isinstance(body, dict) or set(body) != ENROL_KEYS:
        raise ConsoleCertError("invalid_request", "The body must hold exactly v, public_key, pc_label and proof.", 400)
    if body["v"] != 1 or isinstance(body["v"], bool):
        raise ConsoleCertError("invalid_request", "Unsupported version.", 400)
    if not all(isinstance(body[key], str) for key in ("public_key", "pc_label", "proof")):
        raise ConsoleCertError("invalid_request", "public_key, pc_label and proof must be text.", 400)
    label = normalise_pc_label(body["pc_label"])
    if label is None:
        raise ConsoleCertError("invalid_request", "pc_label must be 1 to 64 plain characters.", 400)
    return code, {"public_key": body["public_key"], "pc_label": label, "proof": body["proof"]}


def _refuse(ip: str, code: str, message: str, status: int, enrolment=None, *, retry_after: int | None = None):
    """Count a failure, write at most one non-strict row per address per minute (reason and address only) and return the error."""
    note_failure(ip)
    if _refusal_row_due(ip):
        _audit(service_actor(), "custom:console-cert-enrol-refused", "console_certificate", str(enrolment.id) if enrolment is not None else None,
               "An Engineer Console enrolment was refused.", {"reason": code, "ip": ip}, strict=False, refusal=True)
    error = ConsoleCertError(code, message, status, retry_after=retry_after)
    error.counted = True
    return error


def refuse_early(ip: str, error: ConsoleCertError) -> ConsoleCertError:
    """A refusal before the code was looked at (a bad header or body): the same counting and at-most-one row per minute as the rest."""
    return _refuse(ip, error.code, error.message, error.status_code)


def enrol(*, code: str, host: str | None, fields: dict, ip: str) -> dict:
    """Redeem a code: the proof check, then the certificate. Every check fails closed. The code works once: one atomic update clears it
    before any other check, so a later refusal leaves the 7-day enrolment open but the code gone."""
    from django.db import transaction

    from .secret_store import SecretStoreError

    models = _models()
    now = _now()
    digest = code_hash(code)
    candidate = models.TecTacConsoleEnrolment.objects.filter(code_hash=digest, state="open").first()
    taken = 0
    if candidate is not None:
        taken = models.TecTacConsoleEnrolment.objects.filter(
            pk=candidate.pk, code_hash=digest, state="open", expires_at__gt=now, code_expires_at__gt=now,
        ).update(code_hash="", code_expires_at=None)
    if candidate is None or taken != 1:
        raise _refuse(ip, "code_invalid", "The enrolment code is not valid.", 401)
    enrolment = candidate  # from here the code is burnt; every refusal below carries its own reason
    user = _find_user(enrolment.user_id)
    if account_problem(user):
        raise _refuse(ip, "account_inactive", "This account may not hold a Console certificate.", 403, enrolment)
    try:
        check_certificate_limit(user.pk, fields["pc_label"], now)
    except ConsoleCertError as exc:
        raise _refuse(ip, exc.code, exc.message, exc.status_code, enrolment) from None
    loaded = load_public_key(fields["public_key"])
    if loaded is None:
        raise _refuse(ip, "key_invalid", "The public key must be an uncompressed P-256 key (base64url of SPKI DER).", 400, enrolment)
    public_key, spki_der, spki_sha256 = loaded
    if host is None:
        raise _refuse(ip, "host_unusable", "This address cannot be used for a Console certificate.", 400, enrolment)
    if not verify_proof(public_key, host, code, spki_sha256, fields["proof"]):
        raise _refuse(ip, "proof_invalid", "The proof of possession is not valid.", 400, enrolment)
    try:
        ca = active_ca()
        if ca is None:
            raise _refuse(ip, "ca_unavailable", "The Console certificate authority is not ready.", 503, enrolment)
        with transaction.atomic():
            row, cert_der = issue_certificate(
                ca, user_id=user.pk, username=user.get_username(), spki_der=spki_der, spki_sha256=spki_sha256, pc_label=fields["pc_label"],
                actor=service_actor(), now=now, ip=ip)
            used = models.TecTacConsoleEnrolment.objects.filter(pk=enrolment.pk, state="open").update(state="used", used_serial=row.serial)
            if used != 1:  # cancelled or replaced while this call ran: nothing is issued
                raise ConsoleCertError("code_invalid", "The enrolment code is not valid.", 401)
    except ConsoleCertError as exc:
        if exc.counted:
            raise
        raise _refuse(ip, exc.code, exc.message, exc.status_code, enrolment) from None
    except SecretStoreError:
        raise _refuse(ip, "master_key_unavailable", "The Console certificate authority cannot use its key.", 503, enrolment) from None
    except Exception as exc:
        from .audit import AuditWriteError

        if isinstance(exc, AuditWriteError):
            raise _refuse(ip, "audit_failed", "The change could not be recorded, so it was not made.", 503, enrolment) from None
        raise
    return {
        "v": 1, "host": host, "server_id": ca.server_id, "ca_public_key": b64u(bytes(ca.public_key_der)), "ca_cert": b64u(bytes(ca.cert_der)),
        "cert": b64u(cert_der), "serial": row.serial, "not_after": row.not_after.isoformat(),
        "engineer": {"id": user.pk, "username": user.get_username()},
    }


# ------------------------------------------------------------------------------------------------ revoke
def revoke(actor, serial: str, reason: str, *, can_manage: bool) -> dict:
    """Revoke one certificate. A manager may revoke any; the owner may revoke their own. Already revoked answers without a new row."""
    from django.db import transaction

    models = _models()
    cert = models.TecTacConsoleCertificate.objects.filter(serial=serial).first()
    if cert is None:
        if can_manage:
            raise ConsoleCertError("certificate_not_found", "No such certificate.", 404)
        deny(actor, "console_certificate", serial)
        raise ConsoleCertError("permission_required", "You may only revoke your own Console certificates.", 403)
    if not can_manage and cert.user_id != getattr(actor, "pk", None):
        deny(actor, "console_certificate", serial)
        raise ConsoleCertError("permission_required", "You may only revoke your own Console certificates.", 403)
    now = _now()
    with transaction.atomic():
        changed = _revoke_row(cert, getattr(actor, "pk", None), reason, now, actor)
    cert.refresh_from_db()
    return {"serial": cert.serial, "state": _cert_state(cert, now), "revoked_reason": cert.revoked_reason, "changed": changed}


# ------------------------------------------------------------------------------------------------ answers for the routes
def _iso(value):
    return value.isoformat() if value else None


def _usernames(ids) -> dict:
    ids = {i for i in ids if isinstance(i, int)}
    if not ids:
        return {}
    from django.contrib.auth import get_user_model

    User = get_user_model()
    return {u.pk: u.get_username() for u in User.objects.filter(pk__in=ids)}


def serialise_certificate(cert, now) -> dict:
    state = _cert_state(cert, now)
    return {
        "serial": cert.serial,
        "short_serial": cert.serial[:8],
        "pc_label": cert.pc_label,
        "username": cert.username_snapshot,
        "engineer_id": cert.user_id,
        "issued_at": _iso(cert.created_at),
        "not_after": _iso(cert.not_after),
        "state": state,
        "expiring": state == "active" and cert.not_after - now <= timedelta(days=EXPIRING_CERTIFICATE_DAYS),
        "revoked_at": _iso(cert.revoked_at),
        "revoked_reason": cert.revoked_reason or None,
        "last_used_at": _iso(cert.last_used_at),
    }


def serialise_enrolment(row, now, names: dict | None = None) -> dict:
    names = names or {}
    return {
        "id": str(row.id),
        "engineer_id": row.user_id,
        "username": names.get(row.user_id, ""),
        "authorised_by": row.authorised_by,
        "authorised_by_username": names.get(row.authorised_by, ""),
        "authorised_at": _iso(row.authorised_at),
        "expires_at": _iso(row.expires_at),
        "state": "expired" if row.state == "open" and row.expires_at <= now else row.state,
        "code_active": bool(row.code_hash) and bool(row.code_expires_at) and row.code_expires_at > now,
    }


def open_enrolments(now, *, user_id: int | None = None):
    rows = _models().TecTacConsoleEnrolment.objects.filter(state="open", expires_at__gt=now)
    if user_id is not None:
        rows = rows.filter(user_id=user_id)
    return list(rows.order_by("-authorised_at")[:MAX_ENROLMENTS_LISTED])


def overview_for(user, host: str | None) -> dict:
    """GET mine/: the signed-in person's own certificates and open enrolment."""
    from .runtime_settings import get_console_certificate_validity_days

    models = _models()
    now = _now()
    certs = models.TecTacConsoleCertificate.objects.filter(user_id=user.pk).order_by("-created_at")[:100]
    enrolments = open_enrolments(now, user_id=user.pk)
    ca = active_ca()
    return {
        "certificates": [serialise_certificate(c, now) for c in certs],
        "enrolment": serialise_enrolment(enrolments[0], now, {user.pk: user.get_username()}) if enrolments else None,
        "host": host,
        "server_id": ca.server_id if ca is not None else None,
        "validity_days": get_console_certificate_validity_days(),
    }


def list_for(viewer, *, can_view: bool, engineer=None, state=None, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> dict:
    """GET /: own rows for everyone, every row for a viewer. Filters: engineer (a user id), state. Pages of 50, at most 100."""
    models = _models()
    now = _now()
    rows = models.TecTacConsoleCertificate.objects.all()
    own_only = not can_view
    if own_only:
        rows = rows.filter(user_id=viewer.pk)
        if engineer is not None and engineer != viewer.pk:
            rows = rows.none()
    elif engineer is not None:
        rows = rows.filter(user_id=engineer)
    if state == "active":
        rows = rows.filter(state="active", not_after__gt=now)
    elif state == "expired":
        rows = rows.filter(state="active", not_after__lte=now)
    elif state == "revoked":
        rows = rows.filter(state="revoked")
    page = max(1, page)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    count = rows.count()
    chunk = list(rows.order_by("-created_at", "-id")[(page - 1) * page_size: page * page_size])
    enrolment_rows = open_enrolments(now, user_id=viewer.pk if own_only else None)
    names = _usernames([r.user_id for r in enrolment_rows] + [r.authorised_by for r in enrolment_rows])
    return {
        "count": count, "page": page, "page_size": page_size,
        "results": [serialise_certificate(c, now) for c in chunk],
        "enrolments": [serialise_enrolment(r, now, names) for r in enrolment_rows],
    }


def master_key_available() -> bool:
    from .secret_store import SecretStoreError

    try:
        _store()._load_master_key()
        return True
    except SecretStoreError:
        return False
    except Exception:
        return False


def ca_status() -> dict:
    """GET ca/: whether a CA exists and when it ends. Never key material."""
    models = _models()
    now = _now()
    ca = active_ca()
    out = {"exists": ca is not None, "server_id": None, "not_before": None, "not_after": None, "expires_in_days": None, "expiring": False,
           "active_certificates": 0, "retired_cas": models.TecTacConsoleCA.objects.filter(state="retired").count(),
           "master_key_available": master_key_available()}
    if ca is not None:
        days = (ca.not_after - now).days
        out.update({
            "server_id": ca.server_id, "not_before": _iso(ca.not_before), "not_after": _iso(ca.not_after), "expires_in_days": days,
            "expiring": days <= EXPIRING_CA_DAYS,
            "active_certificates": models.TecTacConsoleCertificate.objects.filter(ca=ca, state="active", not_after__gt=now).count(),
        })
    return out



# ------------------------------------------------------------------------------------------------ the tunnel connect (1.18.53, C4)
class ConnectRefused(ConsoleCertError):
    """A refused tunnel connect. ``code`` is one of CERT_REASONS (the websocket close text). ``serial`` is set when the certificate parsed to a
    32 hex serial, for the refusal row."""

    def __init__(self, code: str, serial: str | None = None):
        super().__init__(code, code, 401)
        self.serial = serial


def ticket_hash(ticket: str) -> str:
    """SHA-256 of the 43 ASCII ticket characters, lower-case hex. The only form of a ticket that reaches a message."""
    return hashlib.sha256(str(ticket).encode("ascii")).hexdigest()


def connect_message(host: str, server_id: str, ticket: str, serial: str, time_text: str, nonce: str) -> bytes:
    """The exact bytes the Console signs on a tunnel connect: lines joined by one LF, no trailing LF."""
    return CONNECT_PREFIX + f"host={host}\nserver={server_id}\nticket={ticket_hash(ticket)}\nserial={serial}\ntime={time_text}\nnonce={nonce}".encode("ascii")


def server_proof_message(host: str, server_id: str, ticket: str, serial: str, nonce: str) -> bytes:
    """The exact bytes Core signs with the CA key and sends back in X-Tectac-Server-Proof."""
    return SERVER_PROOF_PREFIX + f"host={host}\nserver={server_id}\nticket={ticket_hash(ticket)}\nserial={serial}\nnonce={nonce}".encode("ascii")


def _p1363(der_signature: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify_p1363(public_key, raw: bytes, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    if len(raw) != 64:
        return False
    try:
        public_key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")), message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_connect(cert_der, proof: dict, ticket: str, host, user_id: int, now=None) -> dict:
    """Every certificate check of one Console connect, in the documented order. ``proof`` is {time, nonce, sig} as the headers carried them
    (shape already checked). Raises ConnectRefused(reason) for a refusal; a database fault is raised as it is (the caller answers 1013).
    Returns {serial, not_after (epoch seconds), server_id, ca}: ``ca`` is the active CA row, for ``sign_server_proof``."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec

    now = now or _now()
    if abs(now.timestamp() - int(proof["time"])) > PROOF_WINDOW_SECONDS:
        raise ConnectRefused("proof_stale")
    der = bytes(cert_der)
    try:
        cert = x509.load_der_x509_certificate(der)
        serial = format(cert.serial_number, "032x")
    except (ValueError, TypeError):
        raise ConnectRefused("certificate_invalid") from None
    known = serial if SERIAL_PATTERN.fullmatch(serial) else None
    ca = active_ca()
    if ca is None:
        raise ConnectRefused("certificate_invalid", known)
    try:
        ca_cert = x509.load_der_x509_certificate(bytes(ca.cert_der))
        if cert.issuer != ca_cert.subject:
            raise ValueError("issuer")
        ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        public_key = cert.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
            raise TypeError("key")
        spki_hash = hashlib.sha256(_spki_der(public_key)).hexdigest()
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError):
        raise ConnectRefused("certificate_invalid", known) from None
    row = _models().TecTacConsoleCertificate.objects.filter(serial=known).first() if known else None
    if row is None or bytes(row.cert_der) != der or row.spki_sha256 != spki_hash or row.ca_id != ca.pk:
        raise ConnectRefused("certificate_invalid", known)
    if row.state == "revoked":
        raise ConnectRefused("certificate_revoked", known)
    if row.not_after <= now:
        raise ConnectRefused("certificate_expired", known)
    if row.not_before > now:
        raise ConnectRefused("certificate_invalid", known)
    if row.user_id != user_id:
        raise ConnectRefused("certificate_engineer_mismatch", known)
    signature = b64u_decode(proof["sig"], max_chars=100)
    if not isinstance(host, str) or not HOST_PATTERN.fullmatch(host) or signature is None:
        raise ConnectRefused("proof_invalid", known)
    if not _verify_p1363(public_key, signature, connect_message(host, ca.server_id, ticket, serial, proof["time"], proof["nonce"])):
        raise ConnectRefused("proof_invalid", known)
    return {"serial": serial, "not_after": row.not_after.timestamp(), "server_id": ca.server_id, "ca": ca}


def sign_server_proof(verified: dict, host: str, ticket: str, nonce: str) -> str:
    """The value of X-Tectac-Server-Proof: ``v1.`` and base64url of the 64-byte r||s signature of the CA key. The key is decrypted inside
    ``_with_ca_key`` only. An unreadable master key raises the secret store's master_key_unavailable."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    message = server_proof_message(host, verified["server_id"], ticket, verified["serial"], nonce)
    raw = _with_ca_key(verified["ca"], lambda key: _p1363(key.sign(message, ec.ECDSA(hashes.SHA256()))))
    return "v1." + b64u(raw)


def touch_last_used(serial: str, now=None) -> None:
    """Fill ``last_used_at`` at most once an hour: one conditional UPDATE. A fault is logged and never fatal."""
    from django.db.models import Q

    now = now or _now()
    try:
        _models().TecTacConsoleCertificate.objects.filter(serial=serial).filter(
            Q(last_used_at__isnull=True) | Q(last_used_at__lt=now - timedelta(seconds=LAST_USED_SECONDS))).update(last_used_at=now)
    except Exception:
        logger.warning("The Console certificate last-used time could not be written.", exc_info=True)


def has_usable_certificate(user_id: int, now=None) -> bool:
    """True when the person holds at least one active, unexpired certificate of the active CA (one indexed read). A fault is raised."""
    now = now or _now()
    return _active_unexpired(user_id, now).filter(ca__state="active").exists()


def recheck(serial: str, now=None) -> str | None:
    """The 5-minute re-read of one certificate row: ``certificate_revoked`` when it is no longer active or its CA is no longer the active CA,
    ``certificate_expired`` past its end, else None. A fault is raised (the caller applies the re-check's fault rule)."""
    now = now or _now()
    row = _models().TecTacConsoleCertificate.objects.filter(serial=serial).select_related("ca").first()
    if row is None or row.state != "active" or row.ca.state != "active":
        return "certificate_revoked"
    if row.not_after <= now:
        return "certificate_expired"
    return None


def record_refusal(reason: str, ip: str, *, session_id=None, engineer_id=None, serial=None) -> bool:
    """The one non-strict ``custom:console-cert-refused`` row of a refused Console connect, at most one per address per minute. Holds a reason,
    the address, the session id, the engineer id and (only when it parsed to 32 hex) a serial. Never a ticket, a certificate, a proof or a
    header. Returns True when a row was written."""
    if not _refusal_row_due(ip):
        return False
    metadata = {"reason": reason, "ip": ip}
    if isinstance(session_id, str) and session_id:
        metadata["session_id"] = session_id[:64]
    if isinstance(engineer_id, int) and not isinstance(engineer_id, bool):
        metadata["engineer_id"] = engineer_id
    safe_serial = serial if isinstance(serial, str) and SERIAL_PATTERN.fullmatch(serial) else None
    if safe_serial:
        metadata["serial"] = safe_serial
    _audit(service_actor(), "custom:console-cert-refused", "console_certificate", safe_serial, "An Engineer Console connect was refused.", metadata,
           strict=False, refusal=True)
    return True


# ------------------------------------------------------------------------------------------------ API keys (1.18.53)
def interactive_session(request) -> bool:
    """True only for a person who signed in interactively: the request's auth is a Knox token with a digest, it was not made by Tactical's
    API-key authenticator and it carries no X-API-KEY header. Pure logic on the request (no session_security import). The enrolment-code,
    issue and CA-replace routes refuse everything else, so an API key can never start a Console enrolment."""
    auth = getattr(request, "auth", None)
    if auth is None or isinstance(auth, (str, bytes)) or not getattr(auth, "digest", None):
        return False
    authenticator = getattr(request, "successful_authenticator", None)
    if authenticator is not None:
        kind = type(authenticator)
        if kind.__name__ == "APIAuthentication" or getattr(kind, "__module__", "") == "tacticalrmm.auth":
            return False
    meta = getattr(request, "META", None) or {}
    return "HTTP_X_API_KEY" not in meta

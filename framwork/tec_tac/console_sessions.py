"""Engineer Console sessions (Core 1.18.56, C1 of the Engineer Console sign-in plan, signed 26 November 2026).

An engineer signs in to the Engineer Console from the Tec-Tac page in their browser. The Console never sees a password: the browser asks Core
for a one-time code (``authorise``), hands it to the Console over a loopback address, and the Console exchanges it for a session (``redeem``)
by proving it holds the private key of the certificate it enrolled with (docs/console-certificates.md). From then on every request carries
the Console's own token and a fresh signature of the request itself (``ConsoleSessionAuthentication``), so a copied token is useless without
the key, and a replayed request is refused.

A Console session is a normal Tec-Tac session. Core mints a Knox token (Tactical's own sign-in credential table) bound to it, keeps only its
digest and throws the token away, and makes the Tec-Tac session trust row that the browser sign-in makes, so idle time, the absolute limit,
the IP-change policy, the sweep and the administrator's "end this session" all apply to it unchanged. Every way the session can end also ends
the Console session and the live tunnels opened from it (``on_trust_revoked``, ``end_sessions``).

This file is logic and the Console's DRF authentication and permission. The routes are in ``console_session_views``. It imports Django models,
``cryptography``, Knox and the session guard lazily inside functions, so a fault there can never stop Tactical from starting (rule 1.13).
The exact bytes of every message are in docs/console-sessions.md and are pinned by tests/console-sessions-docs-1.18.56.py.

Never in a log line, an audit row, an exception text or an answer: a code, a verifier, a challenge, a Console token, the Knox token, a
ticket, a certificate, a proof, a signature or a header value.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import uuid
from datetime import timedelta

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import APIException, AuthenticationFailed
from rest_framework.permissions import BasePermission

from . import console_certificates as cc

logger = logging.getLogger("tec_tac.console_sessions")

CONSOLE_MIN_VERSION = "0.1.1"  # the oldest Engineer Console Core accepts; announced in every token and current answer
CAPABILITY_ID = "core.console_session"
CAPABILITY_VERSION = "1.0.0"
AUTH_SCHEME = "TecTacConsole"
CODE_SECONDS = 60
SIGNIN_KEEP_SECONDS = 3600
SIGNIN_CLEAN_LIMIT = 200
MAX_REQUEST_BODY = 64 * 1024
NONCE_PREFIX = "tec-tac:cs:nonce:"
NONCE_SECONDS = 300
LAST_USED_SECONDS = 60
MAX_END_BATCH = 1000
MIN_PORT, MAX_PORT = 1024, 65535
CERT_HEADER_MAX_CHARS = 2048
PROOF_HEADER_MAX_CHARS = 400

AUTH_PATTERN = re.compile(r"^TecTacConsole ([A-Za-z0-9_-]{43})$")
PROOF_PATTERN = re.compile(r"^v1\.([0-9]{1,12})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{86})$")
CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
VERSION_PATTERN = re.compile(r"^([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})$")

AUTHORISE_KEYS = frozenset({"serial", "code_challenge", "redirect_port"})
TOKEN_KEYS = frozenset({"v", "code", "code_verifier", "serial"})
TOKEN_OPTIONAL_KEYS = frozenset({"client_version"})

# every way a Console session ends (the reason column of core_console_session and the reason of custom:console-signout)
END_REASONS = ("engineer", "idle", "absolute", "certificate_revoked", "certificate_expired", "ca_replaced", "account_inactive", "admin", "ip_change",
               "replaced")
ENGINEER_TRUST_REASON = "console-engineer"  # the Tec-Tac session reason when the engineer signs out; every "console-<reason>" maps to <reason>


# ------------------------------------------------------------------------------------------------ small helpers
def _models():
    from . import models

    return models


def _ss():
    from . import session_security

    return session_security


def _tunnel():
    from . import probe_tunnel

    return probe_tunnel


def token_hash(token: str) -> str:
    """SHA-256 of the 43 ASCII characters of a Console token, lower-case hex. The only form of a token that is ever stored."""
    return hashlib.sha256(str(token).encode("ascii")).hexdigest()


def service_actor():
    from .audit import service_audit_actor

    return service_audit_actor(module_id="core", service="console-sessions")


def _audit(actor, action, object_id, message, metadata=None, *, strict=True, refusal=False):
    """One Core audit row of the Console sessions. Strict: raises AuditWriteError (no row means no change). Not strict: never raises."""
    from .audit import _record_console_sessions

    if strict:
        return _record_console_sessions(actor=actor, action=action, object_type="console_session", object_id=object_id, message=message,
                                        metadata=metadata, strict=True, refusal=refusal)
    try:
        return _record_console_sessions(actor=actor, action=action, object_type="console_session", object_id=object_id, message=message,
                                        metadata=metadata, strict=False, refusal=refusal)
    except Exception:
        logger.warning("A Console session audit row could not be written (%s).", action, exc_info=True)
        return None


def deny(actor, reason: str = "api_key_refused") -> None:
    """The non-strict Core ``deny`` row for a refused sign-in request (an API key or a plain Django session asked for a code). Never raises."""
    _audit(actor, "deny", None, "Blocked a Console sign-in request that needs a signed-in person.", {"reason": reason}, strict=False, refusal=True)


def version_tuple(text):
    match = VERSION_PATTERN.fullmatch(text) if isinstance(text, str) else None
    return tuple(int(part) for part in match.groups()) if match else None


# ------------------------------------------------------------------------------------------------ authorise (browser): a one-time code
def parse_authorise_body(data) -> dict:
    """The checked body of POST authorise/: exactly serial, code_challenge and redirect_port. Raises ConsoleCertError (400)."""
    if not isinstance(data, dict):
        raise cc.ConsoleCertError("invalid_request", "The body must be a JSON object.", 400)
    unknown = sorted(str(key) for key in data if key not in AUTHORISE_KEYS)
    if unknown:
        raise cc.ConsoleCertError("unknown_field", "Unknown field(s): " + ", ".join(unknown), 400)
    missing = sorted(AUTHORISE_KEYS - set(data))
    if missing:
        raise cc.ConsoleCertError("invalid_request", "Missing field(s): " + ", ".join(missing), 400)
    serial, challenge, port = data["serial"], data["code_challenge"], data["redirect_port"]
    if not isinstance(serial, str) or not cc.SERIAL_PATTERN.fullmatch(serial):
        raise cc.ConsoleCertError("invalid_request", "serial must be 32 lower-case hexadecimal characters.", 400)
    if not isinstance(challenge, str) or not CHALLENGE_PATTERN.fullmatch(challenge):
        raise cc.ConsoleCertError("invalid_request", "code_challenge must be 43 base64url characters (S256 of the verifier).", 400)
    if isinstance(port, bool) or not isinstance(port, int) or not (MIN_PORT <= port <= MAX_PORT):
        raise cc.ConsoleCertError("invalid_request", f"redirect_port must be a whole number from {MIN_PORT} to {MAX_PORT}.", 400)
    return {"serial": serial, "code_challenge": challenge, "redirect_port": port}


def _clean_signins(now) -> None:
    """Delete expired and used sign-in rows older than an hour, at most 200 a call. A fault is logged and never fatal."""
    from django.db.models import Q

    try:
        models = _models()
        cutoff = now - timedelta(seconds=SIGNIN_KEEP_SECONDS)
        ids = list(models.TecTacConsoleSignin.objects.filter(Q(expires_at__lt=cutoff) | Q(used_at__lt=cutoff)).values_list("pk", flat=True)[:SIGNIN_CLEAN_LIMIT])
        if ids:
            models.TecTacConsoleSignin.objects.filter(pk__in=ids).delete()
    except Exception:
        logger.warning("Old Console sign-in codes could not be deleted.", exc_info=True)


def authorise(user, body: dict, host) -> dict:
    """The one-time sign-in code for the signed-in engineer's own certificate. Order: the master key (the sign-in needs the CA key), the host,
    then the certificate: it must be an active, unexpired certificate of the ACTIVE CA owned by this person (anything else is one 403 body that
    does not say whether the serial exists). Only the SHA-256 of the code is stored."""
    models = _models()
    cc._store()._load_master_key()  # raises master_key_unavailable (503) first
    if host is None:
        raise cc.ConsoleCertError("host_unusable", "This address cannot be used for a Console link. Open Tec-Tac on its normal address.", 400)
    now = cc._now()
    certificate = models.TecTacConsoleCertificate.objects.filter(
        serial=body["serial"], user_id=user.pk, state="active", not_before__lte=now, not_after__gt=now, ca__state="active").select_related("ca").first()
    if certificate is None:
        raise cc.ConsoleCertError("serial_not_allowed", "That certificate cannot be used to sign in.", 403)
    _clean_signins(now)
    code = secrets.token_urlsafe(32)
    models.TecTacConsoleSignin.objects.create(
        code_hash=cc.code_hash(code), user_id=user.pk, serial=certificate.serial, code_challenge=body["code_challenge"],
        redirect_port=body["redirect_port"], host=host, expires_at=now + timedelta(seconds=CODE_SECONDS))
    return {"code": code, "expires_in": CODE_SECONDS, "host": host, "server_id": certificate.ca.server_id}


# ------------------------------------------------------------------------------------------------ redeem (the Console): the token
def parse_token_request(raw: bytes, declared) -> dict:
    """The checked body of POST token/: exactly v (1), code, code_verifier and serial, and optionally client_version. Raises ConsoleCertError."""
    try:
        length = int(declared) if declared not in (None, "") else 0
    except (TypeError, ValueError):
        length = 0
    if length > cc.MAX_BODY_BYTES or len(raw) > cc.MAX_BODY_BYTES:
        raise cc.ConsoleCertError("body_too_large", "The request is too large.", 413)
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise cc.ConsoleCertError("invalid_request", "The body must be a JSON object.", 400) from None
    if not isinstance(body, dict) or not TOKEN_KEYS <= set(body) or set(body) - TOKEN_KEYS - TOKEN_OPTIONAL_KEYS:
        raise cc.ConsoleCertError("invalid_request", "The body must hold exactly v, code, code_verifier and serial, and may hold client_version.", 400)
    if body["v"] != 1 or isinstance(body["v"], bool):
        raise cc.ConsoleCertError("invalid_request", "Unsupported version.", 400)
    code, verifier, serial = body["code"], body["code_verifier"], body["serial"]
    if not isinstance(code, str) or not cc.CODE_PATTERN.fullmatch(code):
        raise cc.ConsoleCertError("code_invalid", "The sign-in code is not valid.", 401)
    if not isinstance(verifier, str) or not CHALLENGE_PATTERN.fullmatch(verifier) or not isinstance(serial, str) or not cc.SERIAL_PATTERN.fullmatch(serial):
        raise cc.ConsoleCertError("invalid_request", "code_verifier must be 43 base64url characters and serial 32 lower-case hexadecimal characters.", 400)
    version = body.get("client_version")
    if "client_version" in body and version_tuple(version) is None:
        raise cc.ConsoleCertError("invalid_request", "client_version must look like 0.1.1.", 400)
    return {"code": code, "code_verifier": verifier, "serial": serial, "client_version": version}


def parse_credential_headers(cert_header, proof_header) -> tuple[bytes, dict]:
    """The certificate and the proof from their headers. Either missing is certificate_required; a bad shape is certificate_invalid or
    proof_invalid. Raises ConnectRefused."""
    if not isinstance(cert_header, str) or not cert_header or not isinstance(proof_header, str) or not proof_header:
        raise cc.ConnectRefused("certificate_required")
    der = cc.b64u_decode(cert_header, max_chars=CERT_HEADER_MAX_CHARS)
    if der is None:
        raise cc.ConnectRefused("certificate_invalid")
    proof = parse_proof(proof_header)
    if proof is None:
        raise cc.ConnectRefused("proof_invalid")
    return der, proof


def parse_proof(text) -> dict | None:
    """``v1.<time>.<nonce>.<sig>`` as {time, nonce, sig}, or None for any other shape (the signature is 64 bytes, canonical base64url)."""
    if not isinstance(text, str) or len(text) > PROOF_HEADER_MAX_CHARS:
        return None
    match = PROOF_PATTERN.fullmatch(text)
    if match is None:
        return None
    time_text, nonce, sig = match.groups()
    nonce_bytes = cc.b64u_decode(nonce, max_chars=22)
    if nonce_bytes is None or len(nonce_bytes) != 16:
        return None
    raw = cc.b64u_decode(sig, max_chars=86)
    if raw is None or len(raw) != 64:
        return None
    return {"time": time_text, "nonce": nonce, "sig": sig}


def _refuse_signin(ip: str, error, ctx: dict):
    """Count a refused sign-in against the address (its own counter), write at most one non-strict row per address per minute (reason, address
    and a serial that parsed to 32 hex) and return the error, marked as counted. The row sits under the engineer when the code matched,
    otherwise under the console-sessions service actor."""
    cc.note_failure(ip, cc.SIGNIN_FAILURE_PREFIX)
    if cc._refusal_row_due(ip, "signin"):
        metadata = {"reason": error.code, "ip": ip}
        serial = ctx.get("serial")
        if isinstance(serial, str) and cc.SERIAL_PATTERN.fullmatch(serial):
            metadata["serial"] = serial
        user = ctx.get("user")
        actor = service_actor()
        if user is not None:
            actor = cc.engineer_actor(user)
            metadata.update({"engineer_id": getattr(user, "pk", None), "username": str(getattr(user, "username", "") or "")[:150]})
        _audit(actor, "custom:console-signin-refused", metadata.get("serial"), "An Engineer Console sign-in was refused.", metadata, strict=False, refusal=True)
    counted = cc.ConsoleCertError(error.code, error.message, error.status_code, retry_after=getattr(error, "retry_after", None))
    counted.counted = True
    return counted


def redeem(request, *, raw: bytes, declared, cert_header, proof_header, host, ip: str) -> dict:
    """POST token/ after the transport checks (https only, the address failure limit): every check fails closed, in the documented order. The
    code is burnt from the moment it is taken, whatever follows. Raises ConsoleCertError (every refusal, counted), a SecretStoreError (the CA
    key cannot sign: 503) or AuditWriteError (the strict row could not be written: nothing was made)."""
    ctx: dict = {"serial": None, "user": None}
    try:
        return _redeem(request, raw, declared, cert_header, proof_header, host, ip, ctx)
    except cc.ConsoleCertError as exc:
        if exc.counted or exc.status_code >= 500:
            raise
        raise _refuse_signin(ip, exc, ctx) from None


def _redeem(request, raw, declared, cert_header, proof_header, host, ip, ctx):
    models = _models()
    now = cc._now()
    fields = parse_token_request(raw, declared)
    ctx["serial"] = fields["serial"]
    cert_der, proof = parse_credential_headers(cert_header, proof_header)
    wanted = version_tuple(fields["client_version"]) if fields["client_version"] is not None else None
    if wanted is not None and wanted < version_tuple(CONSOLE_MIN_VERSION):
        raise cc.ConsoleCertError("console_update_required", f"This Engineer Console is too old. Update it to {CONSOLE_MIN_VERSION} or newer.", 426)
    if host is None:
        raise cc.ConsoleCertError("host_unusable", "This address cannot be used for a Console sign-in.", 400)

    digest = cc.code_hash(fields["code"])
    taken = models.TecTacConsoleSignin.objects.filter(code_hash=digest, used_at__isnull=True, expires_at__gt=now).update(used_at=now)
    signin = models.TecTacConsoleSignin.objects.filter(code_hash=digest).first() if taken == 1 else None
    if signin is None:
        raise cc.ConsoleCertError("code_invalid", "The sign-in code is not valid.", 401)
    # from here the code is burnt: every refusal below carries its own reason
    ctx["serial"] = signin.serial
    user = cc._find_user(signin.user_id)
    ctx["user"] = user
    if signin.host != host:
        raise cc.ConsoleCertError("host_mismatch", "This sign-in code was made for another address.", 401)
    found = cc._certificate_row(cert_der, now)  # the shared certificate checks: parse, issuer, CA signature, row, active CA, state, expiry
    if found["row"].user_id != signin.user_id or found["serial"] != signin.serial or found["serial"] != fields["serial"]:
        raise cc.ConnectRefused("certificate_engineer_mismatch", found["serial"])
    expected = cc.b64u(hashlib.sha256(fields["code_verifier"].encode("ascii")).digest())
    if not hmac.compare_digest(expected, signin.code_challenge):
        raise cc.ConsoleCertError("verifier_invalid", "The sign-in code does not match its verifier.", 401)
    if abs(now.timestamp() - int(proof["time"])) > cc.PROOF_WINDOW_SECONDS:
        raise cc.ConnectRefused("proof_stale", found["serial"])
    signature = cc.b64u_decode(proof["sig"], max_chars=100)
    message = cc.signin_message(host, found["ca"].server_id, fields["code"], fields["code_verifier"], found["serial"], proof["time"], proof["nonce"])
    if signature is None or not cc._verify_p1363(found["public_key"], signature, message):
        raise cc.ConnectRefused("proof_invalid", found["serial"])
    if cc.account_problem(user):
        raise cc.ConsoleCertError("account_inactive", "This account may not use the Engineer Console.", 403)
    return _create_session(request, user, signin, found, fields, proof, host, ip)


def _create_session(request, user, signin, found, fields, proof, host, ip) -> dict:
    """One transaction: end the older Console session of this PC, mint the Knox token (only its digest is kept), make the Tec-Tac session and the
    Console session, write the strict audit rows and sign the server proof. A fault anywhere rolls all of it back: no row, no session."""
    from django.db import transaction
    from knox.models import AuthToken

    ss = _ss()
    models = _models()
    now = cc._now()
    ca, certificate = found["ca"], found["row"]
    policy = ss.get_effective_policy(user, request)
    lifetime = timedelta(minutes=int(policy["absolute_lifetime_minutes"]))
    console_id = uuid.uuid4()
    console_token = secrets.token_urlsafe(32)
    with transaction.atomic():
        end_sessions(serial=found["serial"], reason="replaced")
        created = AuthToken.objects.create(user=user, expiry=lifetime)  # (instance, raw token): the raw token is never kept
        digest = str(created[0].digest)
        absolute_at = created[0].expiry or (now + lifetime)
        del created
        client_ip = ss.effective_client_ip(request, policy=policy)
        trust = models.TecTacSessionTrust.objects.create(
            user=user, username=str(user.get_username()), token_fingerprint=ss._fingerprint_for_identity(f"console:{console_id}"), knox_digest=digest,
            last_activity_at=now, last_seen_at=now, initial_ip=client_ip, last_ip=client_ip, user_agent_hash=ss.user_agent_hash(request),
            absolute_expires_at=absolute_at, idle_expires_at=now + timedelta(minutes=int(policy["idle_timeout_minutes"])))
        browser_method = ss._session_created_auth_metadata(user)
        session_meta = {"auth_method": "console", "browser_auth_method": browser_method.get("auth_method", ""), "serial": found["serial"]}
        if browser_method.get("provider"):
            session_meta["provider"] = browser_method["provider"]
        ss._audit("session_created", session=trust, new_ip=client_ip, metadata=session_meta, policy=policy, force=True)
        models.TecTacConsoleSession.objects.create(
            id=console_id, user_id=user.pk, trust_id=trust.pk, token_hash=token_hash(console_token), serial=found["serial"], pc_label=certificate.pc_label)
        _audit(user, "custom:console-signin", str(console_id), "An Engineer Console signed in.",
               {"console_session_id": str(console_id), "serial": found["serial"], "pc_label": certificate.pc_label, "engineer_id": user.pk,
                "username": str(user.get_username()), "ip": ip, "auth_method": "console", "browser_auth_method": browser_method.get("auth_method", ""),
                "trust_id": str(trust.pk)})
        server_proof = cc.sign_server_signin_proof(ca, host, fields["code"], found["serial"], console_token, proof["nonce"])
    cc.touch_last_used(found["serial"])
    return {
        "v": 1, "token": console_token, "idle_minutes": int(policy["idle_timeout_minutes"]), "absolute_expires_at": absolute_at.isoformat(),
        "heartbeat_seconds": int(policy.get("activity_heartbeat_seconds") or 60), "console_min_version": CONSOLE_MIN_VERSION,
        "engineer": {"id": user.pk, "username": str(user.get_username())}, "serial": found["serial"], "pc_label": certificate.pc_label,
        "server_id": ca.server_id, "server_proof": server_proof,
    }


# ------------------------------------------------------------------------------------------------ ending sessions
def _mapped_reason(trust_reason) -> str:
    """The Console end reason for the reason a Tec-Tac session was revoked with. console-<reason> carries ours; the session guard's own
    idle-timeout, absolute-timeout and ip-change-* map to idle, absolute and ip_change; the sweep, an administrator and every other revoke are admin."""
    text = str(trust_reason or "")
    if text.startswith("console-"):
        reason = text[len("console-"):]
        return reason if reason in END_REASONS else "admin"
    if text == "idle-timeout":
        return "idle"
    if text == "absolute-timeout":
        return "absolute"
    if text.startswith("ip-change"):
        return "ip_change"
    return "admin"


def _mark_revoked(row, reason: str, engineer_id=None, username: str = "") -> bool:
    """Mark one Console session revoked (a conditional update, so only the first end counts), write the NON-strict custom:console-signout row and,
    once the transaction commits, have the person's live tunnels re-check. True when this call ended it."""
    models = _models()
    now = cc._now()
    changed = models.TecTacConsoleSession.objects.filter(pk=row.pk, revoked=False).update(revoked=True, revoked_at=now, revoked_reason=reason)
    if changed != 1:
        return False
    _audit(service_actor(), "custom:console-signout", str(row.pk), "An Engineer Console session ended.",
           {"console_session_id": str(row.pk), "serial": row.serial, "pc_label": row.pc_label, "engineer_id": row.user_id if engineer_id is None else engineer_id,
            "username": username, "reason": reason}, strict=False)
    user_id = row.user_id
    cc._after_commit("console_session_ended", lambda: _tunnel().console_session_ended(user_id))
    return True


def on_trust_revoked(session, trust_reason) -> None:
    """Called by session_security._revoke_locked for every Tec-Tac session it revokes (an indexed lookup by trust id, one query; browser sessions
    have no Console row and stop there). Ends the Console session behind it. The caller wraps this in a savepoint and logs a fault: a failed
    revoke hook never blocks a revoke."""
    row = _models().TecTacConsoleSession.objects.filter(trust_id=session.pk, revoked=False).first()
    if row is not None:
        _mark_revoked(row, _mapped_reason(trust_reason), username=str(getattr(session, "username", "") or ""))


def _end_row(row, reason: str) -> None:
    """End one Console session through its Tec-Tac session, so the Knox token goes with it. Inside the caller's transaction."""
    ss = _ss()
    models = _models()
    trust = models.TecTacSessionTrust.objects.select_for_update().filter(pk=row.trust_id).first()
    if trust is not None and not trust.revoked:
        ss._revoke_locked(trust, reason=f"console-{reason}", requested_by="console", event_type="session_revoked")  # its hook marks the Console row
    elif trust is not None:
        ss._invalidate_knox_for_session(trust)  # an inconsistent pair: make sure no token is left
    _mark_revoked(row, reason, username=str(getattr(trust, "username", "") or ""))  # no-op when the hook already did it


def end_sessions(*, serial, reason: str) -> int:
    """End the live Console sessions of one certificate serial (or all of them when ``serial`` is None) with ``reason``. Inside the caller's
    transaction: certificate revoke, CA replacement and a new sign-in on the same PC. Returns how many it found."""
    models = _models()
    qs = models.TecTacConsoleSession.objects.filter(revoked=False)
    if serial:
        qs = qs.filter(serial=serial)
    rows = list(qs.order_by("created_at")[:MAX_END_BATCH])
    for row in rows:
        _end_row(row, reason)
    return len(rows)


def _end_and_commit(row, reason: str) -> None:
    from django.db import transaction

    try:
        with transaction.atomic():
            _end_row(row, reason)
    except Exception:
        logger.warning("A Console session could not be ended (%s).", reason, exc_info=True)


def sign_out(auth) -> None:
    """The engineer ends their own Console session: the Tec-Tac session is revoked (which deletes the Knox token) and the Console row follows."""
    from django.db import transaction

    models = _models()
    with transaction.atomic():
        row = models.TecTacConsoleSession.objects.select_for_update().filter(pk=auth.console_session_id).first()
        if row is None:
            return
        trust = models.TecTacSessionTrust.objects.select_for_update().filter(pk=row.trust_id).first()
        if trust is not None and not trust.revoked:
            _ss()._revoke_locked(trust, reason=ENGINEER_TRUST_REASON, requested_by=str(getattr(trust, "username", "")), event_type="session_revoked")
        _mark_revoked(row, "engineer", username=str(getattr(trust, "username", "") or ""))


# ------------------------------------------------------------------------------------------------ the Console's DRF authentication
class ConsoleAuth:
    """request.auth of a Console-authenticated request. ``digest`` is the Knox digest bound to the session (so the session guard and the tunnel
    ticket work unchanged). It holds no token and no key."""

    def __init__(self, session, digest: str):
        self.digest = str(digest)
        self.console_session_id = str(session.pk)
        self.serial = str(session.serial)
        self.console_serial = self.serial  # the name probe_tunnel.issue_ticket reads
        self.pc_label = str(session.pc_label)
        self.user_id = session.user_id

    @property
    def short_serial(self) -> str:
        return self.serial[:8]

    def __repr__(self):
        return f"<ConsoleAuth {self.console_session_id}>"


class ConsoleBodyTooLarge(APIException):
    status_code = 413
    default_code = "body_too_large"

    def __init__(self):
        super().__init__({"detail": "The request is too large.", "code": self.default_code}, self.default_code)


class ConsoleProofUnavailable(APIException):
    status_code = 503
    default_code = "proof_unavailable"

    def __init__(self):
        super().__init__({"detail": "The request proof cannot be checked right now.", "code": self.default_code}, self.default_code)


def _failed(code: str, message: str = "The Engineer Console credential is not valid."):
    return AuthenticationFailed({"detail": message, "code": code}, code=code)


class ConsoleSessionAuthentication(BaseAuthentication):
    """``Authorization: TecTacConsole <token>`` plus ``X-Tectac-Console-Proof`` on every request. Any other Authorization scheme returns None so
    the other classes decide. Every step fails closed (AuthenticationFailed, WWW-Authenticate: TecTacConsole); the cheap lookups run before any
    crypto, and the nonce is kept only after the signature held."""

    def authenticate_header(self, request):
        return AUTH_SCHEME

    def authenticate(self, request):
        django_request = getattr(request, "_request", request)
        header = django_request.META.get("HTTP_AUTHORIZATION")
        if not isinstance(header, str) or not header.startswith(AUTH_SCHEME):
            return None
        match = AUTH_PATTERN.fullmatch(header)
        if match is None:
            raise _failed("token_invalid")
        token = match.group(1)
        models = _models()
        row = models.TecTacConsoleSession.objects.filter(token_hash=token_hash(token)).first()
        if row is None:
            raise _failed("token_invalid")
        if row.revoked:
            raise _failed("session_revoked", "This Engineer Console session has ended. Sign in again.")
        now = cc._now()
        certificate = models.TecTacConsoleCertificate.objects.filter(serial=row.serial).select_related("ca").first()
        problem = None
        if certificate is None or certificate.state != "active" or certificate.ca.state != "active":
            problem = "certificate_revoked"
        elif certificate.not_after <= now:
            problem = "certificate_expired"
        if problem:
            _end_and_commit(row, problem)
            raise _failed(problem, "The Engineer Console certificate is no longer valid.")
        proof = parse_proof(django_request.META.get("HTTP_X_TECTAC_CONSOLE_PROOF"))
        if proof is None:
            raise _failed("proof_invalid")
        if abs(now.timestamp() - int(proof["time"])) > cc.PROOF_WINDOW_SECONDS:
            raise _failed("proof_stale")
        host = cc.own_host(django_request)
        if host is None:
            raise _failed("proof_invalid")
        body = self._body(django_request)
        message = cc.request_message(host, certificate.ca.server_id, row.serial, django_request.method.upper(), django_request.get_full_path(), body, token,
                                     proof["time"], proof["nonce"])
        public_key = self._public_key(certificate)
        signature = cc.b64u_decode(proof["sig"], max_chars=100)
        if public_key is None or signature is None or not cc._verify_p1363(public_key, signature, message):
            raise _failed("proof_invalid")
        self._keep_nonce(row.serial, proof["nonce"])
        trust = models.TecTacSessionTrust.objects.filter(pk=row.trust_id).only("knox_digest", "revoked").first()
        if trust is None or trust.revoked or not trust.knox_digest:
            _end_and_commit(row, "admin")
            raise _failed("session_revoked", "This Engineer Console session has ended. Sign in again.")
        user = cc._find_user(row.user_id)
        if user is None:
            _end_and_commit(row, "account_inactive")
            raise _failed("session_revoked", "This Engineer Console session has ended. Sign in again.")
        return user, ConsoleAuth(row, trust.knox_digest)

    @staticmethod
    def _body(django_request) -> bytes:
        """The raw body, read from the underlying request only when it is at most 64 KiB."""
        declared = django_request.META.get("CONTENT_LENGTH")
        try:
            length = int(declared) if declared not in (None, "") else 0
        except (TypeError, ValueError):
            raise _failed("proof_invalid") from None
        if length > MAX_REQUEST_BODY or length < 0:
            raise ConsoleBodyTooLarge()
        if length == 0:
            return b""
        try:
            body = django_request.body
        except Exception:
            raise _failed("proof_invalid") from None
        if len(body) > MAX_REQUEST_BODY:
            raise ConsoleBodyTooLarge()
        return bytes(body)

    @staticmethod
    def _public_key(certificate):
        from cryptography import x509

        try:
            return x509.load_der_x509_certificate(bytes(certificate.cert_der)).public_key()
        except Exception:
            logger.warning("A stored Console certificate could not be read.", exc_info=True)
            return None

    @staticmethod
    def _keep_nonce(serial: str, nonce: str) -> None:
        """Keep the nonce for 5 minutes per serial (cache.add): a repeat is refused, and a cache fault is refused too (503), so a down cache means no
        Console requests."""
        try:
            fresh = cc._cache().add(f"{NONCE_PREFIX}{serial}:{nonce}", 1, NONCE_SECONDS)
        except Exception:
            logger.warning("The Console request nonce could not be stored; refusing the request.", exc_info=True)
            raise ConsoleProofUnavailable() from None
        if not fresh:
            raise _failed("proof_replayed")


class ConsoleSessionAuthenticated(BasePermission):
    """The session guard for a Console request, the way SessionAuthenticated is for the browser: the winning authenticator must be
    ConsoleSessionAuthentication; the account must be active, not blocked and not an installer user; the Knox token behind the session must
    exist; then the Tec-Tac session policy (idle, absolute, IP change) applies exactly as for the browser."""

    def has_permission(self, request, view):
        authenticator = getattr(request, "successful_authenticator", None)
        auth = getattr(request, "auth", None)
        if not isinstance(authenticator, ConsoleSessionAuthentication) or not isinstance(auth, ConsoleAuth):
            return False
        user = request.user
        models = _models()
        row = models.TecTacConsoleSession.objects.filter(pk=auth.console_session_id).first()
        if row is None or row.revoked:
            raise _failed("session_revoked", "This Engineer Console session has ended. Sign in again.")
        if cc.account_problem(user):
            _end_and_commit(row, "account_inactive")
            raise _failed("account_inactive", "This account may not use the Engineer Console.")
        reason = self._knox_problem(auth, user)
        if reason:
            _end_and_commit(row, reason)
            raise _failed("session_revoked", "This Engineer Console session has ended. Sign in again.")
        request.tec_tac_session = _ss().ensure_request_session(request)
        self._touch(row)
        return True

    @staticmethod
    def _knox_problem(auth, user):
        from django.utils import timezone
        from knox.models import AuthToken

        row = AuthToken.objects.filter(digest=auth.digest, user_id=user.pk).first()
        if row is None:
            return "admin"
        if row.expiry is not None and row.expiry <= timezone.now():
            return "absolute"
        return None

    @staticmethod
    def _touch(row) -> None:
        """last_used_at at most once a minute: one conditional UPDATE. A fault is logged and never fatal."""
        from django.db.models import Q

        now = cc._now()
        try:
            _models().TecTacConsoleSession.objects.filter(pk=row.pk).filter(
                Q(last_used_at__isnull=True) | Q(last_used_at__lt=now - timedelta(seconds=LAST_USED_SECONDS))).update(last_used_at=now)
        except Exception:
            logger.warning("The Console session last-used time could not be written.", exc_info=True)


# ------------------------------------------------------------------------------------------------ the capability (core.console_session 1.0.0)
def console_info(request):
    """For a request the Console authenticated: {serial, short_serial, pc_label}. None for anything else. Never raises; never a token, a digest
    or a key."""
    try:
        authenticator = getattr(request, "successful_authenticator", None)
        auth = getattr(request, "auth", None)
        if isinstance(authenticator, ConsoleSessionAuthentication) and isinstance(auth, ConsoleAuth):
            return {"serial": auth.serial, "short_serial": auth.short_serial, "pc_label": auth.pc_label}
    except Exception:
        logger.debug("console_info could not read the request.", exc_info=True)
    return None


class _ConsoleSessionProvider:
    def console_info(self, request):
        return console_info(request)


_PROVIDER = _ConsoleSessionProvider()


def console_session_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["console_info"],
        "python": (
            "tec_tac.console_sessions.ConsoleSessionAuthentication (a DRF authentication class); "
            "tec_tac.console_sessions.ConsoleSessionAuthenticated (a DRF permission); "
            "console_info(request) -> {serial, short_serial, pc_label} or None"
        ),
        "headers": {"Authorization": "TecTacConsole <43 characters>", "X-Tectac-Console-Proof": "v1.<time>.<nonce>.<signature>"},
        "console_min_version": CONSOLE_MIN_VERSION,
        "returns_secrets": False,
        "requires_framework": ">=1.18.56",
    }


def register_core_console_session_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Authenticate a request from the Engineer Console: the session token plus a proof signed with the PC's certificate key.",
        operations=("console_info",),
        metadata=console_session_contract_metadata(),
    )

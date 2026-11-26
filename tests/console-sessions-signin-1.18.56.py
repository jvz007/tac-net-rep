#!/usr/bin/env python3
"""Regression: Core 1.18.56 (C1). The Engineer Console sign-in: POST authorise/ (browser) and POST token/ (the Console).

A real P-256 key in a Python stand-in Console (tests/console_sessions_harness.py), the real Core files, a real SQLite file. Covered: the full flow
ends with a token and a server proof that verifies against the CA key; the code works once and not after 60 seconds; a wrong verifier is refused and
burns the code; another person's serial is refused at authorise with one body; an API key gets 403 and a deny row; a bad port, challenge, key set,
an over-size body and a plain-text connection are refused; a wrong, stale, future, other-host, other-code or other-serial proof is refused; a
revoked, expired or wrong-CA certificate is refused; the 11th failure in a minute is 429 and one refusal row is written a minute per address; a
strict audit failure and a server-proof failure leave no session behind; a second sign-in on the same PC ends the first; neither the Console token nor
the Knox token is ever in a row, a log line or the database file; the message bytes are pinned byte for byte; an old client_version is 426 and leaves the
code unburnt; the throttles of authorise.
"""
import base64
import importlib.util
import json
import sys
from datetime import timedelta
from pathlib import Path

spec = importlib.util.spec_from_file_location("cs_harness", Path(__file__).with_name("console_sessions_harness.py"))
H = importlib.util.module_from_spec(spec)
sys.modules["cs_harness"] = H
spec.loader.exec_module(H)
must, rows_of = H.must, H.rows_of

h = H.boot()
if h is None:
    print("console sessions signin 1.18.56 regression: PASS (Django is not installed: nothing to run)")
    sys.exit(0)

M, cc, cs, V = h.models, h.cc, h.cs, h.views
HOST, IP = H.HOST, H.IP
OTHER_IP = "198.51.100.9"

raw_knox = []  # every raw Knox token the harness's Knox manager hands out (so the test can prove none is kept)
_real_create = h.AuthToken.objects.create


def spy_create(user, expiry=None, **kw):
    instance, token = _real_create(user, expiry=expiry, **kw) if expiry is not None else _real_create(user, **kw)
    raw_knox.append(token)
    return instance, token


h.AuthToken.objects.create = spy_create


def refused_rows():
    return rows_of(h, "custom:console-signin-refused")


def counts():
    return (h.AuthToken.objects.count(), M.TecTacSessionTrust.objects.count(), M.TecTacConsoleSession.objects.count())


# ------------------------------------------------------------------------------------------------ the message bytes, pinned byte for byte
pc0 = H.Pc()
sample = dict(host="tec.example.com", server_id="a" * 32, code="C" * 43, verifier="V" * 43, serial="1" * 32, time_text="1764000000", nonce="N" * 22)
must(cc.signin_message(sample["host"], sample["server_id"], sample["code"], sample["verifier"], sample["serial"], sample["time_text"], sample["nonce"]) == pc0.signin_message(**sample),
     "Core's sign-in message equals the written format")
must(cc.server_signin_message("tec.example.com", "a" * 32, "C" * 43, "1" * 32, "T" * 43, "N" * 22) == pc0.server_proof_message("tec.example.com", "a" * 32, "C" * 43, "1" * 32, "T" * 43, "N" * 22),
     "Core's server proof message equals the written format")
must(cc.request_message("tec.example.com", "a" * 32, "1" * 32, "POST", "/api/x/?a=1", b'{"a":1}', "T" * 43, "1764000000", "N" * 22)
     == pc0.request_message("tec.example.com", "a" * 32, "1" * 32, "POST", "/api/x/?a=1", b'{"a":1}', "T" * 43, "1764000000", "N" * 22), "Core's request message equals the written format")
must(cc.signin_message(**{**sample, "serial": "1" * 32}).startswith(b"tectac-console-signin-v1\nhost=tec.example.com\nserver=") and not cc.signin_message(**sample).endswith(b"\n"), "no trailing newline")

# ------------------------------------------------------------------------------------------------ the full flow
h.reset()
user, pc = h.enrol_pc()
ca = cc.active_ca()
browser = h.browser(user)
r, verifier, _ = h.authorise(user, pc, session=browser)
must(r.status_code == 200 and set(r.data) == {"code", "expires_in", "host", "server_id"}, f"authorise answers code, expires_in, host, server_id: {r.status_code} {getattr(r, 'data', '')}")
must(r.data["expires_in"] == 60 and r.data["host"] == HOST and r.data["server_id"] == ca.server_id and len(r.data["code"]) == 43, "the authorise answer")
must(r["Cache-Control"] == "no-store", "authorise is no-store")
code = r.data["code"]
stored = M.TecTacConsoleSignin.objects.get()
must(stored.code_hash == cc.code_hash(code) and code not in json.dumps({"hash": stored.code_hash, "challenge": stored.code_challenge}), "only the SHA-256 of the code is stored")
must(stored.user_id == user.pk and stored.serial == pc.serial and stored.redirect_port == 40123 and stored.host == HOST and stored.code_challenge == pc.challenge(verifier), "the row binds person, serial, port, host and challenge")
must((stored.expires_at - stored.created_at).total_seconds() == 60 or abs((stored.expires_at - stored.created_at).total_seconds() - 60) < 1, "60 seconds")

nonce = pc.nonce()
proof = pc.signin_proof(HOST, pc.server_id, code, nonce=nonce)
t = h.token_request(pc, code, verifier, proof=proof)
must(t.status_code == 201, f"token: {t.status_code} {getattr(t, 'data', '')}")
d = t.data
must(set(d) == {"v", "token", "idle_minutes", "absolute_expires_at", "heartbeat_seconds", "console_min_version", "engineer", "serial", "pc_label", "server_id", "server_proof"}, f"the token answer keys: {sorted(d)}")
must(d["v"] == 1 and d["idle_minutes"] == 30 and d["heartbeat_seconds"] == 60 and d["console_min_version"] == cs.CONSOLE_MIN_VERSION == "0.1.1", "lifetimes and the minimum version")
must(d["engineer"] == {"id": user.pk, "username": user.username} and d["serial"] == pc.serial and d["pc_label"] == "Work PC" and d["server_id"] == ca.server_id, "who, which PC")
must(len(d["token"]) == 43 and t["Cache-Control"] == "no-store", "a 43 character token, no-store")
# the server proof verifies with the CA public key over the written bytes (the Console's nonce, the token hash)
from cryptography.hazmat.primitives import serialization  # noqa: E402
ca_key = serialization.load_der_public_key(bytes(ca.public_key_der))
must(d["server_proof"].startswith("v1."), "v1. prefix")
raw_sig = base64.urlsafe_b64decode(d["server_proof"][3:] + "==")
must(cc._verify_p1363(ca_key, raw_sig, pc.server_proof_message(HOST, ca.server_id, code, pc.serial, d["token"], nonce)), "the server proof verifies against the CA key")
must(not cc._verify_p1363(ca_key, raw_sig, pc.server_proof_message(HOST, ca.server_id, code, pc.serial, d["token"], pc.nonce())), "it covers the Console's own nonce")
must(not cc._verify_p1363(ca_key, raw_sig, pc.server_proof_message(HOST, ca.server_id, code, pc.serial, "x" * 43, nonce)), "and the token")

# what was made, in one place
console = M.TecTacConsoleSession.objects.get()
trust = M.TecTacSessionTrust.objects.get(pk=console.trust_id)
knox = h.AuthToken.objects.get(digest=trust.knox_digest)
must(trust.knox_digest == knox.digest and trust.user_id == user.pk and not trust.revoked, "the Tec-Tac session is bound to the minted Knox token")
must(console.trust_id == trust.pk and console.token_hash == cs.token_hash(d["token"]) and console.serial == pc.serial and not console.revoked, "the Console session")
must(trust.token_fingerprint == h.ss._fingerprint_for_identity(f"console:{console.pk}"), "the trust row is bound to console:<id>")
must(knox.expiry is not None and abs((knox.expiry - h.timezone.now()).total_seconds() - 8 * 3600) < 60, "the Knox token lasts the absolute lifetime of the policy")
signins = rows_of(h, "custom:console-signin")
must(len(signins) == 1 and signins[0]["strict"] is True and signins[0]["module_id"] == "core" and signins[0]["object_type"] == "console_session", "one strict custom:console-signin row")
must(signins[0]["actor"] == user, "under the engineer")
must(signins[0]["operation_context"] == {"server_provenance": "console-sessions"}, "provenance console-sessions")
meta = signins[0]["metadata"]
must(meta["serial"] == pc.serial and meta["pc_label"] == "Work PC" and meta["engineer_id"] == user.pk and meta["auth_method"] == "console" and meta["browser_auth_method"] == "password" and meta["ip"] == IP,
     f"the sign-in row: {meta}")
created = M.TecTacSessionAudit.objects.filter(event_type="session_created", session_id=trust.pk)
must(created.count() == 1 and created.get().metadata["auth_method"] == "console" and created.get().metadata["browser_auth_method"] == "password", "the session_created event names the Console and the browser method")
# an SSO account says so
sso_user, sso_pc = h.enrol_pc(h.new_user("sso", is_sso_user=True))
_, _, sso = h.sign_in(sso_user, sso_pc)
must(sso.status_code == 201, f"sso sign-in: {sso.status_code}")
sso_event = [e for e in M.TecTacSessionAudit.objects.filter(event_type="session_created", username="sso") if e.metadata.get("auth_method") == "console"][0]
must(sso_event.metadata == {"auth_method": "console", "browser_auth_method": "sso", "serial": sso_pc.serial, "provider": "test-idp"}, f"sso: {sso_event.metadata}")

# nothing secret is kept: not the Console token, not any raw Knox token, not the code, the verifier, the proof or the nonce
for secret_name, secret in (("console token", d["token"]), ("code", code), ("verifier", verifier), ("proof", proof), ("nonce", nonce), ("server proof", d["server_proof"]), *[("raw Knox token", k) for k in raw_knox]):
    must(secret not in H.captured_text(h), f"the {secret_name} is not in a log line or an audit row")
    must(secret.encode() not in Path(h.tmp, "cs.sqlite3").read_bytes(), f"the {secret_name} is not in the database file")
for model in (M.TecTacSessionAudit, M.TecTacConsoleSession, M.TecTacConsoleSignin, M.TecTacSessionTrust):
    must(d["token"] not in repr(list(model.objects.values())), f"the Console token is not in {model.__name__}")
must(not refused_rows(), "a good sign-in writes no refusal row")

# ------------------------------------------------------------------------------------------------ the code works once
t2 = h.token_request(pc, code, verifier)
must(t2.status_code == 401 and t2.data["code"] == "code_invalid", f"a used code is refused with one body: {t2.status_code} {t2.data}")
must(counts()[2] == 2, "and makes nothing")  # the first session and the SSO user's
refused_row = refused_rows()
must(len(refused_row) == 1 and refused_row[0]["metadata"]["reason"] == "code_invalid" and refused_row[0]["metadata"]["ip"] == IP, "one refusal row")
must(refused_row[0]["actor"] is not user and getattr(refused_row[0]["actor"], "kind", "") == "service", "a code that does not match is under the service actor")
must(refused_row[0]["metadata"].get("serial") == pc.serial and refused_row[0]["operation_context"]["core_refusal"] is True, "the serial that parsed, and the refusal flag")
must(code not in H.captured_text(h) and verifier not in H.captured_text(h), "no code or verifier in the refusal row")


def fresh_code(user, pc, **kw):
    r, verifier, session = h.authorise(user, pc, **kw)
    must(r.status_code == 200, f"authorise: {r.status_code} {getattr(r, 'data', '')}")
    return r.data["code"], verifier, session


# an expired code (60 seconds)
c, v, _ = fresh_code(user, pc)
M.TecTacConsoleSignin.objects.filter(code_hash=cc.code_hash(c)).update(expires_at=h.timezone.now() - timedelta(seconds=1))
must(h.token_request(pc, c, v).status_code == 401, "a code after its 60 seconds is refused")

# a wrong verifier is refused and burns the code
h.cache.clear()
c, v, _ = fresh_code(user, pc)
bad = h.token_request(pc, c, H.Pc.new_verifier())
must(bad.status_code == 401 and bad.data["code"] == "verifier_invalid", f"wrong verifier: {bad.status_code} {bad.data}")
must(h.token_request(pc, c, v).status_code == 401, "the code is burnt by the wrong verifier: the right one is refused now")
must(M.TecTacConsoleSignin.objects.get(code_hash=cc.code_hash(c)).used_at is not None, "used_at is set")
last = refused_rows()[-1]
must(getattr(last["actor"], "pk", None) == user.pk and last["metadata"]["engineer_id"] == user.pk, "a refusal after the code matched sits under the engineer")

# ------------------------------------------------------------------------------------------------ authorise refusals
h.reset()
user, pc = h.enrol_pc()
other_user, other_pc = h.enrol_pc(h.new_user("other"))
session = h.browser(user)
r1, _, _ = h.authorise(user, other_pc, session=session)
r2, _, _ = h.authorise(user, pc, session=session, serial="f" * 32)
must(r1.status_code == 403 and r2.status_code == 403 and r1.data == r2.data and r1.data["code"] == "serial_not_allowed", f"another person's serial and an unknown serial give one body: {r1.data} {r2.data}")
cc.revoke(user, pc.serial, "lost", can_manage=False)
r3, _, _ = h.authorise(user, pc, session=session)
must(r3.status_code == 403 and r3.data == r1.data, "a revoked certificate gives the same body")
h.reset()
user, pc = h.enrol_pc()
M.TecTacConsoleCertificate.objects.filter(serial=pc.serial).update(not_after=h.timezone.now() - timedelta(seconds=1))
must(h.authorise(user, pc)[0].status_code == 403, "an expired certificate is refused at authorise")

h.reset()
user, pc = h.enrol_pc()
session = h.browser(user)
for name, override in (("port 0", {"redirect_port": 0}), ("port 1023", {"redirect_port": 1023}), ("port 65536", {"redirect_port": 65536}), ("port true", {"redirect_port": True}),
                       ("port text", {"redirect_port": "40000"}), ("port float", {"redirect_port": 40000.5}), ("challenge 42", {"code_challenge": "A" * 42}),
                       ("challenge 44", {"code_challenge": "A" * 44}), ("challenge chars", {"code_challenge": "A" * 42 + "="}), ("serial upper", {"serial": pc.serial.upper()}),
                       ("serial short", {"serial": pc.serial[:31]}), ("unknown key", {"extra": 1})):
    r, _, _ = h.authorise(user, pc, session=session, **override)
    must(r.status_code == 400, f"{name} is refused 400, got {r.status_code} {getattr(r, 'data', '')}")
    h.cache.clear()
for port in (1024, 65535):
    must(h.authorise(user, pc, session=session, port=port)[0].status_code == 200, f"port {port} is allowed")
h.cache.clear()
r = h.call(V.ConsoleSessionAuthoriseView, "POST", "/api/tfd/console-sessions/authorise/", session=session, data={"serial": pc.serial, "code_challenge": "A" * 43})
must(r.status_code == 400, "a missing key is refused")
r = h.call(V.ConsoleSessionAuthoriseView, "POST", "/api/tfd/console-sessions/authorise/", session=session, raw=b"[]")
must(r.status_code == 400, "a body that is not an object is refused")
r = h.call(V.ConsoleSessionAuthoriseView, "POST", "/api/tfd/console-sessions/authorise/", session=session,
           data={"serial": pc.serial, "code_challenge": "A" * 43, "redirect_port": 40000}, extra={"HTTP_HOST": "tec.example.com:8443"})
must(r.status_code == 400 and r.data["code"] == "host_unusable", f"an odd host is host_unusable: {r.status_code}")
h.master_fault = "test"
r = h.call(V.ConsoleSessionAuthoriseView, "POST", "/api/tfd/console-sessions/authorise/", session=session, data={"nonsense": 1})
must(r.status_code == 503 and r.data["code"] == "master_key_unavailable", f"the master key is checked first: {r.status_code} {r.data}")
h.master_fault = None

# an API key (and a plain Django session) is refused with one deny row, before the body or the certificate is looked at
from rest_framework.permissions import IsAuthenticated  # noqa: E402
from rest_framework.test import force_authenticate  # noqa: E402


class Open(V.ConsoleSessionAuthoriseView):  # only the session guard is replaced, so the route's own interactive-session check is what is tested
    permission_classes = [IsAuthenticated]
    throttle_classes = []


for kind in ("api", "session"):
    h.rows.clear()
    issued_before = M.TecTacConsoleSignin.objects.count()
    request = h.factory.post("/api/tfd/console-sessions/authorise/", {"serial": pc.serial, "code_challenge": "A" * 43, "redirect_port": 40000}, format="json",
                             HTTP_HOST=HOST, REMOTE_ADDR=IP, **({"HTTP_X_API_KEY": "api-key"} if kind == "api" else {}))
    force_authenticate(request, user=user, token="api-key" if kind == "api" else None)
    r = Open.as_view()(request)
    must(r.status_code == 403 and r.data["code"] == "interactive_session_required", f"{kind}: {r.status_code} {getattr(r, 'data', '')}")
    must(len(rows_of(h, "deny")) == 1 and rows_of(h, "deny")[0]["metadata"] == {"reason": "api_key_refused"} and M.TecTacConsoleSignin.objects.count() == issued_before, f"{kind}: one deny row, no code")

# the throttle: 10 a minute per person
h.cache.clear()
session = h.browser(user)
statuses = [h.authorise(user, pc, session=session)[0].status_code for _ in range(11)]
must(statuses[:10] == [200] * 10 and statuses[10] == 429, f"the 11th request in a minute is throttled: {statuses}")
must(V.ConsoleSigninMinThrottle.rate == "10/min" and V.ConsoleSigninDayThrottle.rate == "100/day", "10 a minute and 100 a day")

# old rows are cleaned, bounded
h.cache.clear()
long_ago = h.timezone.now() - timedelta(hours=2)
for i in range(205):
    M.TecTacConsoleSignin.objects.create(code_hash=f"{i:064x}", user_id=user.pk, serial=pc.serial, code_challenge="A" * 43, redirect_port=40000, host=HOST, expires_at=long_ago)
before = M.TecTacConsoleSignin.objects.count()
h.authorise(user, pc, session=h.browser(user))
after = M.TecTacConsoleSignin.objects.count()
must(before - after == 199, f"a call deletes at most 200 old rows (and adds its own): {before} -> {after}")
h.cache.clear()
h.authorise(user, pc, session=h.browser(user))
must(not M.TecTacConsoleSignin.objects.filter(expires_at__lt=long_ago + timedelta(minutes=30)).exists(), "the next call finishes the cleaning")

# ------------------------------------------------------------------------------------------------ token refusals
h.reset()
user, pc = h.enrol_pc()


def attempt(label, expect_status, expect_code=None, *, use_code=None, **kw):
    """One fresh code, then one token request with the given faults. Returns the response."""
    h.cache.clear()
    c, v, _ = fresh_code(user, pc)
    r = h.token_request(pc, use_code or c, v, **kw) if "verifier" not in kw else h.token_request(pc, c, kw.pop("verifier"), **kw)
    must(r.status_code == expect_status and (expect_code is None or r.data.get("code") == expect_code), f"{label}: {r.status_code} {getattr(r, 'data', '')}")
    return r, c, v


good, c, v = attempt("a good request", 201)
attempt("an unknown key in the body", 400, "invalid_request", body={"v": 1, "code": "A" * 43, "code_verifier": "A" * 43, "serial": pc.serial, "extra": 1})
attempt("a missing key", 400, "invalid_request", body={"v": 1, "code": "A" * 43, "code_verifier": "A" * 43})
attempt("v 2", 400, "invalid_request", body={"v": 2, "code": "A" * 43, "code_verifier": "A" * 43, "serial": pc.serial})
attempt("v true", 400, "invalid_request", body={"v": True, "code": "A" * 43, "code_verifier": "A" * 43, "serial": pc.serial})
attempt("a short verifier", 400, "invalid_request", body={"v": 1, "code": "A" * 43, "code_verifier": "A" * 42, "serial": pc.serial})
attempt("a code of the wrong shape", 401, "code_invalid", body={"v": 1, "code": "short", "code_verifier": "A" * 43, "serial": pc.serial})
attempt("a body that is not JSON", 400, "invalid_request", raw=b"not json")
attempt("a body that is an array", 400, "invalid_request", raw=b"[]")
attempt("a body over 4 KiB", 413, "body_too_large", raw=b'{"v":1,"pad":"' + b"x" * 5000 + b'"}')
attempt("a plain-text connection (forwarded http)", 403, "tls_required", extra={"HTTP_X_FORWARDED_PROTO": "http"})
r, c, v = attempt("a forwarded https connection", 201, extra={"HTTP_X_FORWARDED_PROTO": "https"})
must(M.TecTacConsoleSignin.objects.filter(used_at__isnull=True).count() >= 0, "(the forwarded-http request did not burn a code before the check)")
attempt("a missing certificate header", 401, "certificate_required", headers={"HTTP_X_TECTAC_CONSOLE_CERT": ""})
attempt("a missing proof header", 401, "certificate_required", headers={"HTTP_X_TECTAC_CONSOLE_PROOF": ""})
attempt("a certificate that is not base64url", 401, "certificate_invalid", cert="not base64!")
attempt("a proof of the wrong shape", 401, "proof_invalid", proof="v1.1.a.b")
attempt("a proof signed by another key", 401, "proof_invalid", proof=pc.signin_proof(HOST, pc.server_id, "x", key=H.Pc().key))

# proofs that must fail, each over a code that is still valid
h.cache.clear()
c, v, _ = fresh_code(user, pc)
for label, kwargs, status, code_expected in (
    ("a stale proof", {"time_text": str(int(__import__("time").time()) - 121)}, 401, "proof_stale"),
    ("a proof from the future", {"time_text": str(int(__import__("time").time()) + 121)}, 401, "proof_stale"),
    ("a proof for another serial", {"serial": "1" * 32}, 401, "proof_invalid"),
):
    h.cache.clear()
    c, v, _ = fresh_code(user, pc)
    r = h.token_request(pc, c, v, proof=pc.signin_proof(HOST, pc.server_id, c, **kwargs))
    must(r.status_code == status and r.data["code"] == code_expected, f"{label}: {r.status_code} {r.data}")
h.cache.clear()
c, v, _ = fresh_code(user, pc)
r = h.token_request(pc, c, v, proof=pc.signin_proof("other.example.com", pc.server_id, c))
must(r.status_code == 401 and r.data["code"] == "proof_invalid", f"a proof for another host: {r.status_code} {r.data}")
h.cache.clear()
c, v, _ = fresh_code(user, pc)
r = h.token_request(pc, c, v, proof=pc.signin_proof(HOST, pc.server_id, "X" * 43))
must(r.status_code == 401 and r.data["code"] == "proof_invalid", "a proof for another code")
h.cache.clear()
c, v, _ = fresh_code(user, pc)
r = h.token_request(pc, c, v, proof=pc.signin_proof(HOST, "b" * 32, c))
must(r.status_code == 401 and r.data["code"] == "proof_invalid", "a proof for another server")
h.cache.clear()
c, v, _ = fresh_code(user, pc)
r = h.token_request(pc, c, v, host="other.example.com")
must(r.status_code == 401 and r.data["code"] in ("host_mismatch", "proof_invalid"), f"a code used on another host: {r.status_code} {r.data}")
h.cache.clear()
c, v, _ = fresh_code(user, pc)
r = h.token_request(pc, c, v, body={"v": 1, "code": c, "code_verifier": v, "serial": "1" * 32})
must(r.status_code == 401 and r.data["code"] == "certificate_engineer_mismatch", f"a body serial that is not the code's: {r.status_code} {r.data}")
h.cache.clear()
c, v, _ = fresh_code(user, pc)
stranger_user, stranger_pc = h.enrol_pc(h.new_user("stranger"))
r = h.token_request(pc, c, v, cert=stranger_pc.cert_b64)
must(r.status_code == 401 and r.data["code"] == "certificate_engineer_mismatch", f"another person's certificate for this code: {r.status_code} {r.data}")

# a revoked, expired or wrong-CA certificate (the shared certificate checks)
h.cache.clear()
c, v, _ = fresh_code(user, pc)
M.TecTacConsoleCertificate.objects.filter(serial=pc.serial).update(state="revoked", revoked_reason="lost")
r = h.token_request(pc, c, v)
must(r.status_code == 401 and r.data["code"] == "certificate_revoked", f"revoked: {r.status_code} {r.data}")
M.TecTacConsoleCertificate.objects.filter(serial=pc.serial).update(state="active", revoked_reason="")
h.cache.clear()
c, v, _ = fresh_code(user, pc)
M.TecTacConsoleCertificate.objects.filter(serial=pc.serial).update(not_after=h.timezone.now() - timedelta(seconds=1))
r = h.token_request(pc, c, v)
must(r.status_code == 401 and r.data["code"] == "certificate_expired", f"expired: {r.status_code} {r.data}")
M.TecTacConsoleCertificate.objects.filter(serial=pc.serial).update(not_after=h.timezone.now() + timedelta(days=30))
h.cache.clear()
c, v, _ = fresh_code(user, pc)
cc.replace_ca(h.new_user("root2", superuser=True))
r = h.token_request(pc, c, v)
must(r.status_code == 401 and r.data["code"] in ("certificate_invalid", "certificate_revoked"), f"a certificate of a replaced CA: {r.status_code} {r.data}")

# an inactive or blocked account
h.reset()
user, pc = h.enrol_pc()
c, v, _ = fresh_code(user, pc)
h.user_flags[user.pk]["block_dashboard_login"] = True
snapshot = counts()
r = h.token_request(pc, c, v)
must(r.status_code == 403 and r.data["code"] == "account_inactive" and counts() == snapshot, f"a dashboard-blocked account: {r.status_code} {r.data}")
h.user_flags[user.pk]["block_dashboard_login"] = False

# ------------------------------------------------------------------------------------------------ client_version
h.reset()
user, pc = h.enrol_pc()
c, v, _ = fresh_code(user, pc)
r = h.token_request(pc, c, v, version="0.1.0")
must(r.status_code == 426 and r.data["code"] == "console_update_required", f"an old Console: {r.status_code} {getattr(r, 'data', '')}")
must(M.TecTacConsoleSignin.objects.get(code_hash=cc.code_hash(c)).used_at is None, "the code is not burnt by a 426")
r = h.token_request(pc, c, v, version="0.1.1")
must(r.status_code == 201, f"the same code works with the minimum version: {r.status_code}")
c, v, _ = fresh_code(user, pc)
must(h.token_request(pc, c, v, version="1.0.0").status_code == 201, "a newer version is accepted")
c, v, _ = fresh_code(user, pc)
must(h.token_request(pc, c, v, version="0.1.x").status_code == 400, "a version that does not look like one is refused")
h.cache.clear()
c, v, _ = fresh_code(user, pc)
must(h.token_request(pc, c, v).status_code == 201, "no client_version at all is accepted (the signed body has no such field)")

# ------------------------------------------------------------------------------------------------ the failure limit and the one refusal row
h.reset()
user, pc = h.enrol_pc()
h.rows.clear()
codes = []
for _attempt in range(10):
    r = h.token_request(pc, "A" * 43, "B" * 43, ip="203.0.113.50")
    codes.append(r.status_code)
must(codes == [401] * 10, f"ten failures are answered 401: {codes}")
r = h.token_request(pc, "A" * 43, "B" * 43, ip="203.0.113.50")
must(r.status_code == 429 and r["Retry-After"] == "60" and r.data["code"] == "rate_limited", f"the 11th failure in a minute is 429: {r.status_code}")
must(len(refused_rows()) == 1, f"one refusal row a minute per address, not {len(refused_rows())}")
must(h.token_request(pc, "A" * 43, "B" * 43, ip="203.0.113.51").status_code == 401, "another address has its own budget")
must(cc.FAILURE_PREFIX != cc.SIGNIN_FAILURE_PREFIX, "the sign-in counter prefix is its own")
# a refused enrolment and a refused sign-in never share a counter
h.cache.clear()
for _ in range(10):
    cc.note_failure("203.0.113.60")
must(not cc.rate_limited("203.0.113.60", cc.SIGNIN_FAILURE_PREFIX) and cc.rate_limited("203.0.113.60"), "the enrolment counter does not limit sign-in")
# a good sign-in is not counted
h.cache.clear()
_, _, ok = h.sign_in(user, pc)
must(ok.status_code == 201 and not cc.rate_limited(IP, cc.SIGNIN_FAILURE_PREFIX), "a success is not a failure")

# ------------------------------------------------------------------------------------------------ all or nothing
h.reset()
user, pc = h.enrol_pc()
h.cache.clear()
r0, v0, browser_session = h.authorise(user, pc)  # (the browser's own Knox token and session exist from here on)
snapshot = counts()
h.fail_actions = {"custom:console-signin"}
r = h.token_request(pc, r0.data["code"], v0)
must(r.status_code == 503 and r.data["code"] == "audit_failed", f"a failed strict row refuses the sign-in: {r.status_code} {getattr(r, 'data', '')}")
must(counts() == snapshot, f"no Knox token, no Tec-Tac session, no Console session was made: {snapshot} -> {counts()}")
must(M.TecTacSessionAudit.objects.filter(event_type="session_created").count() == 1, "no session_created event for the Console either (same transaction): only the browser's")
h.fail_actions = set()
h.cache.clear()
r1, verifier1, s1 = h.authorise(user, pc, session=browser_session)
snapshot = counts()
h.master_fault = "ca_key"
t = h.token_request(pc, r1.data["code"], verifier1)
must(t.status_code == 503 and t.data["code"] == "master_key_unavailable", f"a CA key that cannot sign: {t.status_code} {getattr(t, 'data', '')}")
must(counts() == snapshot, f"a server-proof failure leaves no session: {snapshot} -> {counts()}")
must(M.TecTacConsoleSignin.objects.get(code_hash=cc.code_hash(r1.data["code"])).used_at is not None, "and the code stays burnt")
h.master_fault = None
for secret in raw_knox:
    must(secret not in H.captured_text(h), "no raw Knox token in a log line or a row, even after a rollback")

# ------------------------------------------------------------------------------------------------ a second sign-in on the same PC ends the first
h.reset()
user, pc = h.enrol_pc()
_, _, first = h.sign_in(user, pc)
first_token = first.data["token"]
first_digest = M.TecTacSessionTrust.objects.get(pk=M.TecTacConsoleSession.objects.get().trust_id).knox_digest
_, _, second = h.sign_in(user, pc)
must(second.status_code == 201 and second.data["token"] != first_token, "the second sign-in works")
rows = list(M.TecTacConsoleSession.objects.order_by("created_at"))
must(len(rows) == 2 and rows[0].revoked and rows[0].revoked_reason == "replaced" and not rows[1].revoked, "the first session is revoked with reason replaced")
must(not h.AuthToken.objects.filter(digest=first_digest).exists(), "its Knox token is gone")
must(M.TecTacSessionTrust.objects.get(knox_digest=first_digest).revoked, "its Tec-Tac session is revoked")
out = [r for r in rows_of(h, "custom:console-signout") if r["metadata"]["reason"] == "replaced"]
must(len(out) == 1 and out[0]["strict"] is False, "one non-strict signout row, reason replaced")
r = h.pc_call(V.ConsoleSessionCurrentView, pc, "GET", "/api/tfd/console-sessions/current/", token=first_token)
must(r.status_code == 401, "the first token is refused now")
pc.token = second.data["token"]
must(h.pc_call(V.ConsoleSessionCurrentView, pc, "GET", "/api/tfd/console-sessions/current/").status_code == 200, "the second token works")
# a different PC of the same person keeps its own session
_, pc_b = h.enrol_pc(user, label="Laptop")
_, _, other = h.sign_in(user, pc_b)
must(other.status_code == 201 and M.TecTacConsoleSession.objects.filter(revoked=False).count() == 2, "another PC of the same person is not ended")

print("console sessions signin 1.18.56 regression: PASS")

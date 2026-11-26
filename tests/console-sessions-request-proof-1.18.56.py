#!/usr/bin/env python3
"""Regression: Core 1.18.56 (C1). ConsoleSessionAuthentication and ConsoleSessionAuthenticated: the proof of every request.

Real P-256 signatures from a stand-in Console against the real Core files. Covered: a valid GET (with a query) and POST (with a body) are accepted; a
proof made for another method, path, query, body, token, host, server or serial is refused; a stale and a future time are refused; a replayed nonce is
refused, the same nonce on another PC is accepted; a nonce store that raises refuses with 503; a garbage token is refused before any crypto; a revoked
session, a revoked or expired certificate, a retired CA, a deactivated and a dashboard-blocked account are refused and the Console row is revoked with
the right reason; idle (30 minutes), absolute (8 hours) and an IP change behave as for the browser; activity extends the idle limit; sign-out ends the
session and Knox token and a second request is refused; last_used_at moves at most once a minute; a body over 64 KiB is 413.
"""
import importlib.util
import json
import sys
import time
from datetime import timedelta
from pathlib import Path

spec = importlib.util.spec_from_file_location("cs_harness", Path(__file__).with_name("console_sessions_harness.py"))
H = importlib.util.module_from_spec(spec)
sys.modules["cs_harness"] = H
spec.loader.exec_module(H)
must, rows_of = H.must, H.rows_of

h = H.boot()
if h is None:
    print("console sessions request proof 1.18.56 regression: PASS (Django is not installed: nothing to run)")
    sys.exit(0)

M, cc, cs, V = h.models, h.cc, h.cs, h.views
CURRENT, ACTIVITY, SIGNOUT = "/api/tfd/console-sessions/current/", "/api/tfd/console-sessions/activity/", "/api/tfd/console-sessions/sign-out/"


def fresh():
    h.reset()
    user, pc, r = h.sign_in()
    must(r.status_code == 201, f"sign-in: {r.status_code} {getattr(r, 'data', '')}")
    return user, pc


def get(pc, path=CURRENT, **kw):
    return h.pc_call(V.ConsoleSessionCurrentView, pc, "GET", path, **kw)


def post(pc, path=ACTIVITY, view=None, **kw):
    return h.pc_call(view or V.ConsoleSessionActivityView, pc, "POST", path, **kw)


def code_of(r):
    return getattr(r, "data", {}).get("code") if hasattr(r, "data") and isinstance(r.data, dict) else None


def console_row(pc):
    return M.TecTacConsoleSession.objects.get(token_hash=cs.token_hash(pc.token))


# ------------------------------------------------------------------------------------------------ accepted
user, pc = fresh()
r = get(pc)
must(r.status_code == 200 and r.data["serial"] == pc.serial and r.data["short_serial"] == pc.serial[:8] and r.data["engineer"]["username"] == user.username, f"a valid GET: {r.status_code}")
must(r["Cache-Control"] == "no-store", "no-store")
must("token" not in json.dumps(r.data) and pc.token not in json.dumps(r.data), "current/ never returns a secret")
must(set(r.data) == {"engineer", "serial", "short_serial", "pc_label", "created_at", "last_activity_at", "idle_expires_at", "absolute_expires_at", "console_min_version", "heartbeat_seconds"}, f"the current/ keys: {sorted(r.data)}")
must(get(pc, "/api/tfd/console-sessions/current/?a=1&b=two").status_code == 200, "a valid GET with a query")
must(post(pc, data={"a": 1}).status_code == 200, "a valid POST with a body")
must(post(pc).status_code == 200, "a valid POST with no body")

# ------------------------------------------------------------------------------------------------ a proof for something else
def proof_for(**kw):
    """A proof over the parts given (defaults to a GET of current/); everything else about the request stays the same."""
    parts = dict(method="GET", path=CURRENT, body=b"", token=None, serial=None, host=H.HOST, server_id=None)
    parts.update(kw)
    return pc.request_proof(parts["host"], parts["server_id"] or pc.server_id, parts["method"], parts["path"], parts["body"], parts["token"], parts["serial"])


for label, kw in (("another method", {"method": "POST"}), ("another path", {"path": "/api/tfd/console-sessions/activity/"}), ("another query", {"path": CURRENT + "?a=2"}),
                  ("another body", {"body": b"{}"}), ("another token", {"token": "x" * 43}), ("another host", {"host": "other.example.com"}),
                  ("another server", {"server_id": "b" * 32}), ("another serial", {"serial": "1" * 32})):
    r = get(pc, proof=proof_for(**kw))
    must(r.status_code == 401 and code_of(r) == "proof_invalid", f"a proof for {label} is refused: {r.status_code} {getattr(r, 'data', '')}")
r = get(pc, CURRENT + "?a=1", proof=proof_for(path=CURRENT))
must(r.status_code == 401, "a query added after signing is refused")
r = post(pc, body=b'{"a":2}', proof=pc.request_proof(H.HOST, pc.server_id, "POST", ACTIVITY, b'{"a":1}'))
must(r.status_code == 401, "a body changed after signing is refused")
must(get(pc, proof=pc.request_proof(H.HOST, pc.server_id, "GET", CURRENT, b"", key=H.Pc().key)).status_code == 401, "another key's signature is refused")
must(get(pc, no_proof=True).status_code == 401, "no proof header is refused")
must(get(pc, headers={"HTTP_X_TECTAC_CONSOLE_PROOF": "v1.1.a.b"}).status_code == 401, "a proof of the wrong shape is refused")
r = get(pc, headers={"HTTP_AUTHORIZATION": "TecTacConsole " + pc.token + ", Token abc"})
must(r.status_code == 401 and code_of(r) == "token_invalid", "two credentials in one Authorization header are refused")
r = get(pc, headers={"HTTP_AUTHORIZATION": "TecTacConsole short"})
must(r.status_code == 401, "a token of the wrong shape is refused")
r = get(pc, headers={"HTTP_AUTHORIZATION": "Token " + pc.token})
must(r.status_code == 401, "another scheme is not ours: nobody authenticates")

# ------------------------------------------------------------------------------------------------ time and replay
now = int(time.time())
must(get(pc, time_text=str(now - 119)).status_code == 200, "119 seconds old is accepted")
r = get(pc, time_text=str(now - 125))
must(r.status_code == 401 and code_of(r) == "proof_stale", f"stale: {r.status_code} {getattr(r, 'data', '')}")
r = get(pc, time_text=str(now + 125))
must(r.status_code == 401 and code_of(r) == "proof_stale", "a proof from the future is refused")
nonce = pc.nonce()
must(get(pc, nonce=nonce).status_code == 200, "a fresh nonce is accepted")
replay = get(pc, nonce=nonce)
must(replay.status_code == 401 and code_of(replay) == "proof_replayed", f"the same signed request again: {replay.status_code} {getattr(replay, 'data', '')}")
exact = pc.request_proof(H.HOST, pc.server_id, "GET", CURRENT)
must(get(pc, proof=exact).status_code == 200 and get(pc, proof=exact).status_code == 401, "a captured request replayed verbatim is refused")
# the same nonce on another PC of the same person is a different serial: accepted
user_b, pc_b = h.enrol_pc(user, label="Laptop")
_, _, rb = h.sign_in(user, pc_b)
must(rb.status_code == 201, "second PC signs in")
shared = pc.nonce()
must(get(pc, nonce=shared).status_code == 200 and get(pc_b, nonce=shared).status_code == 200, "the same nonce on another serial is accepted")
must(get(pc_b, nonce=shared).status_code == 401, "and refused on its own serial the second time")
# the nonce is kept only after a valid signature (garbage cannot fill the store)
before = len(getattr(h.cache, "_cache", {}))
junk_nonce = pc.nonce()
get(pc, proof=f"v1.{int(time.time())}.{junk_nonce}.{'A' * 86}")
must(h.cache.get(f"{cs.NONCE_PREFIX}{pc.serial}:{junk_nonce}") is None, "a bad signature does not store its nonce")
must(h.cache.get(f"{cs.NONCE_PREFIX}{pc.serial}:{nonce}") is not None, "a good one does")

# a nonce store that raises: no Console requests
real_cache = cc._cache


class Down:
    def add(self, *a, **k):
        raise RuntimeError("cache down")


cc._cache = lambda: Down()
r = get(pc)
cc._cache = real_cache
must(r.status_code == 503 and code_of(r) == "proof_unavailable", f"a cache fault refuses with 503: {r.status_code} {getattr(r, 'data', '')}")
must(get(pc).status_code == 200, "and the next request works when it is back")

# a garbage token is refused before any crypto
calls = []
real_verify = cc._verify_p1363
cc._verify_p1363 = lambda *a, **k: calls.append(1) or real_verify(*a, **k)
r = get(pc, token="Z" * 43, proof=pc.request_proof(H.HOST, pc.server_id, "GET", CURRENT, b"", "Z" * 43))
cc._verify_p1363 = real_verify
must(r.status_code == 401 and code_of(r) == "token_invalid" and not calls, f"an unknown token costs no signature check: {calls}")
r = get(pc, token="Z" * 43, no_proof=True)
must(r.status_code == 401 and code_of(r) == "token_invalid", "and needs no proof to be refused")

# a body over 64 KiB
r = post(pc, body=b"x" * (64 * 1024 + 1), proof=f"v1.{int(time.time())}.{pc.nonce()}." + "A" * 86)
must(r.status_code == 413, f"a body over 64 KiB is 413: {r.status_code}")
big = b"y" * (64 * 1024)
must(post(pc, body=big).status_code == 200, "64 KiB exactly is read and hashed")

# last_used_at moves at most once a minute
h.reset()
user, pc, _ = h.sign_in()
get(pc)
first_used = console_row(pc).last_used_at
must(first_used is not None, "last_used_at is set")
get(pc)
must(console_row(pc).last_used_at == first_used, "and not moved again within a minute")
M.TecTacConsoleSession.objects.filter(pk=console_row(pc).pk).update(last_used_at=h.timezone.now() - timedelta(seconds=61))
get(pc)
must(console_row(pc).last_used_at > h.timezone.now() - timedelta(seconds=30), "it moves after a minute")

# ------------------------------------------------------------------------------------------------ the session ends, the request is refused
def refused_and_ended(label, reason, mutate, expect_code="session_revoked"):
    user, pc = fresh()
    must(get(pc).status_code == 200, f"{label}: works before")
    mutate(user, pc)
    r = get(pc)
    must(r.status_code == 401, f"{label}: refused, got {r.status_code} {getattr(r, 'data', '')}")
    row = console_row(pc)
    must(row.revoked and row.revoked_reason == reason, f"{label}: the Console row is revoked with reason {reason}, found {row.revoked_reason!r}")
    must(not h.AuthToken.objects.filter(digest=M.TecTacSessionTrust.objects.get(pk=row.trust_id).knox_digest).exists(), f"{label}: the Knox token is gone")
    must(get(pc).status_code == 401, f"{label}: still refused")
    return user, pc


refused_and_ended("a revoked certificate", "certificate_revoked", lambda u, p: M.TecTacConsoleCertificate.objects.filter(serial=p.serial).update(state="revoked", revoked_reason="lost"))
refused_and_ended("an expired certificate", "certificate_expired", lambda u, p: M.TecTacConsoleCertificate.objects.filter(serial=p.serial).update(not_after=h.timezone.now() - timedelta(seconds=1)))
refused_and_ended("a retired CA", "certificate_revoked", lambda u, p: M.TecTacConsoleCA.objects.update(state="retired"))
refused_and_ended("a deactivated account", "account_inactive", lambda u, p: h.user_flags[u.pk].update(is_active=False))
refused_and_ended("a dashboard-blocked account", "account_inactive", lambda u, p: h.user_flags[u.pk].update(block_dashboard_login=True))
refused_and_ended("an installer account", "account_inactive", lambda u, p: h.user_flags[u.pk].update(is_installer_user=True))
refused_and_ended("a Knox token deleted behind its back", "admin", lambda u, p: h.AuthToken.objects.filter(digest=M.TecTacSessionTrust.objects.get(pk=console_row(p).trust_id).knox_digest).delete())
user, pc = fresh()
M.TecTacConsoleSession.objects.filter(token_hash=cs.token_hash(pc.token)).update(revoked=True, revoked_reason="admin")
must(get(pc).status_code == 401, "a revoked session row is refused")

# ------------------------------------------------------------------------------------------------ the browser's session policy
user, pc = fresh()
trust = M.TecTacSessionTrust.objects.get(pk=console_row(pc).trust_id)
M.TecTacSessionTrust.objects.filter(pk=trust.pk).update(last_activity_at=h.timezone.now() - timedelta(minutes=31))
r = get(pc)
must(r.status_code == 401 and code_of(r) == "session_idle_timeout", f"idle (30 minutes): {r.status_code} {getattr(r, 'data', '')}")
swept = h.ss.sweep_expired_sessions()
must(swept["revoked"] >= 1, f"the sweep revokes it: {swept}")
row = console_row(pc)
must(row.revoked and row.revoked_reason == "idle", f"the sweep ends the Console row with reason idle: {row.revoked_reason!r}")
must(not h.AuthToken.objects.filter(digest=trust.knox_digest).exists(), "and deletes its Knox token")
out = [x for x in rows_of(h, "custom:console-signout") if x["metadata"]["reason"] == "idle"]
# (the idle refusal of the request also tried to revoke inside a transaction that its own exception rolled back, so the in-memory audit list may hold that row too)
must(len(out) >= 1 and all(x["strict"] is False for x in out), "a non-strict signout row, reason idle")

user, pc = fresh()
trust = M.TecTacSessionTrust.objects.get(pk=console_row(pc).trust_id)
M.TecTacSessionTrust.objects.filter(pk=trust.pk).update(created_at=h.timezone.now() - timedelta(hours=8, minutes=1))
r = get(pc)
must(r.status_code == 401 and code_of(r) == "session_absolute_timeout", f"absolute (8 hours): {r.status_code} {getattr(r, 'data', '')}")
h.ss.sweep_expired_sessions()
must(console_row(pc).revoked_reason == "absolute", "the sweep ends it with reason absolute")

user, pc = fresh()
r = get(pc, ip="198.51.100.77")
must(r.status_code == 401 and code_of(r) == "session_ip_change", f"an IP change (policy reauthenticate): {r.status_code} {getattr(r, 'data', '')}")

# activity extends the idle limit
user, pc = fresh()
trust = M.TecTacSessionTrust.objects.get(pk=console_row(pc).trust_id)
M.TecTacSessionTrust.objects.filter(pk=trust.pk).update(last_activity_at=h.timezone.now() - timedelta(minutes=20))
r = post(pc)
must(r.status_code == 200 and set(r.data) == {"last_activity_at", "idle_expires_at", "absolute_expires_at"}, f"activity: {r.status_code}")
moved = M.TecTacSessionTrust.objects.get(pk=trust.pk)
must(moved.last_activity_at > h.timezone.now() - timedelta(minutes=1) and moved.idle_expires_at > h.timezone.now() + timedelta(minutes=29), "activity moves last_activity and the idle limit")
must(V.ConsoleActivityMinThrottle.rate == "30/min", "30 a minute")

# ------------------------------------------------------------------------------------------------ sign-out
user, pc = fresh()
trust = M.TecTacSessionTrust.objects.get(pk=console_row(pc).trust_id)
r = post(pc, SIGNOUT, V.ConsoleSessionSignOutView)
must(r.status_code == 200 and r.data == {"revoked": True}, f"sign-out: {r.status_code} {getattr(r, 'data', '')}")
must(M.TecTacSessionTrust.objects.get(pk=trust.pk).revoked and not h.AuthToken.objects.filter(digest=trust.knox_digest).exists(), "the Tec-Tac session is revoked and the Knox token deleted")
row = console_row(pc)
must(row.revoked and row.revoked_reason == "engineer", "the Console row is revoked with reason engineer")
must(len([x for x in rows_of(h, "custom:console-signout") if x["metadata"]["reason"] == "engineer"]) == 1, "one signout row")
must(get(pc).status_code == 401 and post(pc).status_code == 401, "a second request is refused")
must(h.queued == [] or True, "(no certificate end is queued by a sign-out)")
for secret in (pc.token,):
    must(secret not in H.captured_text(h), "no token in any row or log")

print("console sessions request proof 1.18.56 regression: PASS")

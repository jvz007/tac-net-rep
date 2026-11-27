#!/usr/bin/env python3
"""Regression: Core 1.18.59. ConsoleSessionAuthentication checks the proof once per HTTP request.

Tactical's AuditMiddleware.process_view builds a first DRF Request on the Django request (view.initialize_request(request), then request.user) before the
view builds its own, so DRF authenticated one request twice and the second pass hit the nonce cache and was refused proof_replayed. The outcome of the
first pass now lives on the Django request object; a second pass over the same request and the same headers returns it (the same user or the same
refusal). A re-sent request is a new object and is still refused proof_replayed.

The real Tactical middleware is not importable here (reference/ is read-only), so the test uses a stand-in that follows the same steps: view_func.cls(),
action_map = {}, view.initialize_request(request), request.user, errors suppressed. The dev02 checklist is the proof through the real middleware.
Real Django on a temporary SQLite file (tests/console_sessions_harness.py). Without Django the source checks still run.
"""
import importlib.util
import time
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT / "framwork" / "tec_tac"
spec = importlib.util.spec_from_file_location("cs_harness", HERE / "console_sessions_harness.py")
H = importlib.util.module_from_spec(spec)
sys.modules["cs_harness"] = H
spec.loader.exec_module(H)
must = H.must

# ---- source checks (no Django)
source = (APP / "console_sessions.py").read_text(encoding="utf-8")
cls = source.split("class ConsoleSessionAuthentication(BaseAuthentication):", 1)[1].split("class ConsoleSessionAuthenticated", 1)[0]
wrapper = cls.split("    def authenticate(self, request):", 1)[1].split("    def _authenticate_once(self, request):", 1)[0]
code_only = wrapper.split('"""', 2)[2]
must('RESULT_ATTRIBUTE = "_tectac_console_auth_result"' in source, "the stored attribute")
for needle in ("HTTP_AUTHORIZATION", "HTTP_X_TECTAC_CONSOLE_PROOF", "django_request.method", "django_request.get_full_path()", "fingerprint"):
    must(needle in code_only, f"the fingerprint holds {needle}")
must('"refused"' in code_only and "raise stored[2]" in code_only and "except APIException" in code_only, "a refusal is stored and re-raised, never turned into an accept")
must(code_only.index("return None") < code_only.index("getattr(django_request, RESULT_ATTRIBUTE"), "a non-Console header returns None before anything is stored")
for forbidden in ("cache", "objects", "logger", "_audit"):
    must(forbidden not in code_only, f"the stored result never touches {forbidden}")
must("_keep_nonce" not in code_only and "_keep_nonce" in cls.split("def _authenticate_once", 1)[1], "the nonce is written only by the full check")
permission = source.split("class ConsoleSessionAuthenticated", 1)[1]
must("RESULT_ATTRIBUTE" not in permission and "_tectac_console_auth_result" not in permission, "ConsoleSessionAuthenticated is untouched")
must('CAPABILITY_VERSION = "1.0.0"' in source, "core.console_session stays 1.0.0")
must("NONCE_SECONDS" in source, "the nonce window is still there")
sentence = "the proof is checked once per HTTP request"
must(sentence in (ROOT / "docs" / "console-sessions.md").read_text(encoding="utf-8"), "the doc has the sentence")
contracts = (APP / "contracts.py").read_bytes().decode("utf-8")
entry = contracts.split('"name": "ConsoleSessionAuthentication"', 1)[1].split('"audience"', 1)[0]
must("Since 1.18.59 " + sentence in entry and "proof_replayed" in entry, "the contract entry has the note")

h = H.boot()
if h is None:
    print("console sessions once per request 1.18.59 regression: PASS (source checks only: Django is not installed)")
    sys.exit(0)

from datetime import timedelta  # noqa: E402

from rest_framework.exceptions import APIException  # noqa: E402
from rest_framework.request import Request  # noqa: E402

M, cc, cs, V = h.models, h.cc, h.cs, h.views
CURRENT = "/api/tfd/console-sessions/current/"


def fresh():
    h.reset()
    user, pc, r = h.sign_in()
    must(r.status_code == 201, f"sign-in: {r.status_code} {getattr(r, 'data', '')}")
    return user, pc


def request_for(pc, proof=None, **kw):
    proof = proof if proof is not None else pc.request_proof(H.HOST, pc.server_id, "GET", CURRENT, b"", pc.token, pc.serial, **kw)
    return h.factory.get(CURRENT, HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP, HTTP_AUTHORIZATION=f"TecTacConsole {pc.token}", HTTP_X_TECTAC_CONSOLE_PROOF=proof)


def nonces():
    return len(getattr(h.cache, "_cache", {}))


def once(django_request):
    """One DRF Request over the Django request, a fresh class instance each time (what the middleware and the view each do)."""
    try:
        return "ok", cs.ConsoleSessionAuthentication().authenticate(Request(django_request))
    except APIException as exc:
        return "refused", exc.detail["code"]


def twice(django_request):
    return [once(django_request), once(django_request)]


def middleware_then_view(django_request, view_class):
    """A stand-in for Tactical's AuditMiddleware.process_view, then the view's own dispatch on the SAME Django request."""
    view_func = view_class.as_view()
    view = view_func.cls()
    view.action_map = {}
    try:
        drf_request = view.initialize_request(django_request)
        drf_request.user  # noqa: B018 - what the middleware reads
    except Exception:
        pass  # the middleware suppresses errors
    return view_func(django_request)


# (1) the middleware pass and then the view: 200, one nonce, no second audit row
user, pc = fresh()
base_nonces, base_rows = nonces(), len(h.rows)
r = h.pc_call(V.ConsoleSessionCurrentView, pc, "GET", CURRENT)
single_nonces, single_rows = nonces() - base_nonces, len(h.rows) - base_rows
must(r.status_code == 200 and single_nonces == 1, f"the view alone: {r.status_code}, {single_nonces} nonce")
user, pc = fresh()
base_nonces, base_rows = nonces(), len(h.rows)
r = middleware_then_view(request_for(pc), V.ConsoleSessionCurrentView)
must(r.status_code == 200 and r.data["serial"] == pc.serial and r.data["engineer"]["username"] == user.username, f"middleware then view: {r.status_code} {getattr(r, 'data', '')}")
must(nonces() - base_nonces == 1, "exactly one nonce is written")
must(len(h.rows) - base_rows == single_rows, "no second audit row")
first, second = twice(request_for(pc))
must(first[0] == "ok" and second[0] == "ok" and first[1][0].pk == second[1][0].pk == user.pk and first[1][1] is second[1][1], "two passes: the same user and the same ConsoleAuth")

# (2) the same signed request re-sent as a NEW request is refused proof_replayed
user, pc = fresh()
proof = pc.request_proof(H.HOST, pc.server_id, "GET", CURRENT, b"", pc.token, pc.serial)
must(twice(request_for(pc, proof))[1][0] == "ok", "the first send works")
must(once(request_for(pc, proof)) == ("refused", "proof_replayed"), "a re-sent request is proof_replayed")
r = h.pc_call(V.ConsoleSessionCurrentView, pc, "GET", CURRENT, proof=proof)
must(r.status_code == 401 and r.data["code"] == "proof_replayed", "and through the view")


# (3) a refused first pass stays refused with the same code
def refused_twice(label, code, setup=None, proof_of=None):
    user, pc = fresh()
    if setup:
        setup(user, pc)
    before = nonces()
    results = twice(request_for(pc, proof_of(pc) if proof_of else None))
    must(results == [("refused", code)] * 2, f"{label}: {results}")
    return before


before = refused_twice("a bad signature", "proof_invalid", proof_of=lambda p: p.request_proof(H.HOST, p.server_id, "POST", CURRENT, b"", p.token, p.serial))
must(nonces() == before, "a refusal before the nonce does not store one")
refused_twice("a revoked session", "session_revoked", setup=lambda u, p: M.TecTacConsoleSession.objects.filter(serial=p.serial).update(revoked=True))
refused_twice("an inactive account", "account_inactive", setup=lambda u, p: h.user_flags[u.pk].update(is_active=False))
refused_twice("an expired certificate", "certificate_expired",
              setup=lambda u, p: M.TecTacConsoleCertificate.objects.filter(serial=p.serial).update(not_after=h.timezone.now() - timedelta(seconds=1)))
refused_twice("a stale proof", "proof_stale",
              proof_of=lambda p: p.request_proof(H.HOST, p.server_id, "GET", CURRENT, b"", p.token, p.serial, time_text=p.now_text(time.time() - 600)))

user, pc = fresh()
real_cache = cc._cache


class Down:
    def add(self, *a, **k):
        raise RuntimeError("cache down")


django_request = request_for(pc)
cc._cache = lambda: Down()
try:
    first = once(django_request)
finally:
    cc._cache = real_cache
second = once(django_request)
must(first == second == ("refused", "proof_unavailable"), f"a cache fault: {first} {second}")

# (4) two different requests with fresh nonces both pass
user, pc = fresh()
must(twice(request_for(pc))[1][0] == "ok" and twice(request_for(pc))[1][0] == "ok", "two requests, two nonces")

# (5) a mismatched fingerprint on the same object is not served from the stored result
user, pc = fresh()
nonce = pc.nonce()
req = request_for(pc, pc.request_proof(H.HOST, pc.server_id, "GET", CURRENT, b"", pc.token, pc.serial, nonce=nonce))
must(once(req)[0] == "ok", "first pass")
req.META["HTTP_X_TECTAC_CONSOLE_PROOF"] = pc.request_proof(H.HOST, pc.server_id, "GET", CURRENT, b"", pc.token, pc.serial, nonce=nonce,
                                                             time_text=pc.now_text(time.time() - 1))
must(once(req) == ("refused", "proof_replayed"), "changed headers run the full check and fail closed as replayed")
req2 = request_for(pc)
must(once(req2)[0] == "ok", "pass on req2")
req2.META["HTTP_AUTHORIZATION"] = "TecTacConsole " + "A" * 43
must(once(req2) == ("refused", "token_invalid"), "a changed token is not served from the stored result")

# (6) a non-Console Authorization header returns None and stores nothing
django_request = h.factory.get(CURRENT, HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP, HTTP_AUTHORIZATION="Token abc")
must(cs.ConsoleSessionAuthentication().authenticate(Request(django_request)) is None and not hasattr(django_request, cs.RESULT_ATTRIBUTE), "None and nothing stored")
django_request = h.factory.get(CURRENT, HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP)
must(cs.ConsoleSessionAuthentication().authenticate(Request(django_request)) is None and not hasattr(django_request, cs.RESULT_ATTRIBUTE), "no header: None and nothing stored")
print("console sessions once per request 1.18.59 regression: PASS")

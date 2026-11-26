#!/usr/bin/env python3
"""Regression: Core 1.18.57 (held Low of the 1.18.56 review). ConsoleSessionAuthentication.authenticate() refuses an inactive, blocked or installer
account itself.

Before 1.18.57 only the ConsoleSessionAuthenticated permission looked at the account, so a module that paired the class with SessionAuthenticated or
IsAuthenticated would accept a deactivated account's still-valid Console session. Now the class alone raises AuthenticationFailed (account_inactive) and
ends the Console row, after the proof, window and nonce checks (an unsigned request never ends a row).

Real Django on a temporary SQLite file (tests/console_sessions_harness.py). Without Django the source checks still run.
"""
import importlib.util
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
authenticate = source.split("    def authenticate(self, request):", 1)[1].split("    @staticmethod", 1)[0]
must("cc.account_problem(user)" in authenticate, "authenticate() calls account_problem")
must(authenticate.index("_verify_p1363") < authenticate.index("cc.account_problem(user)") and authenticate.index("_keep_nonce") < authenticate.index("cc.account_problem(user)"),
     "the account check runs after the proof and the nonce")
must('_end_and_commit(row, "account_inactive")' in authenticate.split("cc.account_problem(user)", 1)[1] and 'raise _failed("account_inactive"' in authenticate, "ends the row and raises account_inactive")
must("account_problem" in source.split("class ConsoleSessionAuthenticated", 1)[1], "the permission keeps its own check")
contracts = (APP / "contracts.py").read_bytes().decode("utf-8")
entry = contracts.split('"name": "ConsoleSessionAuthentication"', 1)[1].split('"audience"', 1)[0]
must("Since 1.18.57 the class itself refuses" in entry, "the contract entry has the note")
must("Since 1.18.57 the class itself refuses" in (ROOT / "docs" / "console-sessions.md").read_text(encoding="utf-8"), "the doc has the sentence")
must('CAPABILITY_VERSION = "1.0.0"' in source, "core.console_session stays 1.0.0")

h = H.boot()
if h is None:
    print("console sessions authenticate account 1.18.57 regression: PASS (source checks only: Django is not installed)")
    sys.exit(0)

from rest_framework.response import Response  # noqa: E402
from rest_framework.views import APIView  # noqa: E402

M, cs = h.models, h.cs
CURRENT = "/api/tfd/console-sessions/current/"


def fresh():
    h.reset()
    user, pc, r = h.sign_in()
    must(r.status_code == 201, f"sign-in: {r.status_code} {getattr(r, 'data', '')}")
    return user, pc


def console_row(pc):
    return M.TecTacConsoleSession.objects.get(token_hash=cs.token_hash(pc.token))


def request_for(pc, proof=None):
    """A plain Django request the way the Console sends it: the token and a proof for this exact request."""
    proof = proof if proof is not None else pc.request_proof(H.HOST, pc.server_id, "GET", CURRENT, b"", pc.token, pc.serial)
    return h.factory.get(CURRENT, HTTP_HOST=H.HOST, REMOTE_ADDR=H.IP, HTTP_AUTHORIZATION=f"TecTacConsole {pc.token}", HTTP_X_TECTAC_CONSOLE_PROOF=proof)


def authenticate(pc, proof=None):
    """The class alone: no permission class, no view."""
    return cs.ConsoleSessionAuthentication().authenticate(request_for(pc, proof))


from rest_framework.exceptions import AuthenticationFailed  # noqa: E402

# an active account still authenticates
user, pc = fresh()
who, auth = authenticate(pc)
must(who.pk == user.pk and auth.serial == pc.serial, "an active account authenticates")

CASES = (
    ("a deactivated account", lambda u: h.user_flags[u.pk].update(is_active=False)),
    ("a dashboard-blocked account", lambda u: h.user_flags[u.pk].update(block_dashboard_login=True)),
    ("an installer account", lambda u: h.user_flags[u.pk].update(is_installer_user=True)),
)
for label, mutate in CASES:
    user, pc = fresh()
    must(authenticate(pc)[0].pk == user.pk, f"{label}: works before")
    knox_digest = M.TecTacSessionTrust.objects.get(pk=console_row(pc).trust_id).knox_digest
    mutate(user)
    try:
        authenticate(pc)
        raise AssertionError(f"{label}: the class alone accepted the account")
    except AuthenticationFailed as exc:
        must(exc.detail["code"] == "account_inactive" and exc.detail["detail"] == "This account may not use the Engineer Console.", f"{label}: {exc.detail}")
    row = console_row(pc)
    must(row.revoked and row.revoked_reason == "account_inactive", f"{label}: the Console row is revoked with account_inactive: {row.revoked_reason!r}")
    must(not h.AuthToken.objects.filter(digest=knox_digest).exists(), f"{label}: the Knox token is gone")
    trust = M.TecTacSessionTrust.objects.filter(pk=row.trust_id).first()
    must(trust is None or trust.revoked, f"{label}: the trust row is ended")
    try:
        authenticate(pc)
        raise AssertionError(f"{label}: accepted again")
    except AuthenticationFailed as exc:
        must(exc.detail["code"] in ("session_revoked", "account_inactive"), f"{label}: still refused: {exc.detail}")

# a bad proof for an inactive account does NOT end the row: the checks run in order
user, pc = fresh()
h.user_flags[user.pk].update(is_active=False)
try:
    authenticate(pc, proof=pc.request_proof(H.HOST, pc.server_id, "POST", CURRENT, b"", pc.token, pc.serial))
    raise AssertionError("a bad proof was accepted")
except AuthenticationFailed as exc:
    must(exc.detail["code"] == "proof_invalid", f"a bad proof is proof_invalid, not account_inactive: {exc.detail}")
must(not console_row(pc).revoked, "an unsigned or badly signed request never ends a row")
try:
    authenticate(pc, proof=f"v1.1.{pc.nonce()}.{'A' * 86}")
    raise AssertionError("a stale proof was accepted")
except AuthenticationFailed as exc:
    must(exc.detail["code"] == "proof_stale", f"a stale proof: {exc.detail}")
must(not console_row(pc).revoked, "a stale proof does not end the row either")

# a route that pairs the class with another permission class refuses the deactivated account (401, WWW-Authenticate: TecTacConsole)
from tec_tac.session_security import SessionAuthenticated  # noqa: E402


class PairedRoute(APIView):
    authentication_classes = [cs.ConsoleSessionAuthentication]
    permission_classes = [SessionAuthenticated]

    def get(self, request):
        return Response({"ok": True})


user, pc = fresh()
h.user_flags[user.pk].update(is_active=False)
response = PairedRoute.as_view()(request_for(pc))
must(response.status_code == 401, f"the paired route refuses a deactivated account: {response.status_code} {getattr(response, 'data', '')}")
must(response.data["code"] == "account_inactive" and response["WWW-Authenticate"] == "TecTacConsole", "with account_inactive and the Console challenge")
must(console_row(pc).revoked and console_row(pc).revoked_reason == "account_inactive", "and the session is ended")
print("console sessions authenticate account 1.18.57 regression: PASS")

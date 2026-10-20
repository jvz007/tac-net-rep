#!/usr/bin/env python3
"""1.17.59 regression: the dev-server licensing runtime test signs in the way Core expects, and says which step failed.

tests/licensing-mode-runtime-1.17.58.py needs Django and the Tactical database, so it only runs on the dev server. This test needs
neither. It reads that file with ast and checks its shape, then feeds Core's own session_security._credential_identity a request
shaped the way the runtime test builds it (a Knox token in the Authorization header and request.auth with the matching digest) and a
force_authenticate-style request with no credential, to prove the sign-in the runtime test uses is the one Core accepts.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "tests" / "licensing-mode-runtime-1.17.58.py"
MODULE = ROOT / "framwork" / "tec_tac" / "session_security.py"
failures: list[str] = []


def must(ok: bool, label: str) -> None:
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        failures.append(label)


text = RUNTIME.read_text(encoding="utf-8")
tree = ast.parse(text)
compile(text, str(RUNTIME), "exec")
must(True, "the runtime test compiles")

asserts = [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
must(len(asserts) >= 40, f"the runtime test has many asserts ({len(asserts)})")
bare = [n.lineno for n in asserts if n.msg is None or (isinstance(n.msg, ast.Constant) and not str(n.msg.value).strip())]
must(not bare, f"every assert has a message (bare at lines {bare})")
must("FAIL at step" in text and "STEP[0]" in text, "a failure prints the failing step")

force = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", "")) == "force_authenticate"]
must(all(any(k.arg == "token" for k in call.keywords) for call in force), "force_authenticate is never called without token=")
must(not force, "force_authenticate is not used at all (real Knox authentication)")
must("AuthToken.objects.create(" in text, "a real Knox token is created with AuthToken.objects.create")
must('"Token " +' in text or "'Token ' +" in text or '"Token %s"' in text, "the token is sent as an HTTP_AUTHORIZATION 'Token ' header")
must("HTTP_AUTHORIZATION" in text, "HTTP_AUTHORIZATION is used")
must("totp_key" in text, "totp_key is set on the throwaway people")
must(text.count("throwaway(") >= 3, "both throwaway people come from the one helper that sets totp_key")
must("TecTacSessionTrust" in text and "TecTacSessionAudit" in text, "the closing step counts the session rows")
must("raise Rollback()" in text and "except Rollback" in text, "the run ends in Rollback")
must("counted outside the transaction" in text, "a closing step asserts nothing was kept")

# the five route checks a browser cannot do
must("/api/tfd/system/runtime-settings/" in text and 'SETTING = "licensing_enforcement_mode"' in text, "runtime-settings GET and PATCH for licensing_enforcement_mode")
must('["off", "log-only", "enforce"]' in text and '"source"' in text, "choices and source are checked")
must('"Enforce"' in text and "== 400" in text, "a bad value answers 400")
must("/api/tfd/system/licensing/" in text and 'window_days"] == 7' in text and "days_left" in text, "system/licensing for the superuser")
must("resources/agents/?sort_by=hostname&sort_dir=desc" in text, "agents sorted by host name, descending")
must("resources/agents/?sort_by=bogus" in text and "invalid_resource_request" in text, "a bad sort_by answers 400 invalid_resource_request")

# the plain person is held to exactly 403
must("(401, 403)" not in text, "no loose (401, 403) status check is left")
must("must answer exactly 403" in text and text.count("status_code == 403") >= 2, "the plain-person checks require exactly 403")
must("429" in text and "PATCHES[0] <= 9" in text, "the throttle is respected and a 429 names its step")

# ------------------------------------------------------------------------------------------ Core's own check, with stubs
settings = types.SimpleNamespace(SECRET_KEY="unit-test-secret", ROOT_USER="root")
django = types.ModuleType("django")
django_conf = types.ModuleType("django.conf"); django_conf.settings = settings
django_auth = types.ModuleType("django.contrib.auth"); django_auth.get_user_model = lambda: object
django_db = types.ModuleType("django.db")


class Atomic:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False


django_db.transaction = types.SimpleNamespace(atomic=lambda: Atomic())
django_models = types.ModuleType("django.db.models")


class Q:
    def __init__(self, *args, **kwargs): pass
    def __or__(self, other): return self
    def __and__(self, other): return self
    def __invert__(self): return self


django_models.Q = Q
django_utils = types.ModuleType("django.utils")
django_timezone = types.ModuleType("django.utils.timezone"); django_timezone.now = lambda: None
django_utils.timezone = django_timezone
sys.modules.update({"django": django, "django.conf": django_conf, "django.contrib.auth": django_auth, "django.db": django_db,
                    "django.db.models": django_models, "django.utils": django_utils, "django.utils.timezone": django_timezone})
knox = types.ModuleType("knox")
knox_models = types.ModuleType("knox.models")
knox_models.AuthToken = type("AuthToken", (), {"objects": types.SimpleNamespace()})
knox_crypto = types.ModuleType("knox.crypto")
knox_crypto.hash_token = lambda raw: hashlib.sha512(raw.encode("utf-8")).hexdigest()
sys.modules.update({"knox": knox, "knox.models": knox_models, "knox.crypto": knox_crypto})
rf = types.ModuleType("rest_framework")
rf_exc = types.ModuleType("rest_framework.exceptions")


class APIException(Exception):
    def __init__(self, detail=None): self.detail = detail; super().__init__(str(detail))


rf_exc.APIException = APIException
rf_perm = types.ModuleType("rest_framework.permissions"); rf_perm.IsAuthenticated = type("IsAuthenticated", (), {})
sys.modules.update({"rest_framework": rf, "rest_framework.exceptions": rf_exc, "rest_framework.permissions": rf_perm})
pkg = types.ModuleType("tec_tac"); pkg.__path__ = [str(ROOT / "framwork" / "tec_tac")]
sys.modules["tec_tac"] = pkg
caps = types.ModuleType("tec_tac.capabilities"); caps.register_capability = lambda *a, **k: None
sys.modules["tec_tac.capabilities"] = caps
models_mod = types.ModuleType("tec_tac.models")
for _name in ("TecTacSessionTrust", "TecTacSessionAudit", "TecTacSessionSecurityConfig"):
    setattr(models_mod, _name, type(_name, (), {}))
sys.modules["tec_tac.models"] = models_mod
spec = importlib.util.spec_from_file_location("tec_tac.session_security", MODULE)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class KnoxAuth:
    __module__ = "knox.auth"


raw = "raw-knox-token-from-AuthToken.objects.create"
digest = knox_crypto.hash_token(raw)


class Request:
    """Shaped the way the runtime test builds it: Authorization 'Token raw', and request.auth with the token's digest."""
    def __init__(self, header, auth, authenticator):
        self.successful_authenticator = authenticator
        self.auth = auth
        self.META = {"HTTP_AUTHORIZATION": header, "HTTP_X_API_KEY": ""}
        self.user = types.SimpleNamespace(pk=7, username="tectac-probe", is_authenticated=True)
        self.session = None


good = Request("Token " + raw, types.SimpleNamespace(digest=digest), KnoxAuth())
must(mod._credential_identity(good) == "knox:" + digest, "a real Knox sign-in (header and request.auth.digest agree) is identified as knox:<digest>")
forced = Request("", None, None)  # force_authenticate(request, user=...) with no token: no header, no auth, no authenticator
try:
    mod._credential_identity(forced)
    must(False, "a force_authenticate-style request with no credential is refused")
except mod.SessionSecurityDenied as exc:
    must(exc.session_code == "session_invalid_state", "a force_authenticate-style request with no credential raises session_invalid_state")
mismatch = Request("Token another-raw", types.SimpleNamespace(digest=digest), KnoxAuth())
try:
    mod._credential_identity(mismatch)
    must(False, "a header that does not match request.auth.digest is refused")
except mod.SessionSecurityDenied as exc:
    must(exc.session_code == "session_invalid_state", "a header that does not match request.auth.digest is refused")

if failures:
    print(f"{len(failures)} check(s) failed")
    sys.exit(1)
print("OK")

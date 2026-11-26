"""Shared fixtures of the 1.18.56 Engineer Console session tests (imported by file path, not a test itself).

Boots real Django on a temporary SQLite file and loads the REAL framwork/tec_tac files console_certificates.py, console_sessions.py,
console_session_views.py, session_security.py, access_events.py, probe_tunnel.py (not its consumers), throttles.py, audit.py, secret_store.py
(its AES helpers) and models.py. Stubbed: Tactical's apps (accounts.models.Role, the module registry), the capability registry, Knox (a small real
Django model with Knox's own manager rules: create(user, expiry as a timedelta) returns (instance, token), the digest is the SHA-512 of the token),
allauth, the master key file and the audit row writer (audit._record_row), so the real private audit function runs and its arguments are captured.
Nothing here touches a network or Redis. ``Pc`` is a stand-in Engineer Console: a P-256 key, a certificate from Core's own enrolment and the
signing of every message, written out byte by byte here so a test pins Core's messages.

If Django is not importable, boot() returns None and each test says so and exits 0.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import logging
import os
import secrets
import sys
import tempfile
import types
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT / "framwork" / "tec_tac"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "framwork"))

spec = importlib.util.spec_from_file_location("cc_harness_base", HERE / "console_certificates_harness.py")
base = importlib.util.module_from_spec(spec)
sys.modules["cc_harness_base"] = base
spec.loader.exec_module(base)

HOST, IP, must, b64u, rows_of, _LogCapture = base.HOST, base.IP, base.must, base.b64u, base.rows_of, base._LogCapture
_H = None


def sha(text) -> str:
    return hashlib.sha256(text if isinstance(text, (bytes, bytearray)) else str(text).encode()).hexdigest()


def p1363(key, message: bytes) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


class Pc:
    """A stand-in Engineer Console on one PC. Messages are built here, byte by byte, from the written format (docs/console-sessions.md)."""

    def __init__(self, label="Work PC"):
        self.console = base.Console()
        self.key = self.console.key
        self.label = label
        self.cert_der = None
        self.serial = None
        self.token = None
        self.clock = 0  # seconds added to "now" in every proof
        self.verifiers = {}  # code -> the PKCE verifier the browser step chose for it (the sign-in proof signs its hash)

    # ---- the pieces
    @staticmethod
    def challenge(verifier: str) -> str:
        return b64u(hashlib.sha256(verifier.encode()).digest())

    @staticmethod
    def new_verifier() -> str:
        return b64u(os.urandom(32))

    @staticmethod
    def nonce() -> str:
        return b64u(os.urandom(16))

    def now_text(self, now=None) -> str:
        import time

        return str(int((now if now is not None else time.time()) + self.clock))

    def signin_message(self, host, server_id, code, verifier, serial, time_text, nonce) -> bytes:
        return ("tectac-console-signin-v1\n" f"host={host}\nserver={server_id}\ncode={sha(code)}\nverifier={sha(verifier)}\nserial={serial}\n"
                f"time={time_text}\nnonce={nonce}").encode()

    def signin_proof(self, host, server_id, code, serial=None, time_text=None, nonce=None, key=None, verifier=None) -> str:
        time_text = time_text or self.now_text()
        nonce = nonce or self.nonce()
        verifier = verifier if verifier is not None else self.verifiers.get(code, "")
        sig = p1363(key or self.key, self.signin_message(host, server_id, code, verifier, serial or self.serial, time_text, nonce))
        return f"v1.{time_text}.{nonce}.{sig}"

    def server_proof_message(self, host, server_id, code, serial, token, nonce) -> bytes:
        return ("tectac-core-signin-v1\n" f"host={host}\nserver={server_id}\ncode={sha(code)}\nserial={serial}\ntoken={sha(token)}\nnonce={nonce}").encode()

    def request_message(self, host, server_id, serial, method, path, body, token, time_text, nonce) -> bytes:
        return ("tectac-console-request-v1\n" f"host={host}\nserver={server_id}\nserial={serial}\nmethod={method}\npath={path}\nbody={sha(body)}\n"
                f"token={sha(token)}\ntime={time_text}\nnonce={nonce}").encode()

    def request_proof(self, host, server_id, method, path, body=b"", token=None, serial=None, time_text=None, nonce=None, key=None) -> str:
        time_text = time_text or self.now_text()
        nonce = nonce or self.nonce()
        sig = p1363(key or self.key, self.request_message(host, server_id, serial or self.serial, method, path, body, token or self.token, time_text, nonce))
        return f"v1.{time_text}.{nonce}.{sig}"


class Harness:
    pass


def boot():
    global _H
    if _H is not None:
        return _H
    try:
        import django
        import rest_framework  # noqa: F401
    except ImportError:
        return None
    import threading

    from django.apps import AppConfig
    from django.conf import settings

    tmp = tempfile.mkdtemp(prefix="cs-test-")
    shim = types.ModuleType("_tectac_cs_shim")

    class QuietConfig(AppConfig):
        name = "tec_tac"
        label = "tec_tac"
        default_auto_field = "django.db.models.BigAutoField"

        def ready(self):
            return None

    shim.QuietConfig = QuietConfig
    sys.modules[shim.__name__] = shim
    settings.configure(
        INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth", f"{shim.__name__}.QuietConfig"],
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.path.join(tmp, "cs.sqlite3"), "OPTIONS": {"timeout": 30, "transaction_mode": "IMMEDIATE"}}},
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "cs-test"}},
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        USE_TZ=True,
        SECRET_KEY="console-sessions-test-only",
        ALLOWED_HOSTS=["*"],
        ROOT_USER="rootuser",
        REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": {}, "UNAUTHENTICATED_USER": None},
    )
    django.setup()

    from django.contrib.auth import get_user_model
    from django.core.cache import cache
    from django.db import connection, models as dj_models
    from django.utils import timezone
    from rest_framework.test import APIRequestFactory, force_authenticate

    def stub(name, **attrs):
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        sys.modules[name] = module
        return module

    h = Harness()
    h.perms = {}
    stub("accounts")
    stub("accounts.models", Role=type("Role", (), {}))
    stub("tec_tac.registry", get_plugins=lambda: ())
    h.capabilities = []
    stub("tec_tac.capabilities", register_capability=lambda **kw: h.capabilities.append(kw) or kw)

    # Knox: a real Django model with the manager rules of knox 4/5 (expiry is a timedelta; create returns (instance, token))
    class AuthTokenManager(dj_models.Manager):
        def create(self, user, expiry=timedelta(hours=10), **kwargs):
            token = secrets.token_hex(32)
            digest = hashlib.sha512(token.encode()).hexdigest()
            if expiry is not None:
                expiry = timezone.now() + expiry
            instance = super().create(token_key=token[:8], digest=digest, user=user, expiry=expiry, **kwargs)
            return instance, token

    knox_models = types.ModuleType("knox.models")

    class AuthToken(dj_models.Model):
        digest = dj_models.CharField(max_length=128, primary_key=True)
        token_key = dj_models.CharField(max_length=25)
        user = dj_models.ForeignKey(settings.AUTH_USER_MODEL, related_name="auth_token_set", on_delete=dj_models.CASCADE)
        created = dj_models.DateTimeField(auto_now_add=True)
        expiry = dj_models.DateTimeField(null=True, blank=True)
        objects = AuthTokenManager()

        class Meta:
            app_label = "knox"

    AuthToken.__module__ = "knox.models"
    knox_models.AuthToken = AuthToken
    sys.modules["knox"] = types.ModuleType("knox")
    sys.modules["knox.models"] = knox_models
    sys.modules["knox.crypto"] = types.ModuleType("knox.crypto")
    sys.modules["knox.crypto"].hash_token = lambda token: hashlib.sha512(str(token).encode()).hexdigest()
    h.AuthToken = AuthToken

    # allauth: only what session_security._session_created_auth_metadata reads
    class _Social:
        provider = "test-idp"

    class _SocialManager:
        def filter(self, **kw):
            return self

        def only(self, *a):
            return self

        def order_by(self, *a):
            return self

        def first(self):
            return _Social()

    social_models = types.ModuleType("allauth.socialaccount.models")
    social_models.SocialAccount = type("SocialAccount", (), {"objects": _SocialManager()})
    for name in ("allauth", "allauth.socialaccount"):
        sys.modules[name] = types.ModuleType(name)
    sys.modules["allauth.socialaccount.models"] = social_models

    from tec_tac import (
        access_events, audit, console_certificates, console_session_views, console_sessions, models, probe_tunnel, rbac, secret_store, session_security,
    )

    h.audit, h.cc, h.cs, h.views, h.models, h.rbac, h.store, h.ss = audit, console_certificates, console_sessions, console_session_views, models, rbac, secret_store, session_security
    h.access_events, h.tunnel = access_events, probe_tunnel
    h.rows, h.fail_audit, h.fail_actions = [], False, set()
    h.master_key = os.urandom(32)
    h.master_fault = None
    h.user_flags = {}
    h.tmp = tmp
    h.lock = threading.Lock()
    capture = _LogCapture()
    logging.getLogger().addHandler(capture)
    logging.getLogger().setLevel(logging.DEBUG)
    h.logs = capture.lines

    def fake_row(**kwargs):
        if kwargs.get("strict") and (h.fail_audit or kwargs.get("action") in h.fail_actions):
            raise audit.AuditWriteError("Tec-Tac audit write failed.")
        row = dict(kwargs)
        with h.lock:
            h.rows.append(row)
        return {"recorded": True}

    audit._record_row = fake_row

    def fake_master():
        if h.master_fault is not None:
            raise secret_store.SecretStoreError("master_key_unavailable", "The secret store cannot use its master key.", 503, reason=h.master_fault)
        return h.master_key

    secret_store._load_master_key = fake_master

    real_find = console_certificates._find_user

    def find_user(user_id):
        user = real_find(user_id)
        if user is not None:
            for name, value in h.user_flags.get(user.pk, {}).items():
                setattr(user, name, value)
        return user

    console_certificates._find_user = find_user

    # the tunnel end task cannot be queued here (no broker): record the calls instead of trying a connection
    h.queued = []
    probe_tunnel.queue_end = lambda kind, ref: h.queued.append((kind, ref)) or True

    User = get_user_model()
    h.User = User
    with connection.schema_editor() as editor:
        for model in (User, AuthToken, models.TecTacRuntimeConfig, models.TecTacConsoleCA, models.TecTacConsoleCertificate, models.TecTacConsoleEnrolment,
                      models.TecTacConsoleSession, models.TecTacConsoleSignin, models.TecTacSessionSecurityConfig, models.TecTacSessionTrust,
                      models.TecTacSessionAudit):
            editor.create_model(model)

    counter = [0]

    def new_user(username=None, *, superuser=False, active=True, **flags):
        counter[0] += 1
        user = User.objects.create(username=username or f"engineer{counter[0]}", is_superuser=superuser, is_active=active)
        flags.setdefault("totp_key", "totp")  # a person with an authenticator: the session guard's MFA check passes
        h.user_flags[user.pk] = flags
        for name, value in flags.items():
            setattr(user, name, value)
        return user

    def reset():
        for model in (models.TecTacSessionAudit, models.TecTacSessionTrust, models.TecTacConsoleSession, models.TecTacConsoleSignin, AuthToken,
                      models.TecTacRuntimeConfig, models.TecTacConsoleCertificate, models.TecTacConsoleEnrolment, models.TecTacConsoleCA, models.TecTacSessionSecurityConfig):
            model.objects.all()._raw_delete("default")
        User.objects.all()._raw_delete("default")
        h.user_flags.clear()
        h.rows.clear()
        h.logs.clear()
        h.queued.clear()
        h.fail_audit = False
        h.fail_actions.clear()
        h.master_fault = None
        cache.clear()
        access_events.clear_callers_for_tests()

    factory = APIRequestFactory()
    h.factory = factory

    def browser(user):
        """A signed-in browser: a Knox token and its Authorization header (the way a person's browser is)."""
        instance, token = AuthToken.objects.create(user=user, expiry=timedelta(hours=8))
        return types.SimpleNamespace(user=user, instance=instance, token=token, header=f"Token {token}")

    def call(view, method, path, *, user=None, session=None, data=None, url_kwargs=None, extra=None, raw=None, content_type="application/json"):
        """Call a view the way a client does. ``session`` is a browser() (forced authentication with a Knox token and header). With no session the
        view's own authentication classes run (the Console routes)."""
        extra = dict(extra or {})
        extra.setdefault("HTTP_HOST", HOST)
        extra.setdefault("REMOTE_ADDR", IP)
        maker = getattr(factory, method.lower())
        if raw is not None:
            request = maker(path, data=raw, content_type=content_type, **extra)
        elif method.upper() == "GET":
            request = maker(path, **extra)
        else:
            request = maker(path, data=data if data is not None else {}, format="json", **extra)
        if session is not None:
            request.META["HTTP_AUTHORIZATION"] = session.header
            force_authenticate(request, user=session.user, token=session.instance)
        return view.as_view()(request, **(url_kwargs or {}))

    def enrol_pc(user=None, label="Work PC", admin=None):
        """Issue as an administrator, ask for the code as the engineer (functions, not routes), enrol through the real enrol route. Returns (user, pc)."""
        admin = admin or User.objects.filter(username="admin").first() or new_user("admin", superuser=True)
        user = user or new_user()
        console_certificates.authorise(admin, user.pk)
        code = console_certificates.create_enrolment_code(user, HOST)["code"]
        pc = Pc(label)
        response = base_enrol(code, pc)
        must(response.status_code == 201, f"enrol: {response.status_code} {response.data}")
        pc.cert_der = base64.urlsafe_b64decode(response.data["cert"] + "=" * (-len(response.data["cert"]) % 4))
        pc.serial = response.data["serial"]
        pc.cert_b64 = response.data["cert"]
        pc.server_id = response.data["server_id"]
        return user, pc

    def base_enrol(code, pc):
        from tec_tac import console_certificate_views

        body = pc.console.body(code, HOST, pc.label)
        return call(console_certificate_views.ConsoleCertificateEnrolView, "POST", "/api/tfd/console-certificates/enrol/", raw=json.dumps(body).encode(),
                    extra={"HTTP_AUTHORIZATION": f"Enrol {code}"})

    def authorise(user, pc, verifier=None, port=40123, session=None, **override):
        """Browser step: POST authorise/. Returns (response, verifier, session)."""
        verifier = verifier or pc.new_verifier()
        session = session or browser(user)
        body = {"serial": pc.serial, "code_challenge": pc.challenge(verifier), "redirect_port": port}
        body.update(override)
        response = call(console_session_views.ConsoleSessionAuthoriseView, "POST", "/api/tfd/console-sessions/authorise/", session=session, data=body)
        if response.status_code == 200:
            pc.verifiers[response.data["code"]] = verifier
        return response, verifier, session

    def token_request(pc, code, verifier, *, body=None, headers=None, proof=None, cert=None, ip=IP, host=HOST, version=None, raw=None, extra=None):
        """Console step: POST token/ with the certificate and a proof."""
        payload = body if body is not None else {"v": 1, "code": code, "code_verifier": verifier, "serial": pc.serial}
        if version is not None:
            payload = {**payload, "client_version": version}
        proof_value = proof if proof is not None else pc.signin_proof(host, pc.server_id, code)
        hdr = {"HTTP_X_TECTAC_CONSOLE_CERT": cert if cert is not None else pc.cert_b64, "HTTP_X_TECTAC_CONSOLE_PROOF": proof_value, "HTTP_HOST": host, "REMOTE_ADDR": ip}
        hdr.update(extra or {})
        hdr.update(headers or {})
        return call(console_session_views.ConsoleSessionTokenView, "POST", "/api/tfd/console-sessions/token/",
                    raw=raw if raw is not None else json.dumps(payload).encode(), extra=hdr)

    def sign_in(user=None, pc=None, **kw):
        """The whole flow: enrol (when no PC is given), authorise in the browser, redeem. Returns (user, pc, response)."""
        if pc is None:
            user, pc = enrol_pc(user)
        response, verifier, _ = authorise(user, pc)
        must(response.status_code == 200, f"authorise: {response.status_code} {response.data}")
        code = response.data["code"]
        result = token_request(pc, code, verifier, **kw)
        if result.status_code == 201:
            pc.token = result.data["token"]
            pc.session = result.data
        return user, pc, result

    def pc_call(view, pc, method="GET", path=None, data=None, *, token=None, proof=None, headers=None, body=None, host=HOST, server_id=None, serial=None,
                time_text=None, nonce=None, key=None, ip=IP, no_proof=False):
        """A Console request, signed. ``path`` is the request target with its query. Returns the response."""
        raw = body if body is not None else (json.dumps(data).encode() if data is not None else b"")
        tok = token or pc.token
        extra = {"HTTP_HOST": host, "REMOTE_ADDR": ip, "HTTP_AUTHORIZATION": f"TecTacConsole {tok}"}
        if not no_proof:
            extra["HTTP_X_TECTAC_CONSOLE_PROOF"] = proof if proof is not None else pc.request_proof(
                host, server_id or pc.server_id, method.upper(), path, raw, tok, serial or pc.serial, time_text, nonce, key)
        extra.update(headers or {})
        maker = getattr(factory, method.lower())
        if raw:
            request = maker(path, data=raw, content_type="application/json", **extra)
        else:
            request = maker(path, **extra)
        return view.as_view()(request)

    h.new_user, h.reset, h.call, h.browser, h.enrol_pc, h.authorise, h.token_request, h.sign_in, h.pc_call = (
        new_user, reset, call, browser, enrol_pc, authorise, token_request, sign_in, pc_call)
    h.Pc = Pc
    h.connection, h.cache, h.timezone = connection, cache, timezone
    _H = h
    return h


def captured_text(h) -> str:
    """Everything a log line or an audit row captured, as one searchable text."""
    return "\n".join(h.logs) + "\n" + json.dumps(h.rows, default=str)

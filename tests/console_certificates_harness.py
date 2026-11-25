"""Shared fixtures of the 1.18.52 Console certificate tests (imported by file path, not a test itself).

Boots real Django (the project's .venv has it) with a temporary SQLite file and the shim app the 1.18.45 system check test uses, then loads the REAL
framwork/tec_tac/console_certificates.py, console_certificate_views.py, throttles.py, rbac.py, audit.py and secret_store.py (its AES helpers).
Stubbed: Tactical's apps (accounts.models.Role, the module registry), the session guard, the master key file and the audit row writer
(audit._record_row), so the real private audit function runs and its arguments are captured. Nothing here touches a network or Redis.

If Django is not importable, boot() returns None and each test says so and exits 0 (the AST and text checks of the version test still run).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "framwork" / "tec_tac"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "framwork"))

HOST = "tec.example.com"
IP = "203.0.113.7"
_H = None


def must(condition, message="check failed"):
    if not condition:
        raise AssertionError(message)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class _LogCapture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        text = record.getMessage()
        if record.exc_info:
            text += " " + repr(record.exc_info[1])
        self.lines.append(text)


class KnoxToken:
    """A Knox token reduced to what the routes read: a digest (1.18.53: the routes that start an enrolment need an interactive session)."""

    digest = "knox-digest-for-tests"


class Console:
    """A stand-in for the Engineer Console: a P-256 key pair and the proof it signs."""

    def __init__(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        self.key = ec.generate_private_key(ec.SECP256R1())
        self.spki = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_key = b64u(self.spki)

    @property
    def spki_hash(self) -> str:
        return hashlib.sha256(self.spki).hexdigest()

    def proof(self, host: str, code: str, spki_hash: str | None = None, key=None) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        message = (f"tectac-console-enrol-v1\nhost={host}\ncode={hashlib.sha256(code.encode()).hexdigest()}\nkey={spki_hash or self.spki_hash}").encode()
        r, s = decode_dss_signature((key or self.key).sign(message, ec.ECDSA(hashes.SHA256())))
        return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def connect_proof(self, host: str, server_id: str, ticket: str, serial: str, time_text: str, nonce: str, key=None) -> str:
        """The v1.<time>.<nonce>.<sig> value of X-Tectac-Console-Proof (1.18.53), written out here byte by byte so a test pins Core's message."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        message = ("tectac-console-connect-v1\n" f"host={host}\nserver={server_id}\nticket={hashlib.sha256(ticket.encode()).hexdigest()}\n"
                   f"serial={serial}\ntime={time_text}\nnonce={nonce}").encode()
        r, s = decode_dss_signature((key or self.key).sign(message, ec.ECDSA(hashes.SHA256())))
        return f"v1.{time_text}.{nonce}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def body(self, code: str, host: str = HOST, pc_label: str = "Work PC", **override) -> dict:
        body = {"v": 1, "public_key": self.public_key, "pc_label": pc_label, "proof": self.proof(host, code)}
        body.update(override)
        return body


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

    tmp = tempfile.mkdtemp(prefix="cc-test-")
    shim = types.ModuleType("_tectac_cc_shim")

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
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.path.join(tmp, "cc.sqlite3"), "OPTIONS": {"timeout": 30, "transaction_mode": "IMMEDIATE"}}},
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "cc-test"}},
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        USE_TZ=True,
        SECRET_KEY="console-certificates-test-only",
        ALLOWED_HOSTS=["*"],
        REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": {}, "UNAUTHENTICATED_USER": None},
    )
    django.setup()

    from django.contrib.auth import get_user_model
    from django.core.cache import cache
    from django.db import connection
    from rest_framework.permissions import IsAuthenticated
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
    stub("tec_tac.session_security", SessionAuthenticated=type("SessionAuthenticated", (IsAuthenticated,), {}))
    h.tunnel_calls, h.tunnel_fault = [], [False]

    def tunnel_call(name):
        def call_it(arg):
            from django.db import connection as db_connection

            h.tunnel_calls.append((name, arg, db_connection.in_atomic_block))  # in_atomic_block must be False: the hook runs after the commit
            if h.tunnel_fault[0]:
                raise RuntimeError("the tunnel layer is down")
            return []

        return call_it

    stub("tec_tac.probe_tunnel", certificate_revoked=tunnel_call("certificate_revoked"), ca_replaced=tunnel_call("ca_replaced"))

    from tec_tac import audit, console_certificate_views, console_certificates, models, rbac, secret_store

    h.audit, h.cc, h.views, h.models, h.rbac, h.store = audit, console_certificates, console_certificate_views, models, rbac, secret_store
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

    def has_perm(user, code):
        return code in h.perms.get(getattr(user, "pk", None), ())

    rbac.has_extension_permission = has_perm

    User = get_user_model()
    h.User = User
    with connection.schema_editor() as editor:
        for model in (User, models.TecTacRuntimeConfig, models.TecTacConsoleCA, models.TecTacConsoleCertificate, models.TecTacConsoleEnrolment):
            editor.create_model(model)

    counter = [0]

    def new_user(username=None, *, superuser=False, active=True, perms=(), **flags):
        counter[0] += 1
        user = User.objects.create(username=username or f"engineer{counter[0]}", is_superuser=superuser, is_active=active)
        h.perms[user.pk] = tuple(perms)
        if flags:
            h.user_flags[user.pk] = flags
        return user

    def reset():
        models.TecTacRuntimeConfig.objects.all()._raw_delete('default')
        models.TecTacConsoleCertificate.objects.all()._raw_delete('default')
        models.TecTacConsoleEnrolment.objects.all()._raw_delete('default')
        models.TecTacConsoleCA.objects.all()._raw_delete('default')
        User.objects.all()._raw_delete('default')  # raw: a normal delete would look for every table that points at the user
        h.perms.clear()
        h.user_flags.clear()
        h.rows.clear()
        h.logs.clear()
        h.tunnel_calls.clear()
        h.tunnel_fault[0] = False
        h.fail_audit = False
        h.fail_actions.clear()
        h.master_fault = None
        cache.clear()

    factory = APIRequestFactory()

    def call(view, method, path, user=None, data=None, url_kwargs=None, query="", auth="knox", **extra):
        """auth: knox (the default: a Knox-like token with a digest), api (an API-key request: a string token and an X-API-KEY header), session
        (no token, like a plain Django session) or any object, passed as the token."""
        if auth == "api":
            extra.setdefault("HTTP_X_API_KEY", "api-key-for-tests")
        extra.setdefault("HTTP_HOST", HOST)
        extra.setdefault("REMOTE_ADDR", IP)
        maker = getattr(factory, method.lower())
        if method.upper() == "GET":
            request = maker(path + query, **extra)
        elif isinstance(data, (bytes, str)):
            request = maker(path, data=data, content_type="application/json", **extra)
        else:
            request = maker(path, data=data if data is not None else {}, format="json", **extra)
        if user is not None:
            token = KnoxToken() if auth == "knox" else ("api-key-for-tests" if auth == "api" else (None if auth == "session" else auth))
            force_authenticate(request, user=user, token=token)
        response = view.as_view()(request, **(url_kwargs or {}))
        return response

    def enrol(code, console=None, host=HOST, pc_label="Work PC", ip=IP, body=None, headers=None, raw=None):
        console = console or Console()
        payload = body if body is not None else console.body(code, host, pc_label)
        data = raw if raw is not None else json.dumps(payload).encode()
        extra = {"HTTP_AUTHORIZATION": f"Enrol {code}", "HTTP_HOST": host, "REMOTE_ADDR": ip}
        extra.update(headers or {})
        return call(views_enrol(), "POST", "/api/tfd/console-certificates/enrol/", None, data, **extra)

    def views_enrol():
        return console_certificate_views.ConsoleCertificateEnrolView

    def full_flow(admin=None, user=None, console=None, pc_label="Work PC"):
        """Issue as an administrator, ask for the code as the engineer, enrol. Returns (user, console, code, response)."""
        admin = admin or new_user("admin", superuser=True)
        user = user or new_user()
        console = console or Console()
        issued = call(console_certificate_views.ConsoleCertificateIssueView, "POST", "/api/tfd/console-certificates/issue/", admin, {"user_id": user.pk})
        must(issued.status_code == 201, f"issue: {issued.status_code} {issued.data}")
        code_response = call(console_certificate_views.ConsoleCertificateEnrolmentCodeView, "POST", "/api/tfd/console-certificates/mine/enrolment-code/", user, {})
        must(code_response.status_code == 200, f"code: {code_response.status_code} {code_response.data}")
        code = code_response.data["code"]
        return user, console, code, enrol(code, console, pc_label=pc_label)

    h.new_user, h.reset, h.call, h.enrol, h.full_flow, h.Console = new_user, reset, call, enrol, full_flow, Console
    h.connection, h.cache = connection, cache
    _H = h
    return h


def rows_of(h, action):
    return [r for r in h.rows if r.get("action") == action]


def captured_text(h) -> str:
    """Everything a log line or an audit row captured, as one searchable text."""
    return "\n".join(h.logs) + "\n" + json.dumps(h.rows, default=str)

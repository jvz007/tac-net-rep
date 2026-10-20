"""Shared stubs for the 1.17.58 licensing tests (mode, status read, override).

Django is not installed on the PC that prepares a release, so the real ``module_manager_v2``, ``module_licensing``,
``module_licensing_views``, ``runtime_settings``, ``module_v2_views`` and ``module_repository_views`` run against stubs for Django, DRF,
the runtime configuration row, RBAC and the audit writer. Staging itself is not run: a test that needs the gate called from a view
replaces the staging function with one that calls ``_enforce_candidate_licensing`` the way the real ones do. The real staging,
the real model, the migration and the real audit table are dev-server work: ``tests/licensing-mode-runtime-1.17.58.py``.

Use: ``H = harness.install()``. ``H.reset()`` puts the world back (mode blank, no rows, a superuser flag off).
"""
from __future__ import annotations

import logging
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    return module


class PermissionDenied(Exception):
    pass


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


class APIView:
    pass


class AtomicCtx:
    entered = 0
    exited_with_error = 0

    def __enter__(self):
        AtomicCtx.entered += 1
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            AtomicCtx.exited_with_error += 1
        return False


def _passthrough(*a, **k):
    return lambda fn: fn


class User:
    def __init__(self, name="alice", superuser=False, runtime=False):
        self.username, self.superuser, self.runtime = name, superuser, runtime
        self.is_authenticated = True


class Config:
    pk = 1
    module_register_timeout_seconds = 30
    tactical_operation_upload_max_mib = 10
    system_name = "Tec-Tac"
    licensing_enforcement_mode = ""
    updated_at = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
    updated_by = None
    saved: list = []

    def save(self, update_fields=None):
        Config.saved.append(tuple(update_fields or ()))


def install():
    for name in ("fcntl",):
        _stub(name, LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
    for name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric"):
        _stub(name)
    _stub("cryptography.hazmat.primitives.serialization")
    _stub("cryptography.hazmat.primitives.asymmetric.ed25519", Ed25519PublicKey=object)
    _stub("cryptography.exceptions", InvalidSignature=Exception)

    _stub("django")
    _stub("django.db", transaction=SimpleNamespace(atomic=lambda: AtomicCtx()))
    _stub("drf_spectacular")
    _stub("drf_spectacular.utils", extend_schema=_passthrough, extend_schema_view=_passthrough)
    _stub("rest_framework")
    _stub("rest_framework.exceptions", PermissionDenied=PermissionDenied)
    _stub("rest_framework.response", Response=Response)
    _stub("rest_framework.views", APIView=APIView)
    _stub("rest_framework.parsers", MultiPartParser=object, FormParser=object)

    world = SimpleNamespace(
        audits=[], audit_fail=SimpleNamespace(on=False, only_strict=False), superuser_ids=set(), runtime_ids=set(),
        config=Config(), current_fails=SimpleNamespace(on=False), log=[],
    )

    def record(**kwargs):
        if world.audit_fail.on and (kwargs.get("strict") or not world.audit_fail.only_strict):
            raise RuntimeError("audit store down")
        world.audits.append({key: value for key, value in kwargs.items() if key != "request"})  # the request object is not row data
        return {"recorded": True}

    class TecTacRuntimeConfig:
        @classmethod
        def current(cls):
            if world.current_fails.on:
                raise RuntimeError("database unavailable")
            return world.config

        class objects:
            @staticmethod
            def select_for_update():
                return SimpleNamespace(get=lambda pk: world.config)

    _stub("tec_tac.audit", record=record,
          service_audit_actor=lambda *, module_id, service, identity=None: SimpleNamespace(kind="service", module_id=module_id, service=service, identity=identity or f"{module_id}.{service}"))
    _stub("tec_tac.models", TecTacRuntimeConfig=TecTacRuntimeConfig)
    _stub("tec_tac.rbac", is_effective_superuser=lambda user: getattr(user, "superuser", False),
          can_manage_runtime_settings=lambda user: getattr(user, "superuser", False) or getattr(user, "runtime", False))
    _stub("tec_tac.session_security", SessionAuthenticated=type("SessionAuthenticated", (), {}))
    _stub("tec_tac.throttles", RuntimeSettingsWriteMinThrottle=type("Min", (), {}), RuntimeSettingsWriteDayThrottle=type("Day", (), {}))
    _stub("tec_tac.views", _can_manage_modules=lambda user: True, _require_module_manager=lambda user: None)

    from tec_tac import module_licensing as ml  # noqa: E402
    from tec_tac import module_manager_v2 as v2  # noqa: E402
    from tec_tac import runtime_settings as rs  # noqa: E402
    from tec_tac import module_licensing_views as lv  # noqa: E402
    from tec_tac import module_v2_views as v2views  # noqa: E402
    from tec_tac import module_repository_views as repoviews  # noqa: E402
    from tec_tac import capabilities as caps  # noqa: E402

    class Capture(logging.Handler):
        def __init__(self):
            super().__init__(logging.DEBUG)

        def emit(self, record):
            world.log.append(record.getMessage() + " | " + (self.format(record) if record.exc_info else ""))

    logging.getLogger().addHandler(Capture())
    logging.getLogger().setLevel(logging.DEBUG)

    def reset():
        world.audits.clear()
        world.log.clear()
        world.audit_fail.on = False
        world.audit_fail.only_strict = False
        world.current_fails.on = False
        world.config.licensing_enforcement_mode = ""
        Config.saved.clear()
        AtomicCtx.exited_with_error = 0

    world.reset = reset
    world.ml, world.v2, world.rs, world.lv, world.v2views, world.repoviews, world.caps = ml, v2, rs, lv, v2views, repoviews, caps
    world.User, world.Response, world.PermissionDenied, world.AtomicCtx = User, Response, PermissionDenied, AtomicCtx
    world.root = ROOT
    return world


def candidate(module_id="reportmanager", version="1.0.0", required=True, product="reportmanager"):
    """A candidate as ``_package_metadata`` builds it: the manifest's licensing block, normalised."""
    return {
        "id": module_id, "extension_version": version,
        "licensing": {"required": required, "product": product if required else None,
                      "capability": "licensing.entitlements" if required else None, "capability_version": ">=1.0.0,<2.0.0" if required else None},
    }

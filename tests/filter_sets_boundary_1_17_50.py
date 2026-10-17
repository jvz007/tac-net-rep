"""Shared test boundary for the 1.17.50 filter set tests (a helper, not a test: it asserts nothing).

Runs the real tec_tac.filter_sets, saved_views, audit and registry code, and with ``real_capabilities=True`` the real capabilities
registry. Only the Django/DRF boundary is faked: an in-memory TecTacSavedView model with a transaction that really rolls back, users,
the Tactical AuditLog, a recording ``django.db.models.Q`` and DRF classes. Django is not installed on the PC that prepares a release.
"""
from __future__ import annotations

import copy
import importlib
import sys
import types
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork" / "tec_tac"


class IntegrityError(Exception):
    pass


class Q:
    """A recording stand-in for django.db.models.Q: keeps the tree so a test can read and evaluate it."""

    def __init__(self, **kwargs):
        self.kind, self.kwargs, self.parts = "leaf", dict(kwargs), []

    @classmethod
    def _node(cls, kind, parts):
        node = cls()
        node.kind, node.kwargs, node.parts = kind, {}, list(parts)
        return node

    def __and__(self, other):
        return Q._node("and", [self, other])

    def __or__(self, other):
        return Q._node("or", [self, other])

    def __invert__(self):
        return Q._node("not", [self])

    def __repr__(self):
        if self.kind == "leaf":
            return "Q(%s)" % ", ".join(f"{k}={v!r}" for k, v in self.kwargs.items())
        if self.kind == "not":
            return f"~{self.parts[0]!r}"
        return "(" + (" & " if self.kind == "and" else " | ").join(repr(p) for p in self.parts) + ")"

    def evaluate(self, row: dict) -> bool:
        """Evaluate against a dict, the way Django would for iexact/icontains/istartswith/iendswith/exact (None is not matched)."""
        if self.kind == "and":
            return all(p.evaluate(row) for p in self.parts)
        if self.kind == "or":
            return any(p.evaluate(row) for p in self.parts)
        if self.kind == "not":
            return not self.parts[0].evaluate(row)
        (key, value), = self.kwargs.items()
        if key == "pk__isnull":
            return not value  # a row always has a pk
        for known in ("iexact", "icontains", "istartswith", "iendswith"):
            if key.endswith("__" + known):
                path = key[: -len(known) - 2]
                suffix = known
                break
        else:
            path, suffix = key, "exact"
        actual = row.get(path)
        if actual is None:
            return False
        if suffix == "exact":
            return actual == value
        actual, value = str(actual).casefold(), str(value).casefold()
        return {"iexact": actual == value, "icontains": value in actual, "istartswith": actual.startswith(value),
                "iendswith": actual.endswith(value)}[suffix]


def install(real_capabilities: bool = False) -> SimpleNamespace:
    pkg = types.ModuleType("tec_tac")
    pkg.__path__ = [str(PKG)]
    sys.modules["tec_tac"] = pkg
    ns = SimpleNamespace(STORE={}, CLOCK=[0], IntegrityError=IntegrityError, Q=Q)

    class _Atomic:
        def __enter__(self):
            self.snapshot = {
                key: (obj, {k: (copy.deepcopy(v) if k in ("payload", "readers") else v) for k, v in obj.__dict__.items()})
                for key, obj in ns.STORE.items()
            }
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc_type is not None:
                ns.STORE.clear()
                for key, (obj, state) in self.snapshot.items():
                    obj.__dict__.clear()
                    obj.__dict__.update(state)
                    ns.STORE[key] = obj
            return False

    django = types.ModuleType("django")
    django_db = types.ModuleType("django.db")
    django_db.transaction = types.SimpleNamespace(atomic=lambda: _Atomic())
    django_db.IntegrityError = IntegrityError
    django_models = types.ModuleType("django.db.models")
    django_models.Q = Q
    django_db.models = django_models
    django_contrib = types.ModuleType("django.contrib")
    django_auth = types.ModuleType("django.contrib.auth")

    class User:
        is_authenticated = True

        def __init__(self, pk, username, *, superuser=False, active=True):
            self.pk = pk
            self.id = pk
            self.username = username
            self.is_superuser = superuser
            self.is_active = active
            self.role = types.SimpleNamespace(is_superuser=False)

        def get_and_set_role_cache(self):
            return self.role

    ns.User = User
    ns.alice, ns.bob, ns.carol = User(1, "alice"), User(2, "bob"), User(3, "carol")
    ns.dave = User(4, "dave", active=False)
    ns.root = User(9, "root", superuser=True)
    ns.USERS = {u.pk: u for u in (ns.alice, ns.bob, ns.carol, ns.dave, ns.root)}

    class _UserQS:
        def __init__(self, rows):
            self.rows = rows

        def values_list(self, field, flat=False):
            return [getattr(row, field) for row in self.rows]

    class _UserManager:
        def filter(self, pk__in=(), is_active=True):
            return _UserQS([u for u in ns.USERS.values() if u.pk in set(pk__in) and u.is_active == is_active])

    django_auth.get_user_model = lambda: types.SimpleNamespace(objects=_UserManager())
    sys.modules.update({"django": django, "django.db": django_db, "django.db.models": django_models,
                        "django.contrib": django_contrib, "django.contrib.auth": django_auth})

    class SavedViewRow:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

        def save(self, update_fields=None):
            ns.CLOCK[0] += 1
            self.updated_at = ns.CLOCK[0]
            ns.STORE[str(self.id)] = self

        def delete(self):
            ns.STORE.pop(str(self.id), None)

    class QS:
        def __init__(self, rows):
            self.rows = list(rows)

        def filter(self, **kwargs):
            rows = self.rows
            for key, value in kwargs.items():
                if key == "pk":
                    rows = [r for r in rows if str(r.id) == str(value)]
                elif key.endswith("__startswith"):  # 1.17.51: the repair step reads view_key__startswith
                    attr = key[: -len("__startswith")]
                    rows = [r for r in rows if str(getattr(r, attr)).startswith(value)]
                else:
                    rows = [r for r in rows if getattr(r, key) == value]
            return QS(rows)

        def select_related(self, *args):
            return self

        def order_by(self, *fields):
            return QS(sorted(self.rows, key=lambda r: (r.name, str(r.id))))

        def first(self):
            return self.rows[0] if self.rows else None

        def count(self):
            return len(self.rows)

        def __iter__(self):
            return iter(self.rows)

    class Manager:
        force_integrity = False

        def filter(self, **kwargs):
            return QS(ns.STORE.values()).filter(**kwargs)

        def select_related(self, *args):
            return QS(ns.STORE.values())

        def create(self, *, owner, module_id, view_key, name, payload, readers):
            if self.force_integrity or any(
                r.owner_id == owner.pk and (r.module_id, r.view_key, r.name) == (module_id, view_key, name) for r in ns.STORE.values()
            ):
                raise IntegrityError("unique")
            ns.CLOCK[0] += 1
            row = SavedViewRow(
                id=uuid.uuid4(), owner=owner, owner_id=owner.pk, module_id=module_id, view_key=view_key, name=name,
                payload=payload, readers=readers, created_at=ns.CLOCK[0], updated_at=ns.CLOCK[0],
            )
            ns.STORE[str(row.id)] = row
            return row

    ns.MANAGER = Manager()
    SavedViewRow.objects = ns.MANAGER
    models_stub = types.ModuleType("tec_tac.models")
    models_stub.TecTacSavedView = SavedViewRow
    sys.modules["tec_tac.models"] = models_stub

    ns.ENABLED = {"demo-disabled": False}
    if real_capabilities:
        if "fcntl" not in sys.modules:
            try:
                import fcntl  # noqa: F401
            except ImportError:
                sys.modules["fcntl"] = types.ModuleType("fcntl")  # module_state imports it; nothing here locks a file
        module_state = importlib.import_module("tec_tac.module_state")
        module_state.is_enabled = lambda module_id, state=None: ns.ENABLED.get(module_id, True)
        module_state.load_state = lambda: {}
        capabilities = importlib.import_module("tec_tac.capabilities")
    else:
        capabilities = types.ModuleType("tec_tac.capabilities")
        capabilities.register_capability = lambda **kwargs: kwargs
        capabilities.list_capabilities = lambda check_health=False: []
        sys.modules["tec_tac.capabilities"] = capabilities
        module_state = types.ModuleType("tec_tac.module_state")
        module_state.load_state = lambda: {}
        module_state.is_enabled = lambda module_id, state=None: ns.ENABLED.get(module_id, True)
        sys.modules["tec_tac.module_state"] = module_state
    ns.capabilities = capabilities

    ns.GRANTS = {}
    rbac_stub = types.ModuleType("tec_tac.rbac")
    rbac_stub.effective_permissions = lambda actor: set(ns.GRANTS.get(actor.pk, ()))
    sys.modules["tec_tac.rbac"] = rbac_stub

    # resources: user_context(user) with a scope the test controls per user
    ns.SCOPES = {}
    ns.SCOPE_ERRORS = set()

    class Context:
        def __init__(self, user):
            self.user = user

        @property
        def scope(self):
            if self.user.pk in ns.SCOPE_ERRORS:
                raise RuntimeError("scope lookup failed")
            return ns.SCOPES.get(self.user.pk, {"mode": "unrestricted", "unrestricted": True, "whole_client_ids": [], "site_ids": []})

    resources = types.ModuleType("tec_tac.resources")
    resources.user_context = lambda user: Context(user)
    sys.modules["tec_tac.resources"] = resources

    rf = types.ModuleType("rest_framework")
    rf_response = types.ModuleType("rest_framework.response")
    rf_views = types.ModuleType("rest_framework.views")

    class Response:
        def __init__(self, data=None, status=200):
            self.data = data
            self.status_code = status

    class APIView:
        pass

    rf_response.Response = Response
    rf_views.APIView = APIView
    sys.modules.update({"rest_framework": rf, "rest_framework.response": rf_response, "rest_framework.views": rf_views})
    spectacular = types.ModuleType("drf_spectacular")
    spectacular_utils = types.ModuleType("drf_spectacular.utils")
    spectacular_utils.extend_schema = lambda *a, **k: (lambda obj: obj)
    spectacular_utils.extend_schema_view = lambda *a, **k: (lambda obj: obj)
    sys.modules.update({"drf_spectacular": spectacular, "drf_spectacular.utils": spectacular_utils})
    fake_session = types.ModuleType("tec_tac.session_security")
    fake_session.SessionAuthenticated = object
    sys.modules["tec_tac.session_security"] = fake_session
    fake_throttles = types.ModuleType("tec_tac.throttles")
    for name in ("FilterSetWriteMinThrottle", "FilterSetWriteDayThrottle", "FilterValuesMinThrottle",
                 "SavedViewWriteMinThrottle", "SavedViewWriteDayThrottle"):
        setattr(fake_throttles, name, type(name, (), {}))
    sys.modules["tec_tac.throttles"] = fake_throttles

    from tec_tac import audit, registry, saved_views  # noqa: E402

    ns.audit, ns.registry, ns.saved_views = audit, registry, saved_views
    ns.filter_sets = importlib.import_module("tec_tac.filter_sets")
    ns.views = importlib.import_module("tec_tac.filter_set_views")
    ns.saved_view_views = importlib.import_module("tec_tac.saved_view_views")

    class FakeRow:
        pk = 1

    class AuditManager:
        def __init__(self):
            self.rows = []
            self.fail = False

        def create(self, **kwargs):
            if self.fail:
                raise RuntimeError("audit db down")
            self.rows.append(kwargs)
            return FakeRow()

    class FakeAuditLog:
        objects = AuditManager()

    audit._auditlog_model = lambda: FakeAuditLog
    ns.AUDIT = FakeAuditLog.objects.rows
    ns.FakeAuditLog = FakeAuditLog

    def spec(plugin_id, **kwargs):
        return registry.PluginSpec(plugin_id=plugin_id, plugin_type=kwargs.pop("plugin_type", "extension"), root=ROOT, version="1.0.0", **kwargs)

    ns.spec = spec
    ns.OPEN = spec("demo-open")
    ns.LOCKED = spec("demo-locked", permission_groups=(("Use", ("demo-locked.use",)),))
    ns.DISABLED = spec("demo-disabled")
    ns.LEGACY = spec("demo-legacy", plugin_type="legacy", legacy=True)
    ns.PLUGINS = [ns.OPEN, ns.LOCKED, ns.DISABLED, ns.LEGACY]
    registry.get_plugins = lambda: tuple(ns.PLUGINS)

    class Request:
        def __init__(self, user, data=None, query=None):
            self.user = user
            self.data = data
            self.query_params = query or {}

    ns.Request = Request

    def reset():
        ns.STORE.clear()
        del ns.AUDIT[:]
        ns.GRANTS.clear()
        ns.SCOPES.clear()
        ns.SCOPE_ERRORS.clear()
        ns.FakeAuditLog.objects.fail = False
        ns.MANAGER.force_integrity = False
        ns.filter_sets._VALUES_CACHE.clear()

    ns.reset = reset
    return ns

#!/usr/bin/env python3
"""1.17.31 regression (C4 part 1): Core's ticket for a Tactical terminal socket, its owner check, its store and its refusals.

Reuses the stub harness of tests/tactical-operations-1.17.7.py (the real audit.py, rbac.py, tactical_operations.py and
module_category.py run against stubs for Django, DRF and Tactical's own models). The new code is the real tactical_websocket.py and
tactical_websocket_views.py. Django, channels and Tactical are not installed on the development PC, so the cache, the session trust
rows and the Knox table are fakes here. The consumer that relays the socket is tested in tests/tactical-websocket-consumer-1.17.31.py,
and the real Redis single-use delete, the ASGI route and the watcher only run on the dev server (tests/tactical-websocket-runtime-1.17.33.py).

Covered: a permitted owner, flag and in-scope agent gets {ticket, path, session_id, expires_in, kind}; the raw ticket is not in the
stored key or value; a non-owner, a server or premium module (unless an honoured AD-20 replacement), a disabled, legacy, unknown or core
module, a missing flag and an out-of-scope agent are refused with the right code, and each 403 or scope refusal writes one deny row
(server_provenance tactical-websocket, core_refusal, reason) and nothing else; an unknown kind, a bad agent id, a bad body, no session and
no Tactical link are refused without a row; a dummy, down or colliding cache gives 503 and no ticket; a ticket is taken once, and a
malformed, unknown, replayed or expired ticket is refused; session_refusal names each lost sign-in; the kind's owners equal the terminal
defaults route's owners in ROUTE_OWNERS; register_tactical_operation accepts remote-background's terminal-defaults GET and refuses the same
route for agents, endpoints, take-control and a premium module; the capability and its provider check the verified caller; the views
answer the documented codes; the throttle rates are 30 a minute and 500 a day; the contract rows exist; the record() path refuses the
websocket provenance key.
"""
from __future__ import annotations

import ast
import copy
import json
import re
import sys
import time
import types
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
HARNESS = HERE / "tactical-operations-1.17.7.py"
source = HARNESS.read_text(encoding="utf-8")
cut = source.index("fresh()\nmust(ops.list_operations() == []")
G = {"__name__": "ws_stubs", "__file__": str(HARNESS)}
exec(compile(source[:cut], str(HARNESS), "exec"), G)  # noqa: S102 - test-only reuse of the operations harness
must, PLUGINS, ENABLED, ROWS, FakeAuditLog, declare, refused, fresh, Roleish, Role, ops, audit, rbac, adapter = (
    G[k] for k in ("must", "PLUGINS", "ENABLED", "ROWS", "FakeAuditLog", "declare", "refused", "fresh", "Roleish", "Role", "ops", "audit",
                   "rbac", "adapter")
)
APP = G["APP"]
ROOT = G["ROOT"] if "ROOT" in G else APP.parents[1]

Role.FIELDS["can_use_terminal"] = "BooleanField"
Role.FIELDS["can_send_cmd"] = "BooleanField"


def stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    return module


# ------------------------------------------------------------------------------------------------ Django boundary (fakes)
NOW = [datetime(2026, 10, 13, 12, 0, tzinfo=dt_timezone.utc)]


class FakeCache:
    """Django's cache surface used by tactical_websocket. ``mode``: real, dummy (holds nothing), down (every call raises)."""

    def __init__(self):
        self.data, self.mode = {}, "real"

    def _check(self):
        if self.mode == "down":
            raise ConnectionError("redis is down")

    def add(self, key, value, timeout=None):
        self._check()
        if self.mode == "dummy":
            return True
        if key in self.data:
            return False
        self.data[key] = copy.deepcopy(value)
        return True

    def get(self, key, default=None):
        self._check()
        if self.mode == "dummy":
            return default
        return copy.deepcopy(self.data.get(key, default))

    def delete(self, key):
        self._check()
        if self.mode == "dummy":
            return False
        return self.data.pop(key, None) is not None


CACHE = FakeCache()
stub("django.core.cache", cache=CACHE)


class _Rows:
    def __init__(self, rows):
        self.rows = list(rows)

    def first(self):
        return self.rows[0] if self.rows else None

    def exists(self):
        return bool(self.rows)

    def filter(self, *args, **kwargs):
        return self


class FakeUser:
    def __init__(self, pk, username, role=None, *, active=True, blocked=False, superuser=False, installer=False, scope=()):
        self.pk, self.username = pk, username
        self.is_authenticated, self.is_active, self.is_superuser, self.is_installer_user = True, active, superuser, installer
        self.block_dashboard_login = blocked
        self.role = role
        self.scope_ids = set(scope)
        USERS[pk] = self

    def get_and_set_role_cache(self):
        return self.role


USERS: dict[int, FakeUser] = {}


class _UserManager:
    @staticmethod
    def filter(**kwargs):
        return _Rows([u for u in USERS.values() if u.pk == kwargs.get("pk")])


FakeUser.objects = _UserManager
stub("django.contrib", )
stub("django.contrib.auth", get_user_model=lambda: FakeUser)


class FakeTrust:
    """The columns of TecTacSessionTrust that session_security.record_terminal_activity reads and writes (1.17.34)."""

    def __init__(self, pk, user_id, *, digest="knox-1", revoked=False, absolute=None):
        self.id, self.user_id, self.knox_digest, self.revoked = pk, user_id, digest, revoked
        self.created_at = NOW[0]
        self.last_activity_at = NOW[0]
        self.last_seen_at = NOW[0]
        self.absolute_expires_at = absolute or (NOW[0] + timedelta(hours=8))
        self.idle_expires_at = NOW[0] + timedelta(minutes=30)
        self.saves = []

    def save(self, update_fields=None):
        self.saves.append(tuple(update_fields or ()))


TRUSTS: dict[str, FakeTrust] = {}


class _TrustManager:
    @staticmethod
    def select_for_update():
        return _TrustManager

    @staticmethod
    def filter(**kwargs):
        return _Rows([t for t in TRUSTS.values() if t.id == kwargs.get("pk")])


FakeTrust.objects = _TrustManager
stub("tec_tac.models", TecTacSessionTrust=FakeTrust)

LIVE_TOKENS: set[str] = {"knox-1"}


class _TokenQuery:
    def __init__(self, digest):
        self.digest = digest

    def filter(self, *args, **kwargs):
        return self

    def exists(self):
        return self.digest in LIVE_TOKENS


class FakeAuthToken:
    class objects:  # noqa: N801 - mirrors Django's manager attribute
        @staticmethod
        def filter(**kwargs):
            return _TokenQuery(kwargs.get("digest"))


stub("knox.models", AuthToken=FakeAuthToken)
stub("knox", )


class FakeQ:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __or__(self, other):
        return self


sys.modules["django.db.models"].Q = FakeQ
stub("django.utils", )
stub("django.utils.timezone", now=lambda: NOW[0])
sys.modules["django.utils"].timezone = sys.modules["django.utils.timezone"]

# rest_framework throttles: the real throttles.py is loaded below, so give it its one base class
stub("rest_framework.throttling", SimpleRateThrottle=type("SimpleRateThrottle", (), {}))

# the Tactical-side helpers that Core reads at call time
MODULE_REPLACEMENT = stub("tec_tac.module_replacement", MODEL={}, HONOURED=set())
MODULE_REPLACEMENT.live_model = lambda: MODULE_REPLACEMENT.MODEL
MODULE_REPLACEMENT.honoured_replacement = lambda node_id, model=None: (
    model[node_id].replaces if node_id in MODULE_REPLACEMENT.HONOURED else None
)
CALLER = {"value": None}
stub("tec_tac.caller_identity", calling_module_for_core_provider=lambda *, provider_file: CALLER["value"])

# session_security: the real helper reads request.auth.digest
session_security = sys.modules["tec_tac.session_security"]
session_security.request_knox_digest = lambda request: str(getattr(getattr(request, "auth", None), "digest", "") or "")[:128]


# the REAL session_security.record_terminal_activity (1.17.34), cut out of session_security.py and run against the fake trust rows, so the
# idle, absolute and never-backwards rules under test are Core's own code. Django's models and DRF are not importable on this PC.
POLICY = {"idle_timeout_minutes": 30, "absolute_lifetime_minutes": 480}
REVOKED_ROWS: list[tuple[str, str]] = []


class _Atomic:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_revoke_locked(session, *, reason, requested_by="", event_type="session_revoked", policy=None, invalidate_knox=True):
    if not session.revoked:
        session.revoked = True
        session.revocation_reason = reason
        REVOKED_ROWS.append((reason, event_type))
        if invalidate_knox:
            LIVE_TOKENS.discard(session.knox_digest)  # the Knox token ends with the row, as _invalidate_knox_for_session does
    return session


def _load_real_terminal_helper():
    import ast as _ast
    import hmac as _hmac

    text = (APP / "session_security.py").read_bytes().decode("utf-8")
    tree = _ast.parse(text)
    wanted = ("_refresh_expiry", "record_terminal_activity")
    body = [n for n in tree.body if isinstance(n, _ast.FunctionDef) and n.name in wanted]
    assert [n.name for n in body] == list(wanted), "the real helper is missing from session_security.py"
    env = {
        "timedelta": timedelta, "hmac": _hmac, "TecTacSessionTrust": FakeTrust, "timezone": sys.modules["django.utils.timezone"],
        "transaction": SimpleNamespace(atomic=lambda: _Atomic()), "get_effective_policy": lambda user=None, request=None: dict(POLICY),
        "_revoke_locked": _fake_revoke_locked, "Any": object, "TecTacSessionTrust_": FakeTrust,
    }
    module = _ast.Module(body=body, type_ignores=[])
    exec(compile(_ast.fix_missing_locations(module), "session_security.py(record_terminal_activity)", "exec"), env)  # noqa: S102
    return env["record_terminal_activity"]


session_security.record_terminal_activity = _load_real_terminal_helper()
session_security._is_effective_superuser = lambda user: bool(
    getattr(user, "is_authenticated", False)
    and (user.is_superuser or user.username == "root" or bool(getattr(getattr(user, "role", None), "is_superuser", False)))
)

# resources_adapter: the role's scope is the user's scope_ids
adapter.objects_in_role_scope = lambda *, user, resource_type, identifiers: bool(identifiers) and set(identifiers) <= set(user.scope_ids)

# ------------------------------------------------------------------------------------------------ real audit rows: a fake table
FakeAuditLog.objects.fail = False


def _resolve_module(module_id):
    if module_id == "core":
        raise audit.AuditContractError("core is not a module")
    plugin = PLUGINS.get(module_id)
    if plugin is None:
        raise audit.AuditContractError(f"Unknown or ambiguous Tec-Tac module_id: {module_id}")
    if not ENABLED.get(module_id, True):
        raise audit.AuditContractError(f"Tec-Tac module {module_id!r} is disabled.")
    return {
        "id": module_id, "version": plugin.version, "legacy": plugin.legacy, "category": getattr(plugin, "category", ""),
        "permissions": tuple(c for _, v in plugin.permission_groups for c in v), "audit_events": (),
    }


audit._resolve_module = _resolve_module

# the owning modules this test needs, beside the harness's own
PLUGINS["remote-background"] = SimpleNamespace(
    plugin_id="remote-background", plugin_type="extension", version="0.5.0",
    permission_groups=(("Use", ("remote-background.use",)),), legacy=False, audit_events=(), category="core",
)
PLUGINS["take-control"] = SimpleNamespace(plugin_id="take-control", plugin_type="extension", version="1.0.0", permission_groups=(),
                                          legacy=False, audit_events=(), category="core")
PLUGINS["endpoints"] = SimpleNamespace(plugin_id="endpoints", plugin_type="extension", version="0.2.0", permission_groups=(),
                                       legacy=False, audit_events=(), category="core")
PLUGINS["premium-x"] = SimpleNamespace(plugin_id="premium-x", plugin_type="extension", version="1.0.0",
                                       permission_groups=(("Use", ("premium-x.use",)),), legacy=False, audit_events=(), category="premium")
PLUGINS["server-x"] = SimpleNamespace(plugin_id="server-x", plugin_type="extension", version="1.0.0", permission_groups=(),
                                      legacy=False, audit_events=(), category="server")
PLUGINS["core-nocat"] = SimpleNamespace(plugin_id="core-nocat", plugin_type="extension", version="1.0.0", permission_groups=(),
                                        legacy=False, audit_events=(), category="")
MODULE_REPLACEMENT.MODEL.update({
    "remote-background": SimpleNamespace(id="remote-background", category="core", replaces=None),
    "premium-x": SimpleNamespace(id="premium-x", category="premium", replaces="remote-background"),
    "server-x": SimpleNamespace(id="server-x", category="server", replaces=None),
})

# the real throttles module, now that its one base class exists
throttles = G["load"]("throttles")
ws = G["load"]("tactical_websocket")

# ------------------------------------------------------------------------------------------------ fixtures
AGENT = "a" * 21
OTHER = "b" * 21
TRUST_ID = "11111111-2222-4333-8444-555555555555"


def make_user(pk=5, name="tech", flags=("can_use_terminal",), scope=(AGENT,), **kwargs):
    role = Roleish(*flags)
    return FakeUser(pk, name, role, scope=scope, **kwargs)


def request_for(user, *, digest="knox-1", trust=TRUST_ID, session=True, data=None):
    req = SimpleNamespace(user=user, META={}, tec_tac_request_id="req-ws-1", data={"agent_id": AGENT} if data is None else data)
    req.auth = SimpleNamespace(digest=digest) if digest else None
    if session:
        req.tec_tac_session = SimpleNamespace(id=trust)
    return req


def reset():
    fresh()
    del ROWS[:]
    CACHE.data.clear()
    CACHE.mode = "real"
    FakeAuditLog.objects.fail = False
    USERS.clear()
    TRUSTS.clear()
    LIVE_TOKENS.clear()
    LIVE_TOKENS.add("knox-1")
    NOW[0] = datetime(2026, 10, 13, 12, 0, tzinfo=dt_timezone.utc)
    CALLER["value"] = None
    ENABLED.update({"remote-background": True, "premium-x": True, "server-x": True, "take-control": True, "endpoints": True,
                    "core-nocat": True, "offmod": False})
    MODULE_REPLACEMENT.HONOURED.clear()
    TRUSTS[TRUST_ID] = FakeTrust(TRUST_ID, 5)
    POLICY.update(idle_timeout_minutes=30, absolute_lifetime_minutes=480)
    del REVOKED_ROWS[:]


def mint(user=None, *, module="remote-background", kind="agent-terminal", agent=AGENT, **kwargs):
    user = user or make_user()
    req = request_for(user, **kwargs)
    return ws.issue_ticket(req, module_id=module, kind=kind, agent_id=agent)


def refusal(fn):
    try:
        fn()
    except ws.TicketRefusal as exc:
        return exc
    raise AssertionError("expected a TicketRefusal")


def deny_rows():
    return [row for row in ROWS if (row.get("debug_info", {}).get("operation_context") or {}).get("server_provenance") == "tactical-websocket"]


# ------------------------------------------------------------------------------------------------ 1. the mint
reset()
user = make_user()
result = mint(user)
must(set(result) == {"ticket", "path", "session_id", "expires_in", "kind"}, f"the documented shape: {sorted(result)}")
must(len(result["ticket"]) == 43 and ws.TICKET_PATTERN.fullmatch(result["ticket"]), "a 32 byte url-safe ticket")
must(result["path"] == f"/ws/tfd/agent-terminal/{result['ticket']}/", "the socket path names the ticket")
must(result["expires_in"] == 30 and result["kind"] == "agent-terminal", "30 seconds, kind agent-terminal")
must(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", result["session_id"]), "session id is a uuid4")
must(len(CACHE.data) == 1, "one entry in the store")
(stored_key, stored_value), = CACHE.data.items()
must(stored_key == "tec-tac:wsticket:v1:" + __import__("hashlib").sha256(result["ticket"].encode()).hexdigest(), "key is prefix plus SHA-256")
must(result["ticket"] not in stored_key and result["ticket"] not in json.dumps(stored_value, default=str), "the raw ticket is never stored")
must(stored_value["user_id"] == 5 and stored_value["trust_id"] == TRUST_ID and stored_value["knox_digest"] == "knox-1", "identity in the value")
must(stored_value["module_id"] == "remote-background" and stored_value["agent_id"] == AGENT and stored_value["session_id"] == result["session_id"], "scope in the value")
must(stored_value["correlation_id"] and stored_value["expires_at"] > time.time(), "correlation id and expiry")
must(ROWS == [], "a successful mint writes no audit row")

# ------------------------------------------------------------------------------------------------ 2. owner refusals (403, one deny row each)
for label, module in (("premium module", "premium-x"), ("server module", "server-x"), ("unknown module", "nope"),
                      ("core itself", "core"), ("core module without category", "core-nocat"), ("disabled module", "take-control"),
                      ("legacy module", "oldmod"), ("module that owns another route", "endpoints")):
    reset()
    if module == "take-control":
        ENABLED["take-control"] = False  # a disabled module is refused like an unknown one
    before = len(ROWS)
    exc = refusal(lambda module=module: mint(module=module))
    must(exc.status == 403 and exc.code == "websocket_owner_required", f"{label}: 403 owner refusal, got {exc.status} {exc.code}")
    must(len(ROWS) == before + 1 and exc.audit and exc.audit["recorded"], f"{label}: one deny row")
    row = ROWS[-1]
    ctx = row["debug_info"]["operation_context"]
    must(row["action"] == "deny" and row["debug_info"]["module_id"] == "remote-background", f"{label}: the row is the terminal owner's deny row")
    must(ctx["core_refusal"] is True and ctx["server_provenance"] == "tactical-websocket" and ctx["websocket"] == "agent-terminal", f"{label}: provenance")
    must(row["debug_info"]["metadata"]["reason"] == "websocket_owner_required" and row["debug_info"]["metadata"]["status"] == 403, f"{label}: reason")
    must(row["username"] == "tech" and row["debug_info"]["object_id"] == AGENT, f"{label}: actor and object")
    must(not CACHE.data, f"{label}: no ticket issued")

# the honoured AD-20 replacement follows the same rule; a premium module that is not a replacement does not
reset()
MODULE_REPLACEMENT.HONOURED.add("premium-x")
result = mint(module="premium-x")
must(result["kind"] == "agent-terminal", "an honoured replacement of remote-background may open the terminal socket")
must(list(CACHE.data.values())[0]["module_id"] == "premium-x", "the ticket carries the replacement that asked")
reset()  # not honoured: refused as a premium module
exc = refusal(lambda: mint(module="premium-x"))
must(exc.code == "websocket_owner_required", "a premium module that is not honoured is refused")
must(ROWS and ROWS[-1]["debug_info"]["module_id"] == "remote-background", "the refusal is still written against the terminal owner")

# no enabled core owner at all: refused, and nothing is written (logged)
reset()
ENABLED["remote-background"] = False
exc = refusal(lambda: mint(module="remote-background"))
must(exc.code == "websocket_owner_required" and exc.audit is None and not ROWS, "a disabled owner refuses and writes no row it cannot attribute")
reset()

# ------------------------------------------------------------------------------------------------ 3. flag and scope refusals
no_flag = make_user(pk=6, name="viewer", flags=("can_send_cmd",), scope=(AGENT,))
exc = refusal(lambda: mint(no_flag, agent=AGENT))
must(exc.status == 403 and exc.code == "tactical_permission_denied", "a missing can_use_terminal is 403 tactical_permission_denied")
must("can_use_terminal" in exc.message, "the detail names the missing flag")
must(len(ROWS) == 1 and ROWS[-1]["debug_info"]["metadata"]["reason"] == "permission_denied", "one deny row, reason permission_denied")
must(not CACHE.data, "no ticket for a missing flag")

reset()
outside = make_user(pk=7, name="limited", scope=(OTHER,))
exc = refusal(lambda: mint(outside, agent=AGENT))
must(exc.status == 404 and exc.code == "object_not_found", "an out-of-scope agent is 404 object_not_found, the executor's code")
must(len(ROWS) == 1 and ROWS[-1]["debug_info"]["metadata"]["reason"] == "not_found", "one deny row, reason not_found")
must(ROWS[-1]["debug_info"]["object_id"] == AGENT, "the deny row names the agent it refused")
must("not found" in exc.message and "outside" not in exc.message, "the answer does not say whether the agent exists")

reset()
superuser_limited = make_user(pk=8, name="admin", flags=(), scope=(), superuser=True)
exc = refusal(lambda: mint(superuser_limited))
must(exc.code == "object_not_found", "a superuser with no scope on the agent is still held to scope (the adapter decides)")

# ------------------------------------------------------------------------------------------------ 4. refusals without a row
reset()
for label, call, code, status in (
    ("unknown kind", lambda: mint(kind="nope"), "websocket_kind_not_found", 404),
    ("bad agent id", lambda: mint(agent="a b"), "invalid_agent_id", 400),
    ("empty agent id", lambda: mint(agent=""), "invalid_agent_id", 400),
    ("long agent id", lambda: mint(agent="x" * 129), "invalid_agent_id", 400),
    ("agent id not text", lambda: mint(agent=5), "invalid_agent_id", 400),
    ("no session", lambda: ws.issue_ticket(request_for(make_user(), session=False), module_id="remote-background", kind="agent-terminal", agent_id=AGENT), "authenticated_request_required", 401),
    ("no Tactical link", lambda: mint(digest=None), "tactical_session_required", 401),
):
    before = len(ROWS)
    exc = refusal(call)
    must(exc.status == status and exc.code == code, f"{label}: {status} {code}, got {exc.status} {exc.code}")
    must(len(ROWS) == before, f"{label}: no deny row")

anon = SimpleNamespace(is_authenticated=False, pk=None)
exc = refusal(lambda: ws.issue_ticket(request_for(anon), module_id="remote-background", kind="agent-terminal", agent_id=AGENT))
must(exc.status == 401 and not ROWS, "an anonymous request is 401 with no row")

# ------------------------------------------------------------------------------------------------ 5. the store
reset()
CACHE.mode = "dummy"
exc = refusal(lambda: mint())
must(exc.status == 503 and exc.code == "websocket_unavailable", "a dummy cache gives 503")
must(not CACHE.data and ROWS == [], "a dummy cache holds nothing and writes no row")

reset()
CACHE.mode = "down"
exc = refusal(lambda: mint())
must(exc.status == 503 and exc.code == "websocket_unavailable", "a failing cache gives 503")

reset()
original = ws.secrets.token_urlsafe
ws.secrets.token_urlsafe = lambda size: "A" * 43
try:
    CACHE.data[ws.cache_key("A" * 43)] = {"someone": "else"}
    exc = refusal(lambda: mint())
    must(exc.status == 503, "a colliding key is refused, not overwritten")
    must(CACHE.data[ws.cache_key("A" * 43)] == {"someone": "else"}, "the existing entry is untouched")
finally:
    ws.secrets.token_urlsafe = original

# ------------------------------------------------------------------------------------------------ 6. one use, expiry, malformed
reset()
ticket = mint()["ticket"]
value = ws.consume_ticket(ticket)
must(value is not None and value["agent_id"] == AGENT, "a valid ticket is consumed")
must(ws.consume_ticket(ticket) is None, "a consumed ticket cannot be consumed again")
must(not CACHE.data, "the store is empty after use")

ticket = mint()["ticket"]
CACHE.data[ws.cache_key(ticket)]["expires_at"] = time.time() - 1
must(ws.consume_ticket(ticket) is None, "an expired ticket is refused")

ticket = mint()["ticket"]
CACHE.mode = "down"
must(ws.consume_ticket(ticket) is None, "a store that cannot answer refuses the socket")
CACHE.mode = "real"
must(ws.consume_ticket("unknown" + "x" * 36) is None, "an unknown ticket is refused")
for junk in ("short", "", None, 12, "a" * 44, "a" * 42 + "!"):
    must(ws.consume_ticket(junk) is None, f"a malformed ticket is refused: {junk!r}")
reset()

# ------------------------------------------------------------------------------------------------ 7. the sign-in re-check
reset()
make_user()  # pk 5, the trust row's user
value = {"user_id": 5, "trust_id": TRUST_ID, "knox_digest": "knox-1"}
must(ws.session_refusal(value) is None, "a live sign-in passes")
TRUSTS[TRUST_ID].revoked = True
must(ws.session_refusal(value) == "session_revoked", "a revoked session row is refused")
TRUSTS[TRUST_ID].revoked = False
TRUSTS[TRUST_ID].created_at = NOW[0] - timedelta(hours=8, seconds=1)  # 1.17.34: expiry is recomputed from created_at and the policy
must(ws.session_refusal(value) == "session_expired", "a session past its absolute lifetime is refused")
must(REVOKED_ROWS == [("absolute-timeout", "session_absolute_timeout")], "1.17.34: an expired session is revoked like a REST request would")
TRUSTS[TRUST_ID] = FakeTrust(TRUST_ID, 5)
LIVE_TOKENS.add("knox-1")
LIVE_TOKENS.discard("knox-1")
must(ws.session_refusal(value) == "credential_unavailable", "a Knox token that is gone is refused")
LIVE_TOKENS.add("knox-1")
USERS[5].is_active = False
must(ws.session_refusal(value) == "user_unavailable", "a disabled user is refused")
USERS[5].is_active = True
USERS[5].block_dashboard_login = True
must(ws.session_refusal(value) == "user_unavailable", "a user blocked from the dashboard is refused")
USERS[5].block_dashboard_login = False
must(ws.session_refusal(dict(value, knox_digest="other")) == "credential_unavailable", "a changed credential is refused")
must(ws.session_refusal({"user_id": 99, "trust_id": TRUST_ID, "knox_digest": "knox-1"}) == "user_unavailable", "an unknown user is refused")
must(ws.session_refusal({"user_id": 5, "trust_id": "00000000-0000-4000-8000-000000000000", "knox_digest": "knox-1"}) == "session_revoked",
     "an unknown session row is refused")
def clock_down():
    raise RuntimeError("clock down")


saved_now = ws.timezone.now
ws.timezone.now = clock_down
must(ws.session_refusal(value) == "check_failed", "any error in the re-check is a refusal")
ws.timezone.now = saved_now
reset()

# ------------------------------------------------------------------------------------------------ 8. the kind's owner is the route owner table
must(ws.KINDS["agent-terminal"]["rule"] == ("agents", "{}", "terminal-defaults"), "the kind names the terminal defaults rule")
must(ops.ROUTE_OWNERS[("agents", "{}", "terminal-defaults")] == frozenset({"remote-background"}), "the table names remote-background")
must(ops._owners_for_rule(ws.KINDS["agent-terminal"]["rule"], pairs={}) == ops.ROUTE_OWNERS[("agents", "{}", "terminal-defaults")],
     "the kind's owners equal the table's owners, so the two cannot drift")
must(ws.owner_module("agent-terminal")["id"] == "remote-background", "deny rows are written against remote-background")

# ------------------------------------------------------------------------------------------------ 9. register_tactical_operation for the terminal defaults route
fresh()
terminal_defaults = dict(
    id="terminal-defaults", module_id="remote-background", method="GET", route="agents/{agent_id:agent}/terminal-defaults/",
    permissions=["can_use_terminal"], scope=[{"type": "agent", "source": "path:agent_id"}], body_fields=[],
    audit={"action": "view", "object_type": "agent", "audit_fields": []},
)
declared = declare(**terminal_defaults)
must(declared.module_id == "remote-background", "remote-background may declare the terminal defaults GET")
for module in ("agents", "endpoints", "take-control", "premium-x"):
    message = refused(**dict(terminal_defaults, id=f"terminal-{module}", module_id=module))
    must("does not own route" in message or "is not a core module" in message, f"{module} is refused the route: {message}")
fresh()

# ------------------------------------------------------------------------------------------------ 10. the capability and its provider
CAPS_BEFORE = len(G["CAPS"])
ws.register_core_tactical_websocket_capability()
registered = G["CAPS"][-1]
must(registered["id"] == "core.tactical_websocket" and registered["version"] == "1.1.0", "capability id and version (1.1.0 since 1.17.34)")
must(registered["operations"] == ("issue_ticket",) and registered["module_id"] == "core", "one operation, owned by core")
meta = ws.tactical_websocket_contract_metadata()
must(meta["operations"] == ["issue_ticket"] and meta["ticket"]["ttl_seconds"] == 30 and meta["ticket"]["single_use"] is True, "metadata")
must(meta["close_codes"]["4401"] and meta["close_codes"]["4003"] and meta["close_codes"]["4503"], "close codes documented")
must("terminal-defaults" in meta["same_owner_as"], "the socket's owner is stated as the terminal defaults route's owner")

reset()
user = make_user()
CALLER["value"] = SimpleNamespace(module_id="remote-background")
out = ws._PROVIDER.issue_ticket(request=request_for(user), module_id="remote-background", kind="agent-terminal", agent_id=AGENT)
must(out["kind"] == "agent-terminal", "the provider issues for the verified caller")
CALLER["value"] = SimpleNamespace(module_id="premium-x")
exc = refusal(lambda: ws._PROVIDER.issue_ticket(request=request_for(user), module_id="remote-background", kind="agent-terminal", agent_id=AGENT))
must(exc.code == "websocket_caller_required", "a different caller is refused")
CALLER["value"] = None
exc = refusal(lambda: ws._PROVIDER.issue_ticket(request=request_for(user), module_id="remote-background", kind="agent-terminal", agent_id=AGENT))
must(exc.code == "websocket_caller_required", "no verified caller is refused")

# ------------------------------------------------------------------------------------------------ 11. audit: the provenance key stays Core's
reset()
audit_user = make_user()
try:
    audit.record(actor=audit_user, module_id="remote-background", action="view", object_type="agent", object_id=AGENT,
                 operation_context={"server_provenance": "tactical-websocket"})
    raise AssertionError("record() must refuse server_provenance")
except audit.AuditContractError:
    pass
row = audit._record_tactical_websocket(actor=audit_user, module_id="remote-background", action="custom:terminal-start",
                                       object_type="agent", object_id=AGENT, after={"shell": "default", "run_as_user": False,
                                                                                   "session_id": "s"}, websocket="agent-terminal",
                                       strict=True, correlation_id="cid-1")
must(row["recorded"] and ROWS[-1]["debug_info"]["operation_context"]["server_provenance"] == "tactical-websocket", "the start row carries the provenance")
must(ROWS[-1]["debug_info"]["correlation_id"] == "cid-1" and ROWS[-1]["after_value"]["shell"] == "default", "correlation id and after value")
FakeAuditLog.objects.fail = True
try:
    audit._record_tactical_websocket(actor=audit_user, module_id="remote-background", action="custom:terminal-start", object_type="agent",
                                     object_id=AGENT, websocket="agent-terminal", strict=True)
    raise AssertionError("a strict start row that cannot be written must raise")
except audit.AuditWriteError:
    pass
FakeAuditLog.objects.fail = False

# ------------------------------------------------------------------------------------------------ 12. the view and the throttles
views = G["load"]("tactical_websocket_views")
must(views.TacticalWebSocketTicketView.throttle_classes == [throttles.TacticalWebSocketTicketMinThrottle, throttles.TacticalWebSocketTicketDayThrottle],
     "the view uses both throttles")
must(throttles.TacticalWebSocketTicketMinThrottle.rate == "30/min" and throttles.TacticalWebSocketTicketDayThrottle.rate == "500/day", "rates")
must(throttles.TacticalWebSocketTicketMinThrottle.scope != throttles.TacticalWebSocketTicketDayThrottle.scope, "distinct scopes")

reset()
view = views.TacticalWebSocketTicketView()
viewer = make_user()
response = view.post(request_for(viewer), "remote-background", "agent-terminal")
must(response.status_code == 201 and set(response.data) == {"ticket", "path", "session_id", "expires_in", "kind"}, "201 with the shape")
for bad in ({"agent_id": AGENT, "extra": 1}, {}, [AGENT], "x"):
    response = view.post(request_for(viewer, data=bad), "remote-background", "agent-terminal")
    must(response.status_code == 400 and response.data["code"] == "invalid_ticket_request", f"a body with other keys is 400: {bad!r}")
response = view.post(request_for(viewer, data={"agent_id": OTHER}), "remote-background", "agent-terminal")
must(response.status_code == 404 and response.data["code"] == "object_not_found", "an out-of-scope agent answers the executor's 404 code")
response = view.post(request_for(viewer), "premium-x", "agent-terminal")
must(response.status_code == 403 and response.data["code"] == "websocket_owner_required", "a non-owner is refused by the view")

# ------------------------------------------------------------------------------------------------ 13. the HTTP and Python contract rows exist in contracts.py
contracts_tree = ast.parse((APP / "contracts.py").read_bytes().decode("utf-8"))
http_keys = set()
core_names = set()
for node in ast.walk(contracts_tree):
    if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "HTTP_CONTRACT_DETAILS" for t in node.targets):
        for key in node.value.keys:
            http_keys.add(key.value)
    if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in node.targets):
        for item in node.value.elts:
            fields = {k.value: v for k, v in zip(item.keys, item.values)}
            if getattr(fields.get("area"), "value", "") == "tactical-websocket":
                core_names.add(fields["name"].value)
must("/api/tfd/tactical-websocket/<str:module_id>/<str:kind>/tickets/" in http_keys, "the route has its HTTP contract row")
must(core_names == {"issue_ticket"}, "the Python contract row names issue_ticket")
urls_source = (APP / "urls.py").read_bytes().decode("utf-8")
must('path("tactical-websocket/<str:module_id>/<str:kind>/tickets/"' in urls_source, "the route is mounted")
must(ws.ROUTE_PATTERN == "ws/tfd/agent-terminal/<str:ticket>/" and ws.TICKET_PATH == "/ws/tfd/agent-terminal/{ticket}/", "socket path constants")

print("tactical-websocket-ticket-1.17.31: ok")

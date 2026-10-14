"""Core's ticketed Tactical terminal socket: the ticket, its store and its checks (Core 1.17.31, C4, AD-6 condition 2).

A browser cannot hold a Tactical token for a WebSocket. Tactical reads its Knox token from the URL, and Core keeps Knox tokens only as
hashes, so Core cannot open a socket to Tactical as the person, and it must not mint extra tokens. So the browser asks the
authenticated API for a ticket (POST /api/tfd/tactical-websocket/<module_id>/<kind>/tickets/) and then opens
/ws/tfd/agent-terminal/<ticket>/. The ticket is random, lives 30 seconds, works once, and is kept only as a hash in Django's cache
(Tactical's Redis, shared by the rmm and daphne processes). tactical_websocket_consumers relays the socket and runs Tactical's own
terminal consumer.

The owner of a kind comes from Tactical's route owner table. The terminal kind is owned by whoever owns the terminal defaults route
(agents/{}/terminal-defaults/, remote-background). Core checks it with tactical_operations._check_route_owner, so the terminal and its
defaults cannot drift apart. An honoured AD-20 replacement follows the same rule. A premium module that is not a replacement is refused.

The kind agent-terminal exists since 1.17.31. Since 1.17.34 (AD-35, capability 1.1.0) the kind server-terminal relays Tactical's server
web terminal (ws/trmmcli/), a shell on the server itself. Only the module globalsettings may ask for it, only an effective superuser may
have it, and only where Tactical's own switch is on. It does not use the route owner table, because Tactical has no REST route for it.

Terminal input counts as session activity (AD-35). Output alone does not. The watcher of each socket enforces the idle limit, the
absolute maximum, the user and the Knox token every 30 seconds (see TerminalActivity and session_refusal).
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
import threading
import time
import uuid
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

from .capabilities import register_capability

logger = logging.getLogger("tec_tac.tactical_websocket")

CAPABILITY_ID = "core.tactical_websocket"
CAPABILITY_VERSION = "1.1.0"
TICKET_TTL_SECONDS = 30
TICKET_CACHE_PREFIX = "tec-tac:wsticket:v1:"
TICKET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")  # secrets.token_urlsafe(32) is 43 characters
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
TICKET_PATH = "/ws/tfd/agent-terminal/{ticket}/"
ROUTE_PATTERN = "ws/tfd/agent-terminal/<str:ticket>/"
SERVER_TICKET_PATH = "/ws/tfd/server-terminal/{ticket}/"
SERVER_ROUTE_PATTERN = "ws/tfd/server-terminal/<str:ticket>/"
SERVER_TERMINAL_MODULE = "globalsettings"
SERVER_TERMINAL_PERMISSION = "can_use_webterm"
DENY_MESSAGE = "Core refused a Tactical terminal ticket. Nothing was started."
PERMISSION_MESSAGE = "Your Tactical role does not allow this operation. It needs the Tactical permission can_use_terminal."
SCOPE_MESSAGE = "The requested object was not found, or you cannot access it."
OWNER_MESSAGE = "Core refused a Tactical terminal ticket: this module does not own that kind of socket."
SUPERUSER_MESSAGE = "Core refused a server terminal ticket: only a Tactical superuser may open a shell on the server."
SERVER_TERMINAL_OFF_MESSAGE = "Core refused a server terminal ticket: Tactical's server web terminal is off, or your Tactical role does not allow it."

# The kinds Core relays. ``segments`` is the Tactical route the owner table decides by; ``rule`` is that rule (the same key as
# ROUTE_OWNERS, so the owners are read from the one table). Adding a kind is additive: a new row here and its own owner rule.
KINDS: dict[str, dict[str, Any]] = {
    "agent-terminal": {
        "route": "agents/{agent_id:agent}/terminal-defaults/",
        "segments": (("lit", "agents"), ("param", "agent_id", "agent"), ("lit", "terminal-defaults")),
        "rule": ("agents", "{}", "terminal-defaults"),
        "permission": "can_use_terminal",
        "object_type": "agent",
        "body_keys": ("agent_id",),
        "path": TICKET_PATH,
    },
    # Core 1.17.34 (AD-35): Tactical's server web terminal. No route owner rule: Tactical has no REST route for it, so the owner is
    # fixed (``owner``) and an AD-20 replacement does not apply. ``body_keys`` is empty: the body is exactly {}.
    "server-terminal": {
        "owner": SERVER_TERMINAL_MODULE,
        "permission": SERVER_TERMINAL_PERMISSION,
        "object_type": "server",
        "body_keys": (),
        "path": SERVER_TICKET_PATH,
        "superuser_only": True,
    },
}


class TicketRefusal(Exception):
    """Core's own refusal to issue a ticket. ``audit`` is the deny row's verdict, or None when no row was due."""

    def __init__(self, status: int, code: str, message: str, audit: dict | None = None):
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message
        self.audit = audit


def cache_key(ticket: str) -> str:
    """The cache key of a ticket. Only its SHA-256 is stored, so the raw ticket never reaches the cache."""
    return TICKET_CACHE_PREFIX + hashlib.sha256(str(ticket).encode("utf-8")).hexdigest()


def _resolve_module(module_id: str) -> dict | None:
    """The enabled, non-legacy module record for module_id, or None. Core is never a ticket owner."""
    from . import audit as audit_core

    name = str(module_id or "").strip()
    if not name or name == "core":
        return None
    try:
        module = audit_core._resolve_module(name)
    except Exception:  # unknown, ambiguous, disabled: refused by the caller
        return None
    if module.get("legacy"):
        return None
    return module


def owner_refusal(module_id: str, kind: str) -> bool:
    """True when module_id may not open sockets of this kind: not loaded, disabled, legacy, or not the owner (AD-21 category)."""
    from .tactical_operations import TacticalOperationRegistrationError, _check_route_owner

    module = _resolve_module(module_id)
    if module is None:
        return True
    fixed = KINDS[kind].get("owner")
    if fixed:
        return module.get("id") != fixed or module.get("category") != "core"
    try:
        _check_route_owner(module, KINDS[kind]["segments"], KINDS[kind]["route"])
    except TacticalOperationRegistrationError:
        return True
    return False


def owner_module(kind: str) -> dict | None:
    """The module that Core writes the deny rows of this kind against: the first enabled core owner of the rule (no replacements)."""
    from .tactical_operations import _owners_for_rule

    fixed = KINDS[kind].get("owner")
    if fixed:
        module = _resolve_module(fixed)
        return module if module is not None and module.get("category") == "core" else None
    for name in sorted(_owners_for_rule(KINDS[kind]["rule"], pairs={})):
        module = _resolve_module(name)
        if module is not None and module.get("category") == "core":
            return module
    return None


def _deny(request, user, kind: str, agent_id: str | None, reason: str, status: int, code: str, message: str, correlation_id: str):
    """One Core deny row for a refusal of a 403 or out-of-scope kind, then the refusal to raise. No body values are written."""
    from . import audit as audit_core

    audit = None
    module = owner_module(kind)
    if module is None:
        logger.error("Tactical terminal ticket refused (%s) but no enabled core owner exists to record it.", reason)
    else:
        try:
            audit = audit_core._record_tactical_websocket(
                actor=user, module_id=module["id"], action="deny", object_type=KINDS[kind]["object_type"],
                object_id=agent_id, message=DENY_MESSAGE, metadata={"reason": reason, "status": status, "kind": kind},
                websocket=kind, refusal=True, request=request, correlation_id=correlation_id,
            )
        except Exception:
            logger.exception("Could not write the deny row for a Tactical terminal ticket (%s).", reason)
    return TicketRefusal(status, code, message, audit)


def server_terminal_enabled() -> bool:
    """True when Tactical's own server web terminal switch is on: the same test as CoreSettings.web_terminal_enabled in v1.5.2.

    Off when Tactical runs hosted, when TRMM_DISABLE_WEB_TERMINAL or DEMO is set, or when the Global Settings toggle
    enable_server_webterminal is off. Any error reads as off (fail closed). Run in a worker thread: it reads the database.
    """
    try:
        from django.conf import settings

        if any(getattr(settings, name, False) for name in ("HOSTED", "TRMM_DISABLE_WEB_TERMINAL", "DEMO")):
            return False
        from core.models import CoreSettings  # Tactical's own model

        core = CoreSettings.objects.first()
        return bool(core is not None and core.web_terminal_enabled)
    except Exception:
        logger.exception("Could not read Tactical's server web terminal switch; treating it as off.")
        return False


def server_terminal_available(user) -> bool:
    """May this user be given a server shell right now? Tactical's switch is on and the user holds can_use_webterm (a Django
    superuser or a role superuser holds every flag). Core checks this before it writes a start row, so a row never stands for a shell
    that Tactical would refuse. A race (the switch flipped after this check) is the one way a row exists without a shell."""
    from .rbac import has_tactical_permission

    return server_terminal_enabled() and has_tactical_permission(user, SERVER_TERMINAL_PERMISSION)


def issue_ticket(request, *, module_id: str, kind: str, agent_id: str | None = None) -> dict[str, Any]:
    """Check the caller and mint one ticket (201 body). Raises TicketRefusal for every refusal.

    Agent kind order: the signed-in session; the kind exists; the agent id is well formed; the module owns the kind (403
    websocket_owner_required); the Tactical flag can_use_terminal (403 tactical_permission_denied); the agent is inside the
    caller's role scope (404 object_not_found, the executor's code). Each 403 and scope refusal writes one Core deny row.
    Server kind order (1.17.34, AD-35): the session; the kind exists; no agent id; the module is exactly globalsettings (403
    websocket_owner_required); the caller is an effective superuser (403 superuser_required); Tactical's server terminal is on and
    the caller holds can_use_webterm (403 server_terminal_disabled). A successful mint writes no audit row: the audit row is one per
    session start. ``agent_id`` defaults to None, so a 1.0.0 caller that names it is unchanged.
    """
    from . import audit as audit_core
    from . import resources_adapter as adapter
    from . import session_security
    from .rbac import has_tactical_permission

    user = getattr(request, "user", None)
    session = getattr(request, "tec_tac_session", None)
    if user is None or not getattr(user, "is_authenticated", False) or session is None:
        raise TicketRefusal(401, "authenticated_request_required", "This operation needs a signed-in Tec-Tac request.")
    if kind not in KINDS:
        raise TicketRefusal(404, "websocket_kind_not_found", "Core has no Tactical socket of that kind.")
    spec = KINDS[kind]
    server_kind = bool(spec.get("superuser_only"))
    if server_kind:
        if agent_id is not None:
            raise TicketRefusal(400, "invalid_ticket_request", "A server terminal ticket takes no agent id.")
    elif not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
        raise TicketRefusal(400, "invalid_agent_id", "The agent id is not valid.")
    correlation_id = audit_core.request_correlation_id(request)
    if owner_refusal(module_id, kind):
        raise _deny(request, user, kind, agent_id, "websocket_owner_required", 403, "websocket_owner_required", OWNER_MESSAGE, correlation_id)
    if server_kind:
        if not session_security._is_effective_superuser(user):
            raise _deny(request, user, kind, None, "superuser_required", 403, "superuser_required", SUPERUSER_MESSAGE, correlation_id)
        if not server_terminal_available(user):
            raise _deny(
                request, user, kind, None, "server_terminal_disabled", 403, "server_terminal_disabled",
                SERVER_TERMINAL_OFF_MESSAGE, correlation_id,
            )
    else:
        flag = spec["permission"]
        if not has_tactical_permission(user, flag):
            raise _deny(
                request, user, kind, agent_id, "permission_denied", 403, "tactical_permission_denied",
                PERMISSION_MESSAGE, correlation_id,
            )
        try:
            in_scope = bool(adapter.objects_in_role_scope(user=user, resource_type="agent", identifiers=[agent_id]))
        except Exception:
            logger.exception("Could not check the role scope for a Tactical terminal ticket; refusing.")
            in_scope = False
        if not in_scope:
            raise _deny(request, user, kind, agent_id, "not_found", 404, "object_not_found", SCOPE_MESSAGE, correlation_id)
    digest = session_security.request_knox_digest(request)
    if not digest:
        raise TicketRefusal(401, "tactical_session_required", "Sign in again so Core can link this session to Tactical.")

    ticket = secrets.token_urlsafe(32)
    session_id = str(uuid.uuid4())
    value = {
        "user_id": user.pk,
        "trust_id": str(getattr(session, "id", "")),
        "knox_digest": digest,
        "module_id": module_id,
        "kind": kind,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "expires_at": time.time() + TICKET_TTL_SECONDS,
    }
    if not server_kind:
        value["agent_id"] = agent_id
    key = cache_key(ticket)
    try:
        added = bool(cache.add(key, value, TICKET_TTL_SECONDS))
        stored = cache.get(key) if added else None
    except Exception:
        logger.exception("Tactical terminal ticket store is unavailable; no ticket issued.")
        added, stored = False, None
    if not added or stored != value:
        # A dummy or unreachable cache holds nothing, so there is no ticket to use. Fail closed.
        if added:
            try:
                cache.delete(key)
            except Exception:
                pass
        raise TicketRefusal(503, "websocket_unavailable", "Core cannot issue a terminal ticket right now. Nothing was started.")
    return {
        "ticket": ticket,
        "path": spec["path"].format(ticket=ticket),
        "session_id": session_id,
        "expires_in": TICKET_TTL_SECONDS,
        "kind": kind,
    }


def consume_ticket(ticket: str) -> dict | None:
    """Take a ticket out of the store, once. None for a malformed, unknown, replayed or expired ticket.

    ``cache.delete`` returns True for exactly one caller, so two sockets that read the same ticket cannot both use it. A cache
    error reads as None (fail closed).
    """
    if not isinstance(ticket, str) or not TICKET_PATTERN.fullmatch(ticket):
        return None
    key = cache_key(ticket)
    try:
        value = cache.get(key)
        if not isinstance(value, dict):
            return None
        if not cache.delete(key):
            return None
    except Exception:
        logger.exception("Tactical terminal ticket store is unavailable; refusing the socket.")
        return None
    if float(value.get("expires_at", 0)) <= time.time():
        return None
    return value


def _is_stale_connection_error(exc: BaseException) -> bool:
    """True for a database error that a fresh connection can cure: OperationalError or InterfaceError (the connection is closed, the
    server closed it, pgbouncer restarted). Anything else, and a Django that cannot be imported here, is not one."""
    try:
        from django.db import InterfaceError, OperationalError
    except ImportError:
        return False
    return isinstance(exc, (OperationalError, InterfaceError))


def _in_atomic_block(connections) -> bool:
    return any(getattr(conn, "in_atomic_block", False) for conn in connections.all())


def run_with_fresh_connection(fn, *args, **kwargs):
    """Run a database read. On a stale connection, close this thread's connections and run it once more (Core 1.17.33).

    A connection that Django has not yet flagged (CONN_MAX_AGE above 0, then a Postgres or pgbouncer restart or an idle kill) fails on
    first use. One such failure must not refuse a good ticket or close a terminal that has run for hours. Rules: only OperationalError and
    InterfaceError are retried, exactly once, and the whole of ``fn`` runs again (so the retry re-runs the full check, not one query). A
    second failure is raised as it is, so callers keep failing closed. Inside a transaction nothing is closed or retried, because a close
    would drop the transaction. Use it for reads only: never for a write that a retry could double (the strict audit row).
    """
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        if not _is_stale_connection_error(exc):
            raise
        from django.db import connections

        if _in_atomic_block(connections):
            raise
        logger.warning("A database connection was stale; reconnecting once.")
        connections.close_all()
        return fn(*args, **kwargs)


def ensure_usable_connections() -> None:
    """Before a write that must not be retried: close this thread's connection if it no longer answers, so the next query opens a
    fresh one. Skipped inside a transaction, for a connection that was never opened, and where Django cannot be imported."""
    try:
        from django.db import connections
    except ImportError:
        return
    for conn in connections.all():
        if getattr(conn, "in_atomic_block", False) or getattr(conn, "connection", None) is None:
            continue
        try:
            usable = conn.is_usable()
        except Exception:  # noqa: BLE001 - a connection that cannot even answer the check is not usable
            usable = False
        if not usable:
            conn.close()


def write_start_row(**kwargs):
    """The strict start row. The connection is checked first, but the write itself is never retried: a retry could double a row, and a
    failed write must stay audit_unavailable (no row, no start). Shared by the agent and the server terminal."""
    from . import audit as audit_core

    ensure_usable_connections()
    return audit_core._record_tactical_websocket(**kwargs)


def _session_refusal_once(value: dict, activity_at=None) -> str | None:
    """session_refusal without its error handling: a database error is raised, so run_with_fresh_connection can retry the whole check.

    The refresh and the idle and absolute checks run in session_security.record_terminal_activity, which is safe to run twice."""
    from knox.models import AuthToken

    from . import session_security

    user = get_user_model().objects.filter(pk=value["user_id"]).first()
    if user is None or not user.is_active or bool(getattr(user, "block_dashboard_login", False)):
        return "user_unavailable"
    digest = str(value.get("knox_digest") or "")
    now = timezone.now()
    live = bool(digest) and AuthToken.objects.filter(digest=digest).filter(Q(expiry__isnull=True) | Q(expiry__gt=now)).exists()
    if not live:
        return "credential_unavailable"
    return session_security.record_terminal_activity(value["trust_id"], user.pk, digest, activity_at)


def session_refusal(value: dict, activity_at=None) -> str | None:
    """Why the sign-in behind a ticket no longer holds, or None when it still does. Used at connect and every watch interval.

    Checks: the user exists, is active and is not blocked from the dashboard; the Knox token behind the ticket is present and not
    expired; the Tec-Tac session row is not revoked, belongs to that user, carries the same Knox digest, is inside its absolute lifetime
    and is not past the idle limit (Core 1.17.34, AD-35: the idle limit now applies to terminals). ``activity_at`` is the time of the
    person's last input or resize since the last check (see TerminalActivity): it refreshes the idle timer before the idle check.
    Output never does. A session found idle or past its maximum is revoked, like a REST request or the sweep would. Reasons:
    user_unavailable, credential_unavailable, session_revoked, session_expired, session_idle_timeout, check_failed. A stale database
    connection is retried once (see run_with_fresh_connection). Any other error, or a second failure, is a refusal.
    """
    try:
        return run_with_fresh_connection(_session_refusal_once, value, activity_at)
    except Exception:
        logger.exception("Could not re-check the sign-in behind a Tactical terminal ticket; refusing.")
        return "check_failed"


def _monotonic() -> float:
    return time.monotonic()


def _whole_number(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def counts_as_activity(kind: str, content) -> bool:
    """Does this frame count as the person working in the terminal (AD-35)? Only input and resize do.

    Agent terminal: {"action": "input", "data": non-empty text} and {"action": "resize", "rows": n, "cols": n}. Server terminal:
    {"action": "trmmcli.input", "data": {"input": non-empty text}} and {"action": "trmmcli.resize", "data": {"rows": n, "cols": n}}.
    start, kill, disconnect, unknown actions, empty input and a size that is not a whole number do not count. Never raises, and
    keeps and logs nothing from the frame."""
    if not isinstance(content, dict):
        return False
    action = content.get("action")
    if kind == "server-terminal":
        data = content.get("data")
        if not isinstance(data, dict):
            return False
        if action == "trmmcli.input":
            return isinstance(data.get("input"), str) and bool(data["input"])
        if action == "trmmcli.resize":
            return _whole_number(data.get("rows")) and _whole_number(data.get("cols"))
        return False
    if action == "input":
        return isinstance(content.get("data"), str) and bool(content["data"])
    if action == "resize":
        return _whole_number(content.get("rows")) and _whole_number(content.get("cols"))
    return False


class TerminalActivity:
    """When the person last typed or resized, kept in memory only. Input does no database write: the watcher takes this once a tick
    and passes it to record_terminal_activity. A monotonic clock measures how long ago the input was, so a wall-clock jump cannot
    move it. No frame, text or size is stored."""

    def __init__(self):
        self._lock = threading.Lock()
        self._noted = None

    def note(self, kind: str, content) -> bool:
        if not counts_as_activity(kind, content):
            return False
        with self._lock:
            self._noted = _monotonic()
        return True

    def take(self):
        """The wall-clock time of the last counted frame since the previous take (timezone-aware), or None."""
        with self._lock:
            noted, self._noted = self._noted, None
        if noted is None:
            return None
        return timezone.now() - timedelta(seconds=max(0.0, _monotonic() - noted))


# ------------------------------------------------------------------------------------------------ Origin (shared by both sockets)
ORIGIN_DEFAULT_PORTS = {"http": 80, "https": 443}


def normal_origin(value) -> str | None:
    """scheme://host[:port] in lower case, with the default port (443 for https, 80 for http) dropped. None when the value is not a
    plain http(s) origin: a path, query, fragment, user name, '*', 'null', a number, a regular expression or a space in it."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text or text in ("*", "null") or not all(ch.isascii() and ch.isprintable() and not ch.isspace() for ch in text):
        return None
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ORIGIN_DEFAULT_PORTS or not parts.hostname:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment or "@" in parts.netloc:
        return None
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    if port is not None and port != ORIGIN_DEFAULT_PORTS[parts.scheme]:
        host = f"{host}:{port}"
    return f"{parts.scheme}://{host}"


def configured_frontend_origins() -> set[str]:
    """The frontend origins Tactical's own CORS settings name: CORS_ORIGIN_WHITELIST and, when present, CORS_ALLOWED_ORIGINS.

    Read from server settings only, never from a request, a header or a ticket. Entries that are not plain http(s) origins are ignored
    (see normal_origin), and so are regular expressions and allow-all settings: narrower than Tactical's CORS on purpose. A settings read
    that fails gives an empty set, so only the same-host rule applies.
    """
    try:
        # imported here, not at the top, so this module still loads where Django's settings are not configured
        from django.conf import settings

        lists = [getattr(settings, name, None) for name in ("CORS_ORIGIN_WHITELIST", "CORS_ALLOWED_ORIGINS")]
    except Exception:  # noqa: BLE001 - any failure to read settings means no frontend origin (fail closed)
        logger.warning("Could not read Tactical's CORS settings; the terminal socket accepts the request host only.")
        return set()
    origins: set[str] = set()
    for entries in lists:
        if isinstance(entries, (list, tuple, set, frozenset)):
            origins.update(origin for origin in map(normal_origin, entries) if origin)
    return origins


def origin_allowed(scope) -> bool:
    """A browser that sends an Origin must come from the same host as the request, or from a frontend origin that Tactical's CORS
    settings name (configured_frontend_origins). That second case is the split layout: the API on one host, the web UI on another.
    No Origin is allowed: the ticket already blocks use from another site, because the ticket is never sent by the page of another site.
    A null, empty or malformed Origin is refused. The frontend list comes from server settings only, never from the request."""
    headers = {}
    for name, value in scope.get("headers") or []:
        headers[bytes(name).lower()] = bytes(value)
    origin = headers.get(b"origin")
    if origin is None:
        return True
    origin_text = origin.decode("latin-1").strip()
    host = headers.get(b"host", b"").decode("latin-1").strip().lower()
    try:
        netloc = urlsplit(origin_text).netloc.lower()
    except ValueError:
        return False
    if host and netloc and netloc == host:
        return True
    origin_form = normal_origin(origin_text)
    return origin_form is not None and origin_form in configured_frontend_origins()


class TacticalWebSocketProvider:
    """The capability provider. A module may ask for a ticket only for itself: Core verifies the caller from the call stack."""

    def issue_ticket(self, *, request, module_id: str, kind: str, agent_id: str | None = None) -> dict[str, Any]:
        from .caller_identity import calling_module_for_core_provider

        identity = calling_module_for_core_provider(provider_file=__file__)
        if identity is None or identity.module_id != module_id:
            raise TicketRefusal(403, "websocket_caller_required", OWNER_MESSAGE)
        return issue_ticket(request, module_id=module_id, kind=kind, agent_id=agent_id)


_PROVIDER = TacticalWebSocketProvider()


def tactical_websocket_contract_metadata() -> dict[str, Any]:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["issue_ticket"],
        "http": "POST /api/tfd/tactical-websocket/<module_id>/<kind>/tickets/. Kind agent-terminal: the JSON object {agent_id} and nothing else. Kind server-terminal (1.1.0): the JSON object {} and nothing else, module_id globalsettings only. Answers 201 {ticket, path, session_id, expires_in, kind}.",
        "socket": "wss://<host>/ws/tfd/agent-terminal/<ticket>/ or wss://<host>/ws/tfd/server-terminal/<ticket>/ (no token in the URL other than the ticket; no Authorization header). Open the path from the 201 answer.",
        "kinds": {
            "agent-terminal": {
                "owner": "the owner of the route agents/{agent_id}/terminal-defaults/ (remote-background in 1.17.31; an honoured AD-20 replacement follows it)",
                "permission": "can_use_terminal",
                "scope": "the agent must be inside the caller's client and site limits",
                "body": "{agent_id}",
                "messages": "Tactical's start, input, resize and kill frames.",
            },
            "server-terminal": {
                "owner": "the module globalsettings only (AD-35 condition 3); no replacement and no other module",
                "who": "an effective superuser only (a Django superuser, a role superuser or the root user)",
                "available": "only where Tactical's server web terminal is on: not hosted, not TRMM_DISABLE_WEB_TERMINAL, not DEMO, and the Global Settings toggle on; the caller also holds can_use_webterm",
                "body": "{}",
                "messages": "Tactical's trmmcli.input {data:{input}}, trmmcli.resize {data:{rows,cols}} and trmmcli.disconnect, and its trmmcli.output answers. There is no start frame: the shell starts when the socket is accepted.",
                "runs_as": "the Tactical service user on the server that runs Tec-Tac and Tactical",
                "added_in": "1.1.0 (Core 1.17.34)",
            },
        },
        "ticket": {"ttl_seconds": TICKET_TTL_SECONDS, "single_use": True, "store": "Django cache (Tactical Redis), key holds the SHA-256 of the ticket only"},
        "close_codes": {
            "4401": "ticket missing, expired, used or unknown, or the sign-in behind it ended (revoked, expired, idle, Knox token gone, user disabled)",
            "4003": "Origin is neither the request host nor a frontend origin from Tactical's CORS_ORIGIN_WHITELIST, or the Tactical flag, agent scope or superuser standing no longer holds, or the server terminal was switched off",
            "4502": "audit_unavailable (1.1.0): the strict server terminal start row could not be written, so no shell was started",
            "4503": "Tactical's terminal consumer could not be loaded; Tactical itself still runs",
        },
        "ticket_refusals": {
            "403 superuser_required": "server-terminal: the caller is not an effective superuser (1.1.0)",
            "403 server_terminal_disabled": "server-terminal: Tactical's server web terminal is off, or the caller lacks can_use_webterm (1.1.0)",
            "400 invalid_ticket_request": "the body has the wrong keys for the kind",
        },
        "activity": "Terminal input and resize frames count as session activity (1.17.34, AD-35): they refresh the sign-in's idle timer, at most once every 30 seconds, with no database write per keystroke. Output alone does not. The idle limit and the absolute maximum now close a terminal socket 4401 and end the sign-in. No frame, text or size is logged or audited.",
        "messages": "Tactical's own messages, unchanged (AD-25).",
        "audit": "one row per session start, written by Core before Tactical starts the shell (strict: no row, no start): custom:terminal-start for agent-terminal, custom:server-terminal-start (object type server, module globalsettings) for server-terminal. Core writes deny rows for refusals; a successful mint writes none. No row ever holds typed text or output.",
        "same_owner_as": "agent-terminal: agents/{agent_id}/terminal-defaults/ (the owner table decides both)",
    }


def register_core_tactical_websocket_capability():
    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Single-use tickets for Tactical terminal sockets that Core relays for the signed-in user, for the owning core module only.",
        operations=("issue_ticket",),
        metadata=tactical_websocket_contract_metadata(),
    )


class _AgentTerminalRoute:
    """The ASGI app of ws/tfd/agent-terminal/<ticket>/. Imports the consumer on the first connection, so a Tactical change that moves
    its terminal class closes this socket with 4503 and never stops Tactical from starting (rule 1.15)."""

    async def __call__(self, scope, receive, send):
        try:
            from .tactical_websocket_consumers import TecTacAgentTerminalConsumer

            app = TecTacAgentTerminalConsumer.as_asgi()
        except Exception:
            logger.exception("Tactical's terminal consumer could not be loaded; closing the Tec-Tac terminal socket.")
            await send({"type": "websocket.close", "code": 4503})
            return
        await app(scope, receive, send)


class _ServerTerminalRoute:
    """The ASGI app of ws/tfd/server-terminal/<ticket>/ (1.17.34). Imports the consumer on the first connection. Tactical's server
    terminal needs fcntl and pty (Linux only), so a missing or moved core.consumers closes 4503 and never stops Tactical starting."""

    async def __call__(self, scope, receive, send):
        try:
            from .tactical_websocket_server_terminal import TecTacServerTerminalConsumer

            app = TecTacServerTerminalConsumer.as_asgi()
        except Exception:
            logger.exception("Tactical's server terminal consumer could not be loaded; closing the Tec-Tac server terminal socket.")
            await send({"type": "websocket.close", "code": 4503})
            return
        await app(scope, receive, send)


def agent_terminal_route():
    return _AgentTerminalRoute()


def server_terminal_route():
    return _ServerTerminalRoute()


def install_tactical_websocket_route() -> bool:
    """Append the ticketed terminal routes to Tactical's ws_urlpatterns, once each. Returns True when this call added a route.

    The agent route is skipped in DEMO, as Tactical skips its terminal route. The server route (1.17.34) is added only where Tactical
    itself would install ws/trmmcli/: not DEMO, not HOSTED and not TRMM_DISABLE_WEB_TERMINAL."""
    from django.conf import settings
    from django.urls import path
    from tacticalrmm import urls as tactical_urls

    if getattr(settings, "DEMO", False):
        return False
    routes = tactical_urls.ws_urlpatterns
    present = {str(getattr(pattern, "pattern", "")) for pattern in routes}
    added = False
    if ROUTE_PATTERN not in present:
        routes.append(path(ROUTE_PATTERN, agent_terminal_route()))
        added = True
    web_terminal_off = any(getattr(settings, name, False) for name in ("HOSTED", "TRMM_DISABLE_WEB_TERMINAL"))
    if not web_terminal_off and SERVER_ROUTE_PATTERN not in present:
        routes.append(path(SERVER_ROUTE_PATTERN, server_terminal_route()))
        added = True
    return added

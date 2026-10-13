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

Only the kind agent-terminal exists in 1.17.31. The server web terminal (ws/trmmcli/) is a shell on the server itself and is not a kind.
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
import time
import uuid
from typing import Any

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

from .capabilities import register_capability

logger = logging.getLogger("tec_tac.tactical_websocket")

CAPABILITY_ID = "core.tactical_websocket"
CAPABILITY_VERSION = "1.0.0"
TICKET_TTL_SECONDS = 30
TICKET_CACHE_PREFIX = "tec-tac:wsticket:v1:"
TICKET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")  # secrets.token_urlsafe(32) is 43 characters
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
TICKET_PATH = "/ws/tfd/agent-terminal/{ticket}/"
ROUTE_PATTERN = "ws/tfd/agent-terminal/<str:ticket>/"
DENY_MESSAGE = "Core refused a Tactical terminal ticket. Nothing was started."
PERMISSION_MESSAGE = "Your Tactical role does not allow this operation. It needs the Tactical permission can_use_terminal."
SCOPE_MESSAGE = "The requested object was not found, or you cannot access it."
OWNER_MESSAGE = "Core refused a Tactical terminal ticket: this module does not own that kind of socket."

# The kinds Core relays. ``segments`` is the Tactical route the owner table decides by; ``rule`` is that rule (the same key as
# ROUTE_OWNERS, so the owners are read from the one table). Adding a kind is additive: a new row here and its own owner rule.
KINDS: dict[str, dict[str, Any]] = {
    "agent-terminal": {
        "route": "agents/{agent_id:agent}/terminal-defaults/",
        "segments": (("lit", "agents"), ("param", "agent_id", "agent"), ("lit", "terminal-defaults")),
        "rule": ("agents", "{}", "terminal-defaults"),
        "permission": "can_use_terminal",
        "object_type": "agent",
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
    try:
        _check_route_owner(module, KINDS[kind]["segments"], KINDS[kind]["route"])
    except TacticalOperationRegistrationError:
        return True
    return False


def owner_module(kind: str) -> dict | None:
    """The module that Core writes the deny rows of this kind against: the first enabled core owner of the rule (no replacements)."""
    from .tactical_operations import _owners_for_rule

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


def issue_ticket(request, *, module_id: str, kind: str, agent_id: str) -> dict[str, Any]:
    """Check the caller and mint one ticket (201 body). Raises TicketRefusal for every refusal.

    Order: the signed-in session; the kind exists; the agent id is well formed; the module owns the kind (403
    websocket_owner_required); the Tactical flag can_use_terminal (403 tactical_permission_denied); the agent is inside the
    caller's role scope (404 object_not_found, the executor's code). Each 403 and scope refusal writes one Core deny row.
    A successful mint writes no audit row: the audit row is one per session start.
    """
    from . import audit as audit_core
    from . import resources_adapter as adapter
    from .rbac import has_tactical_permission
    from .session_security import request_knox_digest

    user = getattr(request, "user", None)
    session = getattr(request, "tec_tac_session", None)
    if user is None or not getattr(user, "is_authenticated", False) or session is None:
        raise TicketRefusal(401, "authenticated_request_required", "This operation needs a signed-in Tec-Tac request.")
    if kind not in KINDS:
        raise TicketRefusal(404, "websocket_kind_not_found", "Core has no Tactical socket of that kind.")
    if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
        raise TicketRefusal(400, "invalid_agent_id", "The agent id is not valid.")
    correlation_id = audit_core.request_correlation_id(request)
    if owner_refusal(module_id, kind):
        raise _deny(request, user, kind, agent_id, "websocket_owner_required", 403, "websocket_owner_required", OWNER_MESSAGE, correlation_id)
    flag = KINDS[kind]["permission"]
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
    digest = request_knox_digest(request)
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
        "agent_id": agent_id,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "expires_at": time.time() + TICKET_TTL_SECONDS,
    }
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
        "path": TICKET_PATH.format(ticket=ticket),
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


def session_refusal(value: dict) -> str | None:
    """Why the sign-in behind a ticket no longer holds, or None when it still does. Used at connect and every watch interval.

    Checks: the user exists, is active and is not blocked from the dashboard; the Tec-Tac session row is not revoked, belongs to
    that user and is inside its absolute lifetime; the Knox token behind it is still present and not expired. The idle timeout is
    not checked: typing in a terminal does not touch the REST API. Any error is a refusal.
    """
    from knox.models import AuthToken

    from .models import TecTacSessionTrust

    try:
        user = get_user_model().objects.filter(pk=value["user_id"]).first()
        if user is None or not user.is_active or bool(getattr(user, "block_dashboard_login", False)):
            return "user_unavailable"
        trust = TecTacSessionTrust.objects.filter(pk=value["trust_id"]).first()
        if trust is None or trust.revoked or trust.user_id != user.pk:
            return "session_revoked"
        now = timezone.now()
        if trust.absolute_expires_at is None or now >= trust.absolute_expires_at:
            return "session_expired"
        digest = str(trust.knox_digest or "")
        if not digest or digest != value.get("knox_digest"):
            return "credential_unavailable"
        live = AuthToken.objects.filter(digest=digest).filter(Q(expiry__isnull=True) | Q(expiry__gt=now)).exists()
        if not live:
            return "credential_unavailable"
        return None
    except Exception:
        logger.exception("Could not re-check the sign-in behind a Tactical terminal ticket; refusing.")
        return "check_failed"


class TacticalWebSocketProvider:
    """The capability provider. A module may ask for a ticket only for itself: Core verifies the caller from the call stack."""

    def issue_ticket(self, *, request, module_id: str, kind: str, agent_id: str) -> dict[str, Any]:
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
        "http": "POST /api/tfd/tactical-websocket/<module_id>/<kind>/tickets/ with the JSON object {agent_id} and nothing else. Answers 201 {ticket, path, session_id, expires_in, kind}.",
        "socket": "wss://<host>/ws/tfd/agent-terminal/<ticket>/ (no token in the URL other than the ticket; no Authorization header).",
        "kinds": {
            "agent-terminal": {
                "owner": "the owner of the route agents/{agent_id}/terminal-defaults/ (remote-background in 1.17.31; an honoured AD-20 replacement follows it)",
                "permission": "can_use_terminal",
                "scope": "the agent must be inside the caller's client and site limits",
            },
        },
        "ticket": {"ttl_seconds": TICKET_TTL_SECONDS, "single_use": True, "store": "Django cache (Tactical Redis), key holds the SHA-256 of the ticket only"},
        "close_codes": {
            "4401": "ticket missing, expired, used or unknown, or the sign-in behind it ended (revoked, expired, Knox token gone, user disabled)",
            "4003": "Origin not the request host, or the Tactical flag or agent scope no longer holds",
            "4503": "Tactical's terminal consumer could not be loaded; Tactical itself still runs",
        },
        "messages": "Tactical's own start, input, resize and kill messages, and its trmmcli.output, terminal_error and terminal_info answers, unchanged (AD-25).",
        "audit": "one row per session start, action custom:terminal-start, written by Core before Tactical starts the shell (strict: no row, no start); Core writes deny rows for refusals; a successful mint writes none.",
        "same_owner_as": "agents/{agent_id}/terminal-defaults/ (the owner table decides both)",
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


def agent_terminal_route():
    return _AgentTerminalRoute()


def install_tactical_websocket_route() -> bool:
    """Append the ticketed terminal route to Tactical's ws_urlpatterns, once. Skipped in DEMO, as Tactical skips its terminal route.

    Returns True when the route was added by this call."""
    from django.conf import settings
    from django.urls import path
    from tacticalrmm import urls as tactical_urls

    if getattr(settings, "DEMO", False):
        return False
    routes = tactical_urls.ws_urlpatterns
    if any(str(getattr(pattern, "pattern", "")) == ROUTE_PATTERN for pattern in routes):
        return False
    routes.append(path(ROUTE_PATTERN, agent_terminal_route()))
    return True

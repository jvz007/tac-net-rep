"""The relayed Tactical terminal socket (Core 1.17.31, C4 part 2). Loaded lazily by tactical_websocket._AgentTerminalRoute.

TecTacAgentTerminalConsumer is Tactical's own TerminalStreamConsumer, run in-process as the ticket's user. Tactical's permission,
shell and NATS logic run unchanged. Core adds, in this order: the ticket (consumed once), the sign-in re-check, the Origin check, the
flag and scope re-check, and one strict audit row before the first start of each session. A watcher closes the socket when the sign-in
behind it ends. Core logs no frame: not input, not output, not a ticket, not a token.

Close codes: 4401 (ticket or sign-in), 4003 (Origin, flag or scope). Messages are Tactical's own, unchanged (AD-25).
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from urllib.parse import urlsplit

from agents.consumers import TerminalStreamConsumer  # Tactical's own consumer; imported only when a socket connects
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model

from . import audit as audit_core
from . import resources_adapter as adapter
from .rbac import has_tactical_permission
from .tactical_websocket import KINDS, consume_ticket, session_refusal

logger = logging.getLogger("tec_tac.tactical_websocket")

WATCH_SECONDS = 30
SHELL_MAX_CHARS = 260
KIND = "agent-terminal"


def clean_shell(value) -> str:
    """The shell as the audit row records it: text with control characters removed, at most 260 characters, or 'default'."""
    text = "".join(ch for ch in str(value or "").strip() if ch.isprintable())
    return text[:SHELL_MAX_CHARS] or "default"


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


def recheck(value: dict):
    """(close code, user). A None code means every check passed. Runs in a worker thread (database_sync_to_async)."""
    if session_refusal(value):
        return 4401, None
    user = get_user_model().objects.filter(pk=value["user_id"]).first()
    if user is None:
        return 4401, None
    if not has_tactical_permission(user, KINDS[KIND]["permission"]):
        return 4003, None
    if not adapter.objects_in_role_scope(user=user, resource_type="agent", identifiers=[value["agent_id"]]):
        return 4003, None
    return None, user


class TecTacAgentTerminalConsumer(TerminalStreamConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tec_value = None
        self._tec_start_lock = asyncio.Lock()
        self._tec_watch = None

    async def connect(self):
        route_kwargs = (self.scope.get("url_route") or {}).get("kwargs") or {}
        value = await database_sync_to_async(consume_ticket)(str(route_kwargs.get("ticket", "")))
        if value is None or value.get("kind") != KIND:
            await self.close(4401)
            return
        if not origin_allowed(self.scope):
            await self.close(4003)
            return
        code, user = await database_sync_to_async(recheck)(value)
        if code is not None:
            await self.close(code)
            return
        self._tec_value = value
        # agent and session come from the ticket only, never from the URL. Tactical's own connect reads them from url_route.
        self.scope = {
            **self.scope,
            "user": user,
            "url_route": {"args": (), "kwargs": {"agent_id": value["agent_id"], "session_id": value["session_id"]}},
        }
        await super().connect()
        if self.group_name:  # set by Tactical only after its own permission and scope checks passed; the socket is accepted
            self._tec_watch = asyncio.ensure_future(self._watch())

    async def disconnect(self, close_code):
        watch, self._tec_watch = self._tec_watch, None
        if watch is not None and not watch.done():
            watch.cancel()
        await super().disconnect(close_code)

    async def _start_terminal(self, content):
        # One lock for Core's audit row and the start, so two start messages cannot both write a row. Tactical's own lock is taken
        # inside the parent call, so it is not held here.
        async with self._tec_start_lock:
            if self.started:
                return  # the second start while a shell runs: Tactical answers it, and no second row is written
            if not await self._write_start_row(content):
                await self._send_terminal_error(
                    "Core could not write the audit record, so the terminal was not started.", code="audit_unavailable",
                )
                return
            await super()._start_terminal(content)

    async def _write_start_row(self, content) -> bool:
        value = self._tec_value
        try:
            result = await database_sync_to_async(audit_core._record_tactical_websocket)(
                actor=self.user, module_id=value["module_id"], action="custom:terminal-start", object_type=KINDS[KIND]["object_type"],
                object_id=value["agent_id"], message="Terminal session started through Core's ticketed socket.",
                after={
                    "shell": clean_shell(content.get("shell")),
                    "run_as_user": bool(content.get("run_as_user", False)),
                    "session_id": value["session_id"],
                },
                websocket=KIND, strict=True, correlation_id=value["correlation_id"],
            )
            return bool(result.get("recorded"))
        except Exception:
            logger.exception("Terminal start audit row was not written; the terminal will not start.")
            return False

    async def _watch(self):
        """Close the socket when the sign-in behind it ends. Idle time is not checked (see tactical_websocket.session_refusal)."""
        try:
            while True:
                await asyncio.sleep(WATCH_SECONDS)
                reason = await database_sync_to_async(session_refusal)(self._tec_value)
                if reason:
                    await self.close(4401)
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Terminal socket watcher failed; closing the socket.")
            with contextlib.suppress(Exception):
                await self.close(4401)

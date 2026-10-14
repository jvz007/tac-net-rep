"""The relayed Tactical server web terminal socket (Core 1.17.34, AD-35). Loaded lazily by tactical_websocket._ServerTerminalRoute.

TecTacServerTerminalConsumer is Tactical's own core.consumers.TerminalConsumer (v1.5.2), run in-process as the ticket's user. It is a
shell on the server that runs Tec-Tac and Tactical, started as the Tactical service user, so it is the most powerful socket Core
relays (AD-35 condition 1). Core adds, in this order: the ticket (consumed once, kind server-terminal), the Origin check, the sign-in
re-check, the effective-superuser re-check, Tactical's own switch and can_use_webterm, and one strict audit row BEFORE Tactical starts
the shell. If that row cannot be written nothing starts (close 4502). Tactical's connect is synchronous, so this consumer is too: it
runs in a worker thread, and a daemon thread watches the sign-in.

Tactical starts the shell the moment the socket is accepted (there is no start frame). Its frames are trmmcli.input, trmmcli.resize and
trmmcli.disconnect, and it answers trmmcli.output. Input and resize count as session activity, output does not (AD-35 condition 2). Core
logs and audits no frame: not input, not output, not a ticket, not a token.

Close codes: 4401 (ticket or sign-in), 4003 (Origin, superuser standing, switch or flag), 4502 (audit unavailable).
"""
from __future__ import annotations

import logging
import threading

from core.consumers import TerminalConsumer  # Tactical's own consumer (needs fcntl and pty); imported only when a socket connects
from django.contrib.auth import get_user_model

from . import session_security
from .rbac import has_tactical_permission
from .tactical_websocket import (
    KINDS,
    TerminalActivity,
    _session_refusal_once,
    consume_ticket,
    origin_allowed,
    run_with_fresh_connection,
    server_terminal_enabled,
    write_start_row,
)

logger = logging.getLogger("tec_tac.tactical_websocket")

KIND = "server-terminal"
WATCH_SECONDS = 30
AUDIT_UNAVAILABLE = 4502


def _recheck_once(value: dict, activity_at=None):
    if _session_refusal_once(value, activity_at):
        return 4401, None
    user = get_user_model().objects.filter(pk=value["user_id"]).first()
    if user is None:
        return 4401, None
    if not session_security._is_effective_superuser(user):
        return 4003, None
    if not server_terminal_enabled() or not has_tactical_permission(user, KINDS[KIND]["permission"]):
        return 4003, None
    return None, user


def recheck(value: dict, activity_at=None):
    """(close code, user). A None code means every check passed. Runs in a worker thread, never the event loop.

    The sign-in (with the idle and absolute limits and any input time), the effective-superuser standing, Tactical's switch and
    can_use_webterm. A stale database connection is retried once. Any other error, or a second failure, closes the socket 4401."""
    try:
        return run_with_fresh_connection(_recheck_once, value, activity_at)
    except Exception:
        logger.exception("Could not re-check the sign-in behind a server terminal ticket; refusing.")
        return 4401, None


class TecTacServerTerminalConsumer(TerminalConsumer):
    _tec_value = None
    _tec_activity = None
    _tec_stop = None
    _tec_watch = None

    def connect(self):
        route_kwargs = (self.scope.get("url_route") or {}).get("kwargs") or {}
        value = consume_ticket(str(route_kwargs.get("ticket", "")))
        if value is None or value.get("kind") != KIND:
            self.close(4401)
            return
        if not origin_allowed(self.scope):
            self.close(4003)
            return
        code, user = recheck(value)
        if code is not None:
            self.close(code)
            return
        if not self._write_start_row(user, value):
            self.close(AUDIT_UNAVAILABLE)  # fail closed: no row, no shell
            return
        self._tec_value = value
        self._tec_activity = TerminalActivity()
        self._tec_stop = threading.Event()
        # the user comes from the ticket only. Tactical's own connect reads it from the scope.
        self.scope = {**self.scope, "user": user}
        super().connect()
        if self.authorized:  # set by Tactical only after its own checks passed; the socket is accepted and the shell is starting
            self._tec_watch = threading.Thread(target=self._watch, daemon=True)
            self._tec_watch.start()

    def _write_start_row(self, user, value) -> bool:
        try:
            result = write_start_row(
                actor=user, module_id=value["module_id"], action="custom:server-terminal-start", object_type=KINDS[KIND]["object_type"],
                object_id=None, message="Server terminal session started through Core's ticketed socket.",
                after={"session_id": value["session_id"]},
                websocket=KIND, strict=True, correlation_id=value["correlation_id"],
            )
            return bool(result.get("recorded"))
        except Exception:
            logger.exception("Server terminal start audit row was not written; the shell will not start.")
            return False

    def receive_json(self, data, **kwargs):
        # Input and resize count as activity (AD-35); nothing is kept from the frame but the time. Output never counts.
        if self._tec_activity is not None:
            self._tec_activity.note(KIND, data)
        return super().receive_json(data, **kwargs)

    def disconnect(self, code):
        if self._tec_stop is not None:
            self._tec_stop.set()
        super().disconnect(code)

    def _end(self, code: int) -> None:
        """Close the socket with ``code`` and kill the shell. ``connected`` is cleared first, so Tactical's own run_command thread does
        not close the socket a second time with 4030 when the shell dies."""
        self.connected = False
        try:
            self.close(code)
        except Exception:  # noqa: BLE001 - the socket may already be gone; the shell must still die
            logger.warning("Could not close the server terminal socket; killing the shell anyway.")
        self.kill_pty()

    def _watch_tick(self) -> bool:
        """One check: hand any input time to the sign-in, then enforce the whole rule plus the superuser re-check. On any failure close
        the socket (4401 for the sign-in, 4003 for standing, switch or flag) and kill the shell. True when it did."""
        code, _ = recheck(self._tec_value, self._tec_activity.take())
        if code is not None:
            self._end(code)
            return True
        return False

    def _watch(self):
        """Run _watch_tick every WATCH_SECONDS until it closes the socket or the socket disconnects."""
        try:
            while not self._tec_stop.wait(WATCH_SECONDS):
                if self._watch_tick():
                    return
        except Exception:
            logger.exception("Server terminal watcher failed; closing the socket.")
            self._end(4401)
        finally:
            try:
                from django.db import connections

                connections.close_all()  # this thread's own database connections
            except Exception:  # noqa: BLE001 - nothing to close where Django is not available
                pass

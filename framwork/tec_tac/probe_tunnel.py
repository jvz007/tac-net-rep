"""Core's Network Probe tunnel (Core 1.18.47, C2 of the probe channel plan): the Console ticket, the session limits, the two data routes' shared
state and the end of a session. Part of the contract core.probe_transport (1.1.0 since Core 1.18.47, 1.2.0 since Core 1.18.50).

An engineer's Console (a native desktop tool) and a Network Probe each open one binary websocket to Core. Core relays the frames between the
two and nothing else: it reads byte 0 (the type) and the length, counts DATA bytes and never looks at stream ids, windows or payloads. It never
logs, audits or stores traffic content at any level.

This file holds what has no channels import: the ticket store, the session index and its limits, the per-session cache records, the account
re-check, the end of a session, the launch link and the two route classes. The consumers live in probe_tunnel_consumer and are imported on the
first connection, so a fault there closes the socket 4503 and never stops Tactical.

It is a sibling of probe_transport.py and imports nothing from endpoint_transport (AD-54). Its own cache prefixes (tec-tac:pt:ticket:, tec-tac:pt:tun...),
its own group prefix (tectac-pnt-) and its own audit actions (custom:probe-tunnel-*); the pools and the failure counters are the probe route's own.

Secrets: a ticket exists in clear text only in the answer of issue_tunnel_ticket and in the Authorization header of the Console's connection. The
cache holds its SHA-256. It is never in a log line, an audit row, a refusal text or a status result. A probe key is never held here.
"""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
import time
import uuid
from urllib.parse import quote

from . import probe_transport as pt

logger = logging.getLogger("tec_tac.probe_transport")

PROBE_SIDE_ROUTE_PATTERN = "ws/tfd/network-probe/tunnel/"
PROBE_SIDE_SOCKET_PATH = "/ws/tfd/network-probe/tunnel/"
CONSOLE_ROUTE_PATTERN = "ws/tfd/probe-tunnel/"
CONSOLE_SOCKET_PATH = "/ws/tfd/probe-tunnel/"
LAUNCH_SCHEME = "tectac-console"
SESSION_HEADER = b"x-tunnel-session"

GROUP_PREFIX = "tectac-pnt-"
TICKET_PREFIX = "tec-tac:pt:ticket:"
INDEX_KEY = "tec-tac:pt:tun-index"
LOCK_KEY = "tec-tac:pt:tun-lock"
SESSION_PREFIX = "tec-tac:pt:tun:"
SIDE_PREFIX = "tec-tac:pt:tunside:"
SIDE_PROBE_READY = "probe_ready"  # 1.18.48: written once the probe socket is in the group; the Console pairs on this, not on the attach marker
SIDE_CONSOLE_READY = "console_ready"  # 1.18.49: the same for the Console socket; both ready markers carry the socket's channel name
END_PREFIX = "tec-tac:pt:tunend:"
STATS_PREFIX = "tec-tac:pt:tunstat:"
CLOSED_PREFIX = "tec-tac:pt:tunclosed:"
AUDITED_PREFIX = "tec-tac:pt:tunaudit:"
TICKET_RATE_PREFIX = "tec-tac:pt:tkrate:"

TICKET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")  # secrets.token_urlsafe(32) is 43 characters
CHANNEL_PATTERN = re.compile(r"^[A-Za-z0-9._!-]{1,200}$")  # a channels specific channel name; anything else is refused
PERMISSION_PATTERN = re.compile(r"^networkprobe\.[a-z0-9_.]{1,100}$")
HOST_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")

TICKET_TTL_SECONDS = 60
PENDING_SLOT_SECONDS = 75  # a slot is held from the ticket until the session ends; a pending one heals after the ticket window plus 15 seconds
SLOT_GRACE_SECONDS = 60  # added to the hard cap when the Console connects, so a leaked slot of an open session heals
ENDED_KEEP_SECONDS = 3600
MAX_SESSIONS = 50
MAX_SESSIONS_PER_PROBE = 5
MAX_SESSIONS_PER_ENGINEER = 3
TICKETS_PER_MINUTE = 10
IDLE_SECONDS_DEFAULT, IDLE_SECONDS_MIN, IDLE_SECONDS_MAX = 900, 60, 900
CAP_SECONDS_DEFAULT, CAP_SECONDS_MIN, CAP_SECONDS_MAX = 14400, 60, 14400
MAX_STATUS_IDS = 200
LOCK_SECONDS = 5
LOCK_TRIES = 40
LOCK_WAIT_SECONDS = 0.05

# The relay (see probe_tunnel_consumer). Core reads byte 0 and the length only.
FRAME_TYPES = (1, 2, 3, 4)  # OPEN, DATA, ACK, CLOSE
TYPE_DATA = 2
HEADER_LEN = 5
MAX_DATA = 32 * 1024
MAX_FRAME = HEADER_LEN + MAX_DATA
STREAM_WINDOW = 128 * 1024
MAX_STREAMS = 8
SESSION_IN_FLIGHT = 1024 * 1024
BUFFER_CAP_BYTES = 1024 * 1024  # Console frames held before the probe side is attached
PAIR_WAIT_SECONDS = 15  # no probe side this long after the Console connected: probe_offline
WATCH_TICK_SECONDS = 5
FLUSH_SECONDS = 5
RECHECK_SECONDS = 300
RECHECK_JITTER_SECONDS = 30
RECHECK_RETRY_SECONDS = 30
RECHECK_GRACE_SECONDS = 300
SEND_TIMEOUT_SECONDS = 5.0
FRAMES_PER_SECOND_MAX = 2000  # 1.18.49: control frames (OPEN, ACK, CLOSE) one tunnel socket may send in a one-second window; the next ends the session protocol_error
DATA_FRAMES_PER_SECOND_MAX = 10000  # 1.18.50: DATA frames in the same window, counted apart so a fast copy is not ended by its own ACKs (100 Mbit/s of 1.5 KB frames)
RATE_CONTROL, RATE_DATA = "rate_control", "rate_data"  # the end row's detail says which bound a protocol_error was
BACKSTOP_IDLE_GRACE_SECONDS = 30  # 1.18.49: the probe socket's own idle timer is the Console's idle limit plus this

CLOSE_PROTOCOL = 1002
CLOSE_GOING_AWAY = 1001
CLOSE_NOT_FOUND = 4404

# The fixed list of section 2.1. protocol_error is added for the websocket close text of a frame that breaks the rules (plan correction).
END_REASONS = (
    "ended_by_engineer", "ended_by_admin", "ended_by_core", "idle_timeout", "hard_cap", "target_out_of_scope", "target_blocked_address",
    "target_own_address", "connect_failed", "probe_offline", "console_disconnected", "console_not_connected", "relay_overloaded", "server_restart",
)
CORE_ONLY_REASONS = ("protocol_error",)
ALL_REASONS = END_REASONS + CORE_ONLY_REASONS
ENDED_BY_VALUES = ("engineer", "admin", "core")
ENDED_BY_REASON = {"engineer": "ended_by_engineer", "admin": "ended_by_admin", "core": "ended_by_core"}
PROBE_END_REASONS = ("ended_by_core", "probe_offline", "server_restart")
REFUSAL_OUTCOMES = ("denied", "invalid", "rate_limited", "limit_reached", "probe_offline", "session_exists", "unavailable")

REFUSAL_MESSAGES = {
    "authenticated_request_required": "This operation needs a signed-in Tec-Tac request.",
    "tactical_session_required": "Sign in again so Core can link this session to Tactical.",
    "module_id_mismatch": "module_id must be the verified caller",
    "invalid_spec": "the spec is not valid",
    "permission_missing": "the person does not hold that permission",
    "probe_offline": "the probe is not connected",
    "rate_limited": "too many tickets this minute",
    "sessions_total": "the server holds the most tunnel sessions it may",
    "sessions_per_probe": "this probe already holds the most tunnel sessions it may",
    "sessions_per_engineer": "this person already holds the most tunnel sessions they may",
    "session_exists": "a ticket was already issued for this session id",
    "out_of_scope": "the person has no access to the probe's site",
    "unavailable": "Core cannot issue a tunnel ticket right now; nothing was started",
    "bad_host": "the request host cannot be used in a launch link",
}


class _Refuse(Exception):
    def __init__(self, outcome: str, code: str):
        super().__init__(code)
        self.outcome, self.code = outcome, code


class IndexUnavailable(Exception):
    """The shared cache cannot hold the session index: fail closed."""


# ------------------------------------------------------------------------------------------------ keys
def _cache():
    return pt._cache()


def _hash(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def ticket_key(ticket: str) -> str:
    """Only the SHA-256 of a ticket reaches the cache."""
    return TICKET_PREFIX + _hash(ticket)


def session_key(session_id: str) -> str:
    return SESSION_PREFIX + session_id


def side_key(session_id: str, side: str) -> str:
    return f"{SIDE_PREFIX}{session_id}:{side}"


def end_key(session_id: str) -> str:
    return END_PREFIX + session_id


def stats_key(session_id: str) -> str:
    return STATS_PREFIX + session_id


def closed_key(session_id: str) -> str:
    return CLOSED_PREFIX + session_id


def audited_key(session_id: str) -> str:
    return AUDITED_PREFIX + session_id


def tunnel_group(session_id: str) -> str:
    return GROUP_PREFIX + session_id


def _keep_seconds() -> int:
    return CAP_SECONDS_MAX + ENDED_KEEP_SECONDS


# ------------------------------------------------------------------------------------------------ headers
def parse_ticket_headers(scope) -> tuple[str | None, str | None]:
    """(ticket, reason). Exactly one Authorization header of the form 'Ticket <43 characters>'. A 'Probe ...' or 'Token ...' header gives
    wrong_scheme. A missing, duplicated, over-long or non-ASCII header, or a ticket of the wrong shape, gives malformed_header. Nothing
    here logs or returns the ticket on a refusal."""
    values = pt._scope_headers(scope).get(b"authorization") or []
    if len(values) != 1 or len(values[0]) > 200:
        return None, "malformed_header"
    try:
        text = values[0].decode("ascii")
    except UnicodeDecodeError:
        return None, "malformed_header"
    scheme, space, rest = text.partition(" ")
    if not space:
        return None, "malformed_header"
    if scheme.lower() != "ticket":
        return None, "wrong_scheme"
    if not TICKET_PATTERN.fullmatch(rest):
        return None, "malformed_header"
    return rest, None


def parse_session_header(scope) -> str | None:
    """The uuid in exactly one X-Tunnel-Session header, or None."""
    values = pt._scope_headers(scope).get(SESSION_HEADER) or []
    if len(values) != 1 or len(values[0]) > 64:
        return None
    try:
        return _clean_session_id(values[0].decode("ascii"))
    except UnicodeDecodeError:
        return None


def _clean_session_id(value) -> str | None:
    if not isinstance(value, str) or len(value) != 36:
        return None
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return value if parsed.version == 4 and str(parsed) == value else None


def check_frame(data) -> bool:
    """True when the binary message is a well-formed tunnel frame by Core's only two rules: byte 0 is a type from 1 to 4 and the length
    is 5 up to HEADER_LEN + 32 KiB. The stream id, the window and the payload are never read."""
    if not isinstance(data, (bytes, bytearray)):
        return False
    return HEADER_LEN <= len(data) <= MAX_FRAME and data[0] in FRAME_TYPES


# ------------------------------------------------------------------------------------------------ the session index (limits)
def _with_index(mutate):
    """Run mutate(index, now) under a short cache lock, then write the index back and read it back. The index is one cache entry
    {session_id: {probe_id, user_id, expires}}; an entry past its expiry is dropped, so a leaked slot heals. No shared cache (a dummy
    cache holds nothing) is IndexUnavailable: fail closed."""
    cache = _cache()
    token = secrets.token_hex(8)
    for _ in range(LOCK_TRIES):
        if cache.add(LOCK_KEY, token, LOCK_SECONDS):
            break
        time.sleep(LOCK_WAIT_SECONDS)
    else:
        raise IndexUnavailable("lock")
    try:
        index = cache.get(INDEX_KEY)
        if not isinstance(index, dict):
            index = {}
        now = time.time()
        index = {k: v for k, v in index.items() if isinstance(v, dict) and float(v.get("expires", 0) or 0) > now}
        result = mutate(index, now)
        cache.set(INDEX_KEY, index, _keep_seconds())
        if cache.get(INDEX_KEY) != index:
            raise IndexUnavailable("readback")
        return result
    finally:
        try:
            if cache.get(LOCK_KEY) == token:
                cache.delete(LOCK_KEY)
        except Exception:
            logger.warning("The tunnel index lock could not be released.", exc_info=True)


def read_index() -> dict:
    """The live entries, read without the lock (status and end-for-probe). Cache only."""
    index = _cache().get(INDEX_KEY)
    if not isinstance(index, dict):
        return {}
    now = time.time()
    return {k: v for k, v in index.items() if isinstance(v, dict) and float(v.get("expires", 0) or 0) > now}


def _release_slot(session_id: str) -> None:
    def mutate(index, now):
        index.pop(session_id, None)

    try:
        _with_index(mutate)
    except Exception:
        logger.warning("A tunnel slot could not be released; it heals at its expiry.", exc_info=True)


def extend_slot(session_id: str, seconds: float) -> None:
    def mutate(index, now):
        if session_id in index:
            index[session_id] = {**index[session_id], "expires": now + seconds}

    try:
        _with_index(mutate)
    except Exception:
        logger.warning("A tunnel slot could not be extended.", exc_info=True)


# ------------------------------------------------------------------------------------------------ spec and refusals
def _clean_spec(spec):
    """A cleaned dict, or None when the spec is not valid."""
    if not isinstance(spec, dict) or set(spec) - {"session_id", "probe_id", "permission", "target_label", "idle_s", "cap_s", "site_id"}:
        return None
    session_id = _clean_session_id(spec.get("session_id"))
    probe_id = spec.get("probe_id")
    permission = spec.get("permission")
    if session_id is None or not isinstance(probe_id, str) or not pt.PROBE_ID_PATTERN.fullmatch(probe_id):
        return None
    if not isinstance(permission, str) or not PERMISSION_PATTERN.fullmatch(permission):
        return None
    site_id = spec.get("site_id")  # 1.18.50: optional; absent means no scope check by Core (see scope_refusal)
    if site_id is not None and (isinstance(site_id, bool) or not isinstance(site_id, int) or site_id <= 0):
        return None
    numbers = {}
    for name, default, low, high in (("idle_s", IDLE_SECONDS_DEFAULT, IDLE_SECONDS_MIN, IDLE_SECONDS_MAX),
                                     ("cap_s", CAP_SECONDS_DEFAULT, CAP_SECONDS_MIN, CAP_SECONDS_MAX)):
        value = spec.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            return None
        numbers[name] = value
    return {"session_id": session_id, "probe_id": probe_id, "permission": permission, "target_label": pt.clean_label(spec.get("target_label")), "site_id": site_id, **numbers}


def _audit(action: str, probe_id=None, **kwargs) -> None:
    pt.record_probe_event(action, probe_id, **kwargs)


def _refusal(outcome: str, code: str, *, user=None, probe_id=None, session_id=None) -> dict:
    """The answer of a refusal, with its one deny audit row. Never holds a ticket or a key."""
    extra = {"session_id": session_id} if session_id else {}
    pk = getattr(user, "pk", None)
    if isinstance(pk, int) and not isinstance(pk, bool):
        extra["engineer"] = pk
    _audit("custom:probe-tunnel-refused", probe_id, reason=code, refusal=True, extra=extra)
    return {"outcome": outcome, "code": code, "message": REFUSAL_MESSAGES.get(code, code)}


def _launch_url(request, ticket: str) -> str | None:
    try:
        host = str(request.get_host()).strip().lower()
    except Exception:
        logger.debug("A call failed and was handled (see the caller).", exc_info=True)
        return None
    host = host.removesuffix(":443")
    if not HOST_PATTERN.fullmatch(host):
        return None
    return f"{LAUNCH_SCHEME}://open?host={quote(host, safe='')}&ticket={quote(ticket, safe='')}"


# ------------------------------------------------------------------------------------------------ the person's scope (1.18.50)
def scope_refusal(user_id, site_id) -> str | None:
    """Why the person may no longer reach the probe's site, or None. Sync (database). No site id (an owner that predates 1.2.0) means no
    check. The person is read fresh and asked the same question the owner asks at open: may this person see this site (Tactical's client and
    site scope and can_list_sites, through tec_tac.resources.get_site). Not found or not permitted is scope_lost. Any other fault is
    check_failed: the caller treats it as a refusal (fail closed) and the re-check retries."""
    if site_id is None:
        return None
    try:
        from django.contrib.auth import get_user_model

        from . import resources

        user = get_user_model().objects.filter(pk=user_id).first()
        if user is None:
            return "scope_lost"
        try:
            resources.get_site(site_id, context=resources.user_context(user))
        except (resources.ResourceNotFound, resources.ResourcePermissionDenied):
            return "scope_lost"
    except Exception:
        logger.warning("The tunnel scope check failed; refusing.", exc_info=True)
        return "check_failed"
    return None


def access_changed_at(user_id):
    """The time of the newest access change for one person (core.access_events), or None. Cache only; any fault is None."""
    try:
        from . import access_events

        return access_events.changed_at(user_id)
    except Exception:
        logger.debug("The access marker could not be read.", exc_info=True)
        return None


def update_site(module_id: str, probe_id: str, site_id: int) -> list[str]:
    """The owner moved a probe to another site (set_tunnel_site): for every live session of that probe that the module opened, write the new
    site into the session record and mark the opener's access marker, so each Console re-checks within one 5-second tick. Returns the ids
    changed. An ended session is skipped."""
    from . import access_events

    updated = []
    for session_id, entry in read_index().items():
        if entry.get("probe_id") != probe_id:
            continue
        record = get_record(session_id)
        if record is None or record.get("module_id") != module_id or get_end(session_id):
            continue
        _cache().set(session_key(session_id), {**record, "site_id": site_id}, _keep_seconds())
        if isinstance(record.get("user_id"), int):
            access_events.mark_changed([record["user_id"]])
        updated.append(session_id)
    return updated


# ------------------------------------------------------------------------------------------------ issue
def issue_ticket(request, caller: str, spec) -> dict:
    """The body of issue_tunnel_ticket after the caller was verified. Order: the signed-in request, the spec, the permission, the probe's
    presence, the ticket rate, then the slots under one lock. One deny row for every refusal. Sync (cache and database)."""
    from . import session_security
    from .rbac import has_extension_permission

    user = getattr(request, "user", None)
    session = getattr(request, "tec_tac_session", None)
    if user is None or not getattr(user, "is_authenticated", False) or session is None:
        return _refusal("denied", "authenticated_request_required")
    clean = _clean_spec(spec)
    if clean is None:
        return _refusal("invalid", "invalid_spec", user=user)
    sid, probe_id = clean["session_id"], clean["probe_id"]
    try:
        digest = session_security.request_knox_digest(request)
    except Exception:
        logger.warning("The Knox digest could not be read for a tunnel ticket.", exc_info=True)
        digest = ""
    if not digest:
        return _refusal("denied", "tactical_session_required", user=user, probe_id=probe_id, session_id=sid)
    try:
        allowed = bool(has_extension_permission(user, clean["permission"]))
    except ValueError:
        return _refusal("invalid", "invalid_spec", user=user, probe_id=probe_id, session_id=sid)
    except Exception:
        logger.warning("The tunnel permission could not be read; refusing.", exc_info=True)
        return _refusal("unavailable", "unavailable", user=user, probe_id=probe_id, session_id=sid)
    if not allowed:
        return _refusal("denied", "permission_missing", user=user, probe_id=probe_id, session_id=sid)
    scope = scope_refusal(user.pk, clean["site_id"])
    if scope == "scope_lost":
        return _refusal("denied", "out_of_scope", user=user, probe_id=probe_id, session_id=sid)
    if scope:
        return _refusal("unavailable", "unavailable", user=user, probe_id=probe_id, session_id=sid)
    try:
        online = pt._connected(probe_id)
    except Exception:
        logger.warning("The probe presence could not be read for a tunnel ticket.", exc_info=True)
        return _refusal("unavailable", "unavailable", user=user, probe_id=probe_id, session_id=sid)
    if not online:
        return _refusal("probe_offline", "probe_offline", user=user, probe_id=probe_id, session_id=sid)
    try:
        if pt._bump(f"{TICKET_RATE_PREFIX}{user.pk}:{pt._minute()}") > TICKETS_PER_MINUTE:
            return _refusal("rate_limited", "rate_limited", user=user, probe_id=probe_id, session_id=sid)
    except Exception:
        logger.warning("The tunnel ticket counter could not be written; refusing.", exc_info=True)
        return _refusal("unavailable", "unavailable", user=user, probe_id=probe_id, session_id=sid)

    ticket = secrets.token_urlsafe(32)
    launch = _launch_url(request, ticket)
    if launch is None:
        return _refusal("unavailable", "bad_host", user=user, probe_id=probe_id, session_id=sid)
    now = time.time()
    record = {
        "session_id": sid, "probe_id": probe_id, "user_id": user.pk, "module_id": caller, "permission": clean["permission"],
        "idle_s": clean["idle_s"], "cap_s": clean["cap_s"], "target": clean["target_label"], "created": now, "site_id": clean["site_id"],
    }
    value = {
        "user_id": user.pk, "trust_id": str(getattr(session, "id", "")), "knox_digest": digest, "session_id": sid, "probe_id": probe_id,
        "module_id": caller, "permission": clean["permission"], "idle_s": clean["idle_s"], "cap_s": clean["cap_s"], "expires_at": now + TICKET_TTL_SECONDS,
    }

    def mutate(index, at):
        if sid in index or _cache().get(session_key(sid)) is not None:
            raise _Refuse("session_exists", "session_exists")
        if len(index) >= MAX_SESSIONS:
            raise _Refuse("limit_reached", "sessions_total")
        if sum(1 for v in index.values() if v.get("probe_id") == probe_id) >= MAX_SESSIONS_PER_PROBE:
            raise _Refuse("limit_reached", "sessions_per_probe")
        if sum(1 for v in index.values() if v.get("user_id") == user.pk) >= MAX_SESSIONS_PER_ENGINEER:
            raise _Refuse("limit_reached", "sessions_per_engineer")
        cache = _cache()
        key = ticket_key(ticket)
        if not cache.add(session_key(sid), record, _keep_seconds()) or cache.get(session_key(sid)) != record:
            raise IndexUnavailable("record")
        if not cache.add(key, value, TICKET_TTL_SECONDS) or cache.get(key) != value:
            for stale in (session_key(sid), key):
                cache.delete(stale)
            raise IndexUnavailable("ticket")
        index[sid] = {"probe_id": probe_id, "user_id": user.pk, "expires": at + PENDING_SLOT_SECONDS}

    try:
        _with_index(mutate)
    except _Refuse as refusal:
        return _refusal(refusal.outcome, refusal.code, user=user, probe_id=probe_id, session_id=sid)
    except Exception:
        logger.warning("The tunnel session index is unavailable; no ticket issued.", exc_info=True)
        return _refusal("unavailable", "unavailable", user=user, probe_id=probe_id, session_id=sid)
    _audit("custom:probe-tunnel-ticket", probe_id, extra={"engineer": user.pk, "session_id": sid, "permission": clean["permission"]})
    return {"outcome": "ok", "ticket": ticket, "launch_url": launch, "expires_in": TICKET_TTL_SECONDS, "session_id": sid}


# ------------------------------------------------------------------------------------------------ redeem and sides
def redeem_ticket(ticket) -> dict | None:
    """Take a ticket out of the store, once. None for a malformed, unknown, used or expired ticket. cache.delete returns True for exactly
    one caller, so two sockets that read the same ticket cannot both use it. A cache error is raised (the consumer answers 1013)."""
    if not isinstance(ticket, str) or not TICKET_PATTERN.fullmatch(ticket):
        return None
    key = ticket_key(ticket)
    cache = _cache()
    value = cache.get(key)
    if not isinstance(value, dict):
        return None
    if not cache.delete(key):
        return None
    if float(value.get("expires_at", 0) or 0) <= time.time():
        return None
    return value


def get_record(session_id: str) -> dict | None:
    record = _cache().get(session_key(session_id))
    return record if isinstance(record, dict) else None


def get_end(session_id: str) -> dict | None:
    marker = _cache().get(end_key(session_id))
    return marker if isinstance(marker, dict) else None


def side_attached(session_id: str, side: str) -> bool:
    return _cache().get(side_key(session_id, side)) is not None


def _attach(session_id: str, side: str) -> bool:
    return bool(_cache().add(side_key(session_id, side), {"at": time.time()}, _keep_seconds()))


def account_refusal(value: dict, permission: str, activity_at=None) -> str | None:
    """Why the person behind a ticket may no longer tunnel, or None. Checks the sign-in (the user is active and not blocked, the Knox token
    is live, the Tec-Tac session is not revoked, idle or past its absolute lifetime: session_security.record_terminal_activity with the
    last DATA time as activity), the permission, and that the owning module is still installed and enabled. Sync; any error is a refusal."""
    from django.contrib.auth import get_user_model

    from .rbac import has_extension_permission
    from .tactical_websocket import session_refusal

    try:
        reason = session_refusal({"user_id": value["user_id"], "trust_id": value["trust_id"], "knox_digest": value["knox_digest"]}, activity_at)
        if reason:
            return reason
        user = get_user_model().objects.filter(pk=value["user_id"]).first()
        if user is None or not has_extension_permission(user, permission):
            return "permission_missing"
        if pt._owner_folder(pt.OWNER_MODULE) is None:
            return "module_disabled"
    except Exception:
        logger.warning("The tunnel account check failed; refusing.", exc_info=True)
        return "check_failed"
    return None


def console_open(ticket: str):
    """The whole Console connect decision, sync (the auth pool). Returns (status, value, record, reason): status is ok, ticket (4401:
    unknown, used or expired), unauthorized (4401: account, permission or module; reason says which), not_pending (4404) or attached
    (4409). A cache fault is raised."""
    value = redeem_ticket(ticket)
    if value is None:
        return "ticket", None, None, "ticket_invalid"
    refusal = account_refusal(value, value["permission"])
    if refusal:
        return "unauthorized", value, None, refusal
    record = get_record(value["session_id"])
    if record is None or record.get("probe_id") != value.get("probe_id") or record.get("user_id") != value.get("user_id") or get_end(value["session_id"]):
        return "not_pending", value, None, "session_not_pending"
    scope = scope_refusal(value["user_id"], record.get("site_id"))  # 1.18.50: the site the owner named; the person may have lost it since the ticket
    if scope:
        return "unauthorized", value, None, scope
    if not _attach(value["session_id"], "console"):
        return "attached", value, record, "console_already_attached"
    extend_slot(value["session_id"], record["cap_s"] + SLOT_GRACE_SECONDS)
    return "ok", value, record, ""


def console_recheck(value: dict, record: dict, activity_at=None) -> str | None:
    """The Console's 5-minute re-check, sync (the recheck pool): the account and permission and module (account_refusal, with the last
    DATA time as activity), then the person's access to the session's site (scope_refusal, from the live record, 1.18.50), then that the
    probe still has presence or a data socket. Returns the reason it fails, or None. Also run at once when the person's access marker moves."""
    reason = account_refusal(value, record["permission"], activity_at)
    if reason:
        return reason
    live = get_record(record["session_id"]) or record  # the live record: the owner may have moved the probe to another site since connect
    reason = scope_refusal(value["user_id"], live.get("site_id"))
    if reason:
        return reason
    try:
        if not side_attached(record["session_id"], "probe") and not pt._connected(record["probe_id"]):
            return "probe_offline"
    except Exception:
        logger.warning("The probe presence could not be read for a tunnel re-check.", exc_info=True)
        return "check_failed"
    return None


def mark_probe_ready(session_id: str, channel: str | None = None) -> None:
    """Sync (the cache pool). The probe's socket calls this after it has joined the session's group, before it sends tunnel.paired. The
    Console pairs only once this marker exists, so the first frames it sends always have a probe in the group to reach (1.18.48). From
    1.18.49 the marker carries the socket's own channel name: frames go to that channel with send(), not to the group."""
    _write_ready(session_id, SIDE_PROBE_READY, channel)


def mark_console_ready(session_id: str, channel: str | None = None) -> None:
    """Sync (the cache pool). The Console's socket, after it has joined the group and before it sends tunnel.paired (1.18.49)."""
    _write_ready(session_id, SIDE_CONSOLE_READY, channel)


def _write_ready(session_id: str, side: str, channel) -> None:
    marker = {"at": time.time()}
    if isinstance(channel, str) and CHANNEL_PATTERN.match(channel):
        marker["channel"] = channel
    _cache().set(side_key(session_id, side), marker, _keep_seconds())


def clean_channel(value) -> str | None:
    """A channel name that passes the strict pattern, or None."""
    return value if isinstance(value, str) and CHANNEL_PATTERN.match(value) else None


def ready_channel(session_id: str, side: str) -> str | None:
    """Sync (the cache pool). The channel name a side published in its ready marker, or None (no marker, no name, or a malformed name)."""
    marker = _cache().get(side_key(session_id, side))
    return clean_channel(marker.get("channel")) if isinstance(marker, dict) else None


def probe_open(probe_id: str, session_id: str):
    """The probe data side's session decision, sync (the cache pool). Returns (status, record): ok, not_pending (4404) or attached (4409)."""
    record = get_record(session_id)
    if record is None or record.get("probe_id") != probe_id or get_end(session_id):
        return "not_pending", None
    if not _attach(session_id, "probe"):
        return "attached", record
    return "ok", record


def poll_session(session_id: str) -> dict:
    """What a watcher asks every few seconds: {ended: marker or None, console: bool, probe: bool, ready: bool}. Cache only. probe is the
    attach marker (the 4409 guard); ready means the probe's socket is in the group (1.18.48). console_channel is the Console's channel name
    from its ready marker, or None (1.18.49). console_at is the time the Console attached (the console side marker), or None (1.18.50:
    the probe socket's hard-cap backstop counts from it)."""
    console = _cache().get(side_key(session_id, "console"))
    return {"ended": get_end(session_id), "console": console is not None, "probe": side_attached(session_id, "probe"),
            "ready": side_attached(session_id, SIDE_PROBE_READY), "console_channel": ready_channel(session_id, SIDE_CONSOLE_READY),
            "console_at": console.get("at") if isinstance(console, dict) else None}


def flush_stats(session_id: str, last_data: float, bytes_up: int, bytes_down: int) -> dict | None:
    """Write the Console's counters to the session's cache record and return the end marker when the session ended elsewhere."""
    _cache().set(stats_key(session_id), {"last_data": last_data, "bytes_up": int(bytes_up), "bytes_down": int(bytes_down)}, _keep_seconds())
    return get_end(session_id)


def read_stats(session_id: str) -> dict:
    stats = _cache().get(stats_key(session_id))
    if isinstance(stats, dict):
        return {"last_data": stats.get("last_data"), "bytes_up": int(stats.get("bytes_up") or 0), "bytes_down": int(stats.get("bytes_down") or 0)}
    return {"last_data": None, "bytes_up": 0, "bytes_down": 0}


# ------------------------------------------------------------------------------------------------ the end of a session
def claim_end(session_id: str, reason: str, ended_by: str, detail: str = ""):
    """Mark the session ended. cache.add decides: the first caller wins and writes the reason and who ended it once. Returns
    ('unknown', None), ('lost', marker) or ('won', marker). The winner also frees the slot."""
    if reason not in ALL_REASONS or ended_by not in ENDED_BY_VALUES:
        raise ValueError("reason or ended_by is not on the fixed list")
    if get_record(session_id) is None:
        return "unknown", None
    marker = {"reason": reason, "ended_by": ended_by, "detail": pt.clean_label(detail, 64), "at": time.time()}
    if _cache().add(end_key(session_id), marker, _keep_seconds()):
        _release_slot(session_id)
        return "won", marker
    return "lost", get_end(session_id) or marker


def end_audit(session_id: str, marker: dict, counters: dict | None = None) -> bool:
    """The one custom:probe-tunnel-end row (sync, a database write): session id, probe id, engineer, reason, ended_by, duration, bytes.
    The Console consumer writes it at its close with its final counters; a session whose Console never attached is written by whoever
    ended it, with zero counters. cache.add decides, so a session never has two. Returns True when this call wrote the row."""
    if not _cache().add(audited_key(session_id), 1, _keep_seconds()):
        return False
    record = get_record(session_id) or {}
    stats = counters if counters is not None else read_stats(session_id)
    console = _cache().get(side_key(session_id, "console"))
    started = console.get("at") if isinstance(console, dict) else None
    duration = max(0, int(float(marker.get("at") or time.time()) - float(started))) if started else 0
    extra = {"session_id": session_id, "ended_by": marker["ended_by"], "duration": duration, "bytes_up": int(stats["bytes_up"]), "bytes_down": int(stats["bytes_down"])}
    if isinstance(record.get("user_id"), int):
        extra["engineer"] = record["user_id"]
    if marker.get("detail"):
        extra["detail"] = marker["detail"]
    _audit("custom:probe-tunnel-end", record.get("probe_id"), reason=marker["reason"], extra=extra)
    return True


def send_probe_close(probe_id: str, session_id: str, marker: dict) -> str:
    """Tell the probe on its control channel to drop its target connection (tunnel.close), even when the data socket is slow. ok or
    offline. Sync."""
    frame = {"v": 1, "type": "event", "id": f"core-tc-{session_id}", "func": "tunnel.close",
             "payload": {"session_id": session_id, "reason": marker["reason"], "ended_by": marker["ended_by"]}}
    return pt._group_send(probe_id, {"type": "probe.push", "frame": frame})


def group_end_sync(session_id: str, marker: dict) -> bool:
    """Send the end message to the session's group so both data sockets close at once. Sync (async_to_sync). False on a fault."""
    try:
        layer = pt._channel_layer()
    except Exception:
        logger.debug("A call failed and was handled (see the caller).", exc_info=True)
        layer = None
    if layer is None:
        return False
    from asgiref.sync import async_to_sync

    async def go():
        import asyncio

        await asyncio.wait_for(layer.group_send(tunnel_group(session_id), end_message(marker)), timeout=SEND_TIMEOUT_SECONDS)

    try:
        async_to_sync(go)()
    except Exception:
        logger.warning("The tunnel end message could not be sent.", exc_info=True)
        return False
    return True


def end_message(marker: dict) -> dict:
    return {"type": "tunnel.end", "reason": marker["reason"], "ended_by": marker["ended_by"]}


def deliver_closed(session_id: str, probe_id: str, marker: dict, bytes_up: int, bytes_down: int) -> str:
    """Exactly one tunnel.closed event per session to the owner's event task as (probe_id, frame): the first caller claims it. Returns
    ok, failed, no_owner or duplicate. Sync and blocking (a broker call): consumers run it on the handover pool under a timeout."""
    if not _cache().add(closed_key(session_id), 1, _keep_seconds()):
        return "duplicate"
    frame = {"v": 1, "type": "event", "id": f"core-tclosed-{session_id}", "func": "tunnel.closed",
             "payload": {"session_id": session_id, "reason": marker["reason"], "ended_by": marker["ended_by"], "bytes_up": int(bytes_up),
                         "bytes_down": int(bytes_down), "source": "core"}}
    return pt.enqueue_event(probe_id, frame)


def end_session(session_id: str, reason: str, ended_by: str, detail: str = "") -> dict:
    """End one session from a sync caller (the provider, or Core itself). The first end wins: the reason and ended_by are written once,
    the slot is freed, both data sockets are told, the probe is told on the control channel, one audit row is written and, when the
    Console side never attached, one tunnel.closed is delivered with zero counters. A second end changes nothing."""
    status, marker = claim_end(session_id, reason, ended_by, detail)
    if status == "unknown":
        return {"outcome": "invalid", "session_id": session_id}
    record = get_record(session_id) or {}
    if status == "lost":
        return {"outcome": "ok", "session_id": session_id, "already_ended": True, "reason": marker["reason"], "ended_by": marker["ended_by"]}
    for step in (lambda: send_probe_close(record["probe_id"], session_id, marker), lambda: group_end_sync(session_id, marker)):
        try:
            step()
        except Exception:
            logger.warning("A step of ending a tunnel session failed.", exc_info=True)
    try:
        if not side_attached(session_id, "console"):  # the Console consumer reports an attached session at its close, with its final counters
            end_audit(session_id, marker, {"bytes_up": 0, "bytes_down": 0})
            deliver_closed(session_id, record["probe_id"], marker, 0, 0)
    except Exception:
        logger.warning("The tunnel end row or the tunnel.closed event could not be written.", exc_info=True)
    return {"outcome": "ok", "session_id": session_id, "already_ended": False, "reason": marker["reason"], "ended_by": marker["ended_by"]}


def end_for_probe(probe_id: str, reason: str, ended_by: str = "core", detail: str = "") -> list[str]:
    """End every live session of one probe (and only that probe). Returns the ids that this call ended."""
    ended = []
    for session_id, entry in read_index().items():
        if entry.get("probe_id") != probe_id:
            continue
        result = end_session(session_id, reason, ended_by, detail)
        if result.get("outcome") == "ok" and not result.get("already_ended"):
            ended.append(session_id)
    return ended


# ------------------------------------------------------------------------------------------------ status
def status_rows(session_ids) -> dict:
    """Per session {state, probe_id, site_id, started, last_data, console_connected, probe_connected, bytes_up, bytes_down, reason, ended_by}. Cache
    only. A session with no record is unknown."""
    rows = {}
    cache = _cache()
    for session_id in session_ids:
        record = get_record(session_id)
        if record is None:
            rows[session_id] = {"state": "unknown", "probe_id": None, "site_id": None, "started": None, "last_data": None, "console_connected": False,
                                "probe_connected": False, "bytes_up": 0, "bytes_down": 0, "reason": None, "ended_by": None}
            continue
        marker = get_end(session_id)
        console = cache.get(side_key(session_id, "console"))
        stats = read_stats(session_id)
        state = "ended" if marker else ("open" if console is not None else "pending")
        rows[session_id] = {
            "state": state, "probe_id": record.get("probe_id"), "site_id": record.get("site_id"), "started": console.get("at") if isinstance(console, dict) else None,
            "last_data": stats["last_data"], "console_connected": console is not None, "probe_connected": side_attached(session_id, "probe"),
            "bytes_up": stats["bytes_up"], "bytes_down": stats["bytes_down"], "reason": marker.get("reason") if marker else None,
            "ended_by": marker.get("ended_by") if marker else None,
        }
    return rows


# ------------------------------------------------------------------------------------------------ the routes
class _TunnelRoute:
    """The ASGI app of one tunnel route. Imports the consumer on the first connection, so a fault there closes the socket 4503 and never
    stops Tactical from starting (rule 1.15)."""

    def __init__(self, side: str):
        self.side = side

    async def __call__(self, scope, receive, send):
        try:
            from . import probe_tunnel_consumer as consumers

            app = (consumers.ProbeTunnelProbeConsumer if self.side == "probe" else consumers.ProbeTunnelConsoleConsumer).as_asgi()
        except Exception:
            logger.exception("The probe tunnel consumer could not be loaded; closing the socket.")
            await send({"type": "websocket.close", "code": pt.CLOSE_UNAVAILABLE})
            return
        await app(scope, receive, send)


def _install(pattern: str, side: str) -> bool:
    from django.urls import path
    from tacticalrmm import urls as tactical_urls

    routes = tactical_urls.ws_urlpatterns
    if pattern in {str(getattr(item, "pattern", "")) for item in routes}:
        return False
    routes.append(path(pattern, _TunnelRoute(side)))
    return True


def install_tunnel_probe_route() -> bool:
    """Append ws/tfd/network-probe/tunnel/ (the probe side) to Tactical's ws_urlpatterns, once. True when this call added it."""
    return _install(PROBE_SIDE_ROUTE_PATTERN, "probe")


def install_tunnel_console_route() -> bool:
    """Append ws/tfd/probe-tunnel/ (the Console side) to Tactical's ws_urlpatterns, once. True when this call added it."""
    return _install(CONSOLE_ROUTE_PATTERN, "console")

#!/usr/bin/env python3
"""1.17.28 regression: the private mail relay is withdrawn (AD-30 amendment, Johan, 14 October 2026).

Django-free. The real ``runtime_settings.py``, ``priority_mail.py``, ``module_failure_notices.py`` and ``caller_identity.py`` load against
stubs: Tactical's CoreSettings (smtp_host, email_is_configured, send_mail), a fake resolver, a rolling-back transaction and a recording
audit. Covered:

* GET no longer carries ``priority_mail_private_relay``. A PATCH that names it is the normal 400 for a superuser and for a manage-only
  role, never 200. A person with no right gets the old 403 and no row.
* ``refused_reason`` takes no ``allow_private`` and still refuses 10.x, 172.16.x, 192.168.x, 100.64.x, fc00::/7, loopback, metadata,
  link-local and the embedded IPv4 form of each. ``public_refusal`` is the one check and ``host_refusal`` is the same function.
* Core's own Priority 1 send refuses a mail server on 10.0.0.5 with the stored column True (the column is ignored), and the
  ``custom:priority-mail`` row carries exactly the six count and code keys.
* ``module_frame_on_stack`` is gone from ``caller_identity.py``.
* ``clear_retired_private_relay`` clears a stored True with exactly one strict audit row carrying only the boolean transition; a second
  call writes nothing; a failed audit write leaves the column True (rolled back); an absent row, a stored False and a database error
  write nothing and never raise. The scheduler tick calls it.
* Grep: no ``priority_mail_private_relay`` or "private relay" text in framwork/, docs/ or contracts, bar the files the release keeps
  (the model column, migration 0029, the retirement itself, docs/runtime-settings.md, and the release notes).
"""
from __future__ import annotations

import inspect
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
KEY = "priority_mail_private_relay"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


# ------------------------------------------------------------------------------------------------ stubs for Django and Tactical
class PermissionDenied(Exception):
    pass


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status


def passthrough(*a, **k):
    return lambda fn: fn


class Snapshot:
    """Rolls the stub row back when the block raises, as a database transaction does."""

    def __enter__(self):
        self._value = CONFIG.priority_mail_private_relay
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            CONFIG.priority_mail_private_relay = self._value
        return False


mod("django")
mod("django.db", transaction=SimpleNamespace(atomic=lambda: Snapshot()))
mod("drf_spectacular")
mod("drf_spectacular.utils", extend_schema=passthrough, extend_schema_view=passthrough)
mod("rest_framework")
mod("rest_framework.exceptions", PermissionDenied=PermissionDenied)
mod("rest_framework.response", Response=Response)
mod("rest_framework.views", APIView=type("APIView", (), {}))
mod("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)

RBAC = {"superuser": False, "manage": False}
mod("tec_tac.rbac",
    is_effective_superuser=lambda user: bool(getattr(user, "superuser", False)),
    can_manage_runtime_settings=lambda user: bool(getattr(user, "superuser", False) or getattr(user, "manage", False)))
mod("tec_tac.session_security", SessionAuthenticated=type("SessionAuthenticated", (), {}))
mod("tec_tac.throttles", RuntimeSettingsWriteMinThrottle=type("Min", (), {}), RuntimeSettingsWriteDayThrottle=type("Day", (), {}))

AUDITS: list = []
AUDIT_FAIL = {"on": False}


def record(**kwargs):
    if AUDIT_FAIL["on"]:
        raise RuntimeError("audit store down")
    AUDITS.append(kwargs)


mod("tec_tac.audit", record=record,
    service_audit_actor=lambda *, module_id, service, identity=None: SimpleNamespace(kind="service", module_id=module_id,
                                                                                     service=service, identity=identity))


class Config:
    saved: list = []

    def __init__(self):
        self.singleton = 1
        self.module_register_timeout_seconds = 30
        self.tactical_operation_upload_max_mib = 10
        self.system_name = "Tec-Tac"
        self.priority_mail_private_relay = False
        self.update_sources = {}
        self.updated_at = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
        self.updated_by = None

    def save(self, update_fields=None):
        Config.saved.append(tuple(update_fields or ()))


CONFIG = Config()
ROW = {"present": True}


class _Query:
    def filter(self, **kw):
        return self

    def first(self):
        return CONFIG if ROW["present"] else None

    def get(self, pk=None):
        return CONFIG


class TecTacRuntimeConfig:
    objects = SimpleNamespace(select_for_update=lambda: _Query())

    @classmethod
    def current(cls):
        return CONFIG


mod("tec_tac.models", TecTacRuntimeConfig=TecTacRuntimeConfig)

# the Tactical mail object Core is allowed to read, and nothing else
CORE = SimpleNamespace(smtp_host="relay.example", email_is_configured=True, sent=[])


class StrictCoreSettings:
    def __getattr__(self, name):
        if name in ("smtp_host", "email_is_configured", "send_mail"):
            return getattr(CORE, name)
        raise AssertionError(f"Core read a Tactical mail field it may not read: {name}")

    def send_mail(self, subject, body, override_recipients=(), test=False, **kw):
        CORE.sent.append(list(override_recipients))
        return ("ok", True)


mod("tacticalrmm")
mod("tacticalrmm.utils", get_core_settings=lambda: StrictCoreSettings())
mod("tec_tac.module_category", category_of=lambda *a, **k: "core")
mod("tec_tac.module_state", is_enabled=lambda module_id, state=None: True)
mod("tec_tac.registry", discover_plugins=lambda: ())

pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]

from tec_tac import caller_identity  # noqa: E402
from tec_tac import module_failure_notices as mfn  # noqa: E402
from tec_tac import priority_mail  # noqa: E402
from tec_tac import runtime_settings as rs  # noqa: E402

RESOLVE: dict = {}


def fake_resolve(name):
    if name not in RESOLVE:
        raise OSError("name does not resolve")
    return list(RESOLVE[name])


priority_mail.resolve_addresses = fake_resolve


def person(**rights):
    return SimpleNamespace(**{"username": "u", "superuser": False, "manage": False, **rights})


def patch(body, who):
    return rs.RuntimeSettingsView().patch(SimpleNamespace(user=who, data=body))


# ------------------------------------------------------------------------------------------------ (1) the setting is gone from the API
must(KEY not in rs.serialize_runtime_settings(CONFIG), "GET no longer carries the key")
must(KEY not in rs.RUNTIME_SETTING_NAMES and not hasattr(rs, "SETTING_PRIORITY_MAIL_PRIVATE_RELAY"), "no setting constant")
must(not hasattr(rs, "get_priority_mail_private_relay") and not hasattr(rs, "validate_priority_mail_private_relay"), "no reader or validator")
for who, label in ((person(superuser=True), "superuser"), (person(manage=True), "manage-only role")):
    AUDITS.clear()
    saves = len(Config.saved)
    for body in ({KEY: True}, {KEY: False}, {KEY: None}, {KEY: 1}, {KEY: True, rs.SETTING_MODULE_REGISTER_TIMEOUT: 45}):
        try:
            resp = patch(body, who)
        except PermissionDenied as exc:
            raise AssertionError((label, body, "a refusal must be 400 here, not 403", exc))
        must(resp.status_code == 400 and resp.data == {"detail": "Unknown runtime setting(s): " + KEY}, (label, body, resp.data))
    must(CONFIG.priority_mail_private_relay is False and CONFIG.module_register_timeout_seconds == 30, (label, "config unchanged"))
    must(AUDITS == [] and len(Config.saved) == saves, (label, "no row, no save"))
# a person with no right at all still gets the old message
try:
    patch({KEY: True}, person())
except PermissionDenied as exc:
    must(str(exc) == rs.RUNTIME_SETTINGS_DENIED, exc)
else:
    raise AssertionError("no right must be refused")
must(AUDITS == [], "no deny row for the key: it is not a setting any more")

# ------------------------------------------------------------------------------------------------ (2) one public-only rule
must("allow_private" not in inspect.signature(priority_mail.refused_reason).parameters, "refused_reason takes no allow_private")
must(inspect.signature(priority_mail.refused_reason).parameters.keys() == {"address"}, "refused_reason takes the address only")
must(priority_mail.host_refusal is priority_mail.public_refusal, "host_refusal is a plain alias of public_refusal")
for gone in ("host_check", "PRIVATE_NETWORKS", "_private_relay_on", "_judge_host"):
    must(not hasattr(priority_mail, gone), ("removed", gone))
try:
    priority_mail.refused_reason("10.0.0.5", allow_private=True)
except TypeError:
    pass
else:
    raise AssertionError("allow_private must not be accepted")

PRIVATE_AND_OTHER = [
    "10.0.0.5", "10.255.255.254", "172.16.0.9", "172.31.255.1", "192.168.1.20", "100.64.0.9", "100.127.255.254", "fc00::5", "fd12:3456::1",
    "127.0.0.1", "127.1.2.3", "::1", "169.254.10.10", "169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "0.0.0.0", "::",
    "224.0.0.1", "ff02::1", "fe80::1", "192.0.2.1", "198.18.0.1", "240.0.0.1",
]
EMBEDDED = [
    "::ffff:10.0.0.5", "::ffff:192.168.1.20", "::ffff:172.16.0.9", "::ffff:100.64.0.9", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
    "64:ff9b::a00:5", "64:ff9b::c0a8:114", "2002:0a00:0005::1", "2002:7f00:0001::1",
]
for address in PRIVATE_AND_OTHER + EMBEDDED:
    must(priority_mail.refused_reason(address) is not None, ("refused", address))
    RESOLVE["mail.example"] = [address]
    must(priority_mail.public_refusal("mail.example") == priority_mail.REFUSED, ("public_refusal", address))
    must(priority_mail.host_refusal("mail.example") == priority_mail.REFUSED, ("host_refusal", address))
for address in ("93.184.216.34", "172.32.0.1", "100.128.0.1", "2606:4700::1111"):
    RESOLVE["public.example"] = [address]
    must(priority_mail.public_refusal("public.example") is None, ("public passes", address))
RESOLVE["mixed.example"] = ["93.184.216.34", "10.1.1.1"]
must(priority_mail.public_refusal("mixed.example") == priority_mail.REFUSED, "one private address among public ones refuses the name")
must(priority_mail.public_refusal("") == priority_mail.REFUSED, "an empty name is refused")
must(priority_mail.public_refusal("missing.example") == priority_mail.REFUSED, "a name that does not resolve is refused")

# ------------------------------------------------------------------------------------------------ (3) Core's own send: column ignored
CONFIG.priority_mail_private_relay = True  # a stored True from 1.17.26 changes nothing now
RESOLVE["relay.example"] = ["10.0.0.5"]
ROWS: list = []
NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
ADMIN = SimpleNamespace(pk=1, email="root@example.test", is_superuser=True)
NOTICE = mfn.notice_for_job({"id": "00000000-0000-4000-8000-000000000001", "status": "failed", "action": "enable", "plugin_id": "patching",
                             "finished_at": NOW.isoformat(), "error": "failed", "requested_by": "alice"})
sent = mfn.send_p1_email(NOTICE, [ADMIN], configured=lambda: True, recent=lambda since: 0, audit=lambda j, md: ROWS.append(dict(md)),
                         have=lambda ids: set(), mark=lambda u, c: None, server="srv.example.test", now=NOW)
must(sent == 0 and CORE.sent == [], ("a private mail server is refused for Core's own send", CORE.sent))
must(len(ROWS) == 1 and ROWS[0]["code"] == "mail_host_refused" and ROWS[0]["outcome"] == "refused", ROWS)
must(set(ROWS[0]) == {"recipients", "sent", "refused", "outcome", "code", "requested_by"}, ("the row keys", set(ROWS[0])))
must("10.0.0.5" not in repr(ROWS) and "relay.example" not in repr(ROWS), "no address or host in the row")
RESOLVE["relay.example"] = ["93.184.216.34"]
ROWS.clear()
sent = mfn.send_p1_email(NOTICE, [ADMIN], configured=lambda: True, recent=lambda since: 0, audit=lambda j, md: ROWS.append(dict(md)),
                         have=lambda ids: set(), mark=lambda u, c: None, server="srv.example.test", now=NOW)
must(sent == 1 and CORE.sent == [["root@example.test"]] and set(ROWS[0]) == {"recipients", "sent", "refused", "outcome", "code", "requested_by"},
     ("a public server still sends", ROWS))
CONFIG.priority_mail_private_relay = False

# ------------------------------------------------------------------------------------------------ (4) the stack helper is gone
must(not hasattr(caller_identity, "module_frame_on_stack"), "module_frame_on_stack is removed")
must("module_frame_on_stack" not in (APP / "caller_identity.py").read_text(encoding="utf-8"), "no module_frame_on_stack in the source")

# ------------------------------------------------------------------------------------------------ (5) the clear
CONFIG.priority_mail_private_relay = True
AUDITS.clear()
must(rs.clear_retired_private_relay() is True, "a stored True is cleared")
must(CONFIG.priority_mail_private_relay is False, "the column is False")
must(len(AUDITS) == 1, ("exactly one audit row", AUDITS))
row = AUDITS[0]
must(row["module_id"] == "core" and row["action"] == "modify" and row["object_type"] == "runtime_settings", row)
must(row["object_id"] == KEY and row["strict"] is True, row)
must(row["before"] == {KEY: True} and row["after"] == {KEY: False}, row)
must(row["message"] == rs.RETIRED_PRIVATE_RELAY_MESSAGE and "retired" in row["message"], row)
must(row.get("metadata") is None and set(row) <= {"actor", "module_id", "action", "object_type", "object_id", "message", "before", "after",
                                                   "strict"}, ("no other value", sorted(row)))
must(len(Config.saved) >= 1 and "priority_mail_private_relay" in Config.saved[-1], Config.saved)
# a second call: the column is False, so nothing is written
AUDITS.clear()
saves = len(Config.saved)
must(rs.clear_retired_private_relay() is False and AUDITS == [] and len(Config.saved) == saves, "idempotent")
# a failed audit write leaves the column True, so the next tick retries
CONFIG.priority_mail_private_relay = True
AUDIT_FAIL["on"] = True
try:
    must(rs.clear_retired_private_relay() is False, "a failed audit write is not raised")
finally:
    AUDIT_FAIL["on"] = False
must(CONFIG.priority_mail_private_relay is True, "the failed write rolled the clear back")
AUDITS.clear()
must(rs.clear_retired_private_relay() is True and CONFIG.priority_mail_private_relay is False and len(AUDITS) == 1, "the retry clears it once")
# an absent row, a stored False and a database error write nothing and never raise
AUDITS.clear()
ROW["present"] = False
must(rs.clear_retired_private_relay() is False and AUDITS == [], "a missing row writes nothing")
ROW["present"] = True
CONFIG.priority_mail_private_relay = False
must(rs.clear_retired_private_relay() is False and AUDITS == [], "a stored False writes nothing")
original_first = _Query.first


def broken(self):
    raise RuntimeError("database unavailable")


_Query.first = broken
try:
    must(rs.clear_retired_private_relay() is False, "a database error never raises")
finally:
    _Query.first = original_first
# the scheduler tick calls it, and the call sits in the tick, not in a module
tick = (APP / "management" / "commands" / "tec_tac_scheduler_tick.py").read_text(encoding="utf-8")
must("clear_retired_private_relay()" in tick, "the scheduler tick calls the clear")

# ------------------------------------------------------------------------------------------------ (6) grep: no live reference
ALLOWED_COLUMN_FILES = {
    "framwork/tec_tac/models.py",
    "framwork/tec_tac/migrations/0029_priority_mail_private_relay.py",
    "framwork/tec_tac/migrations/0030_notice_ledger.py",  # names 0029 as its dependency, nothing else
    "framwork/tec_tac/runtime_settings.py",
    "docs/runtime-settings.md",
}
for path in sorted(list((ROOT / "framwork").rglob("*.py")) + list((ROOT / "docs").rglob("*.md"))):
    rel = path.relative_to(ROOT).as_posix()
    if rel.startswith("docs/releases/"):
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    lowered = text.lower()
    must("private relay" not in lowered, ("the phrase 'private relay' is gone", rel))
    if KEY in text:
        must(rel in ALLOWED_COLUMN_FILES, ("the column name is only in the kept files", rel))
contracts_text = (APP / "contracts.py").read_text(encoding="utf-8")
must(KEY not in contracts_text and "private relay" not in contracts_text.lower(), "contracts carry no relay text")

print("[TEST] PASS priority mail no private relay 1.17.28")

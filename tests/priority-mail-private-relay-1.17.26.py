#!/usr/bin/env python3
"""1.17.26 regression: the private mail relay setting for Core's own Priority 1 email (AD-30, Johan CQ80 and CQ81, 14 October 2026).

Django-free. Runs the real ``priority_mail.py``, ``module_failure_notices.py`` and ``caller_identity.py`` with Tactical's ``CoreSettings``
replaced by a strict fake (it answers only ``smtp_host``, ``email_is_configured`` and ``send_mail``), a fake resolver and a stub registry
over a temporary extensions folder. Covered:

* Setting off (the default): every private, loopback, link-local, metadata and carrier-grade name is refused, as in 1.17.25.
* Setting on and Core's own call: 10.x, 192.168.x, 172.16.x, 100.64.x and fc00:: names pass. Cloud metadata, loopback, link-local,
  unspecified, multicast, documentation and reserved ranges, an IPv4-mapped loopback and an unresolvable name stay refused. A name with
  one public and one bad address is judged address by address and refused. A public name passes with ``private_relay`` false.
* A module-folder frame on the stack, an injected host seam, an injected send seam, and a module calling ``host_refusal`` or
  ``host_check`` directly all get the public-only rule, with a warning logged, with the setting on.
* ``sweep_failed_jobs`` called from a module file gets public-only. The same call from Core's own frame gets the private path.
* The audit row carries ``private_relay``, true only when the relaxed rule accepted the name, and nothing else new (counts and codes only).
* The setting reader fails closed: an error, a missing runtime_settings and an odd stored value read as off.
* ``get_priority_mail_private_relay`` is not in the public Python contract text, and the sender still reads no other CoreSettings field.
* Docs name AD-30 (docs/resource-directory.md 'Move a site' cites AD-29).
"""
from __future__ import annotations

import logging
import sys
import tempfile
import types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


mod("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)

SECRET = "SMTP-PASSWORD-SENTINEL-1126"


class StrictCoreSettings:
    def __init__(self):
        self.smtp_host = "mail.example.test"
        self.email_is_configured = True
        self._secret = SECRET
        self.sent: list = []

    def __getattr__(self, name):
        raise AssertionError(f"Core read a Tactical mail field it may not read: {name}")

    def send_mail(self, subject, body, attachment=None, attachment_filename=None, attachment_type=None, attachment_extension=None,
                  alert_template=None, override_recipients=(), test=False):
        self.sent.append(list(override_recipients))
        return ("ok", True)


CORE = StrictCoreSettings()
mod("tacticalrmm")
mod("tacticalrmm.utils", get_core_settings=lambda: CORE)

AUDIT_CALLS: list = []
mod("tec_tac.audit", service_audit_actor=lambda *, module_id, service, identity=None: SimpleNamespace(kind="service"),
    record=lambda **kw: AUDIT_CALLS.append(kw))

# a stub registry over a temporary extensions folder: one enabled module (and a server-category one) whose folder holds real files
TMP = Path(tempfile.mkdtemp(prefix="tectac-relay-"))
EXT = TMP / "extensions"
PLUGINS = {}
for plugin_id in ("alerts", "userinvite"):
    root = EXT / plugin_id
    root.mkdir(parents=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type="extension", root=root, version="0.1.0", legacy=False)
REGISTRY_FAIL = {"on": False}


def discover_plugins():
    if REGISTRY_FAIL["on"]:
        raise RuntimeError("registry unreadable")
    return tuple(PLUGINS.values())


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
pkg.registry = mod("tec_tac.registry", discover_plugins=discover_plugins)
pkg.module_state = mod("tec_tac.module_state", is_enabled=lambda module_id, state=None: True)

RELAY = {"value": False, "raises": False}


def reader():
    if RELAY["raises"]:
        raise RuntimeError("database unavailable")
    return RELAY["value"]


RS = mod("tec_tac.runtime_settings", get_priority_mail_private_relay=reader)

from tec_tac import caller_identity  # noqa: E402
from tec_tac import module_failure_notices as mfn  # noqa: E402
from tec_tac import priority_mail  # noqa: E402

RESOLVE: dict = {}


def fake_resolve(name):
    if name not in RESOLVE:
        raise OSError("name does not resolve")
    return list(RESOLVE[name])


priority_mail.resolve_addresses = fake_resolve

LOGS: list = []


class Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(f"{record.levelname} " + record.getMessage())


logging.getLogger().addHandler(Capture(level=logging.DEBUG))
logging.getLogger().setLevel(logging.DEBUG)

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
ADMIN = SimpleNamespace(pk=1, email="root@example.test", is_superuser=True)
JOB = {"id": "00000000-0000-4000-8000-000000000001", "status": "failed", "action": "enable", "plugin_id": "patching",
       "finished_at": NOW.isoformat(), "error": "failed", "requested_by": "alice"}
NOTICE = mfn.notice_for_job(JOB)
MARKERS: set = set()
ROWS: list = []


def run_send(**seams):
    """send_p1_email from Core's own frame (this test file is outside every module folder)."""
    MARKERS.clear()
    ROWS.clear()
    CORE.sent.clear()
    base = dict(configured=lambda: True, recent=lambda since: 0, audit=lambda job_id, md: ROWS.append(dict(md)), have=lambda ids: set(),
                mark=lambda user, cid: MARKERS.add(cid), server="srv.example.test", now=NOW)
    base.update(seams)
    return mfn.send_p1_email(NOTICE, [ADMIN], **base)


def name(addresses):
    RESOLVE["relay.example"] = list(addresses)
    return "relay.example"


CORE.smtp_host = "relay.example"
PRIVATE_OK = ["10.0.0.5", "10.255.255.254", "192.168.1.20", "172.16.0.9", "172.31.255.1", "100.64.0.9", "100.127.255.254", "fc00::5",
              "fd12:3456::1", "::ffff:10.0.0.5"]
ALWAYS_REFUSED = ["127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1", "169.254.10.10", "169.254.169.254", "169.254.170.2", "100.100.100.200",
                  "fd00:ec2::254", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "fe80::1", "192.0.2.1", "198.18.0.1", "240.0.0.1"]
# just outside the private ranges these are ordinary public addresses, so they pass under either rule
JUST_OUTSIDE_PUBLIC = ["172.32.0.1", "100.128.0.1", "172.15.255.255", "100.63.255.255"]

# ------------------------------------------------------------------------------------------------ setting off: as 1.17.25
RELAY["value"] = False
for address in PRIVATE_OK + ALWAYS_REFUSED:
    must(priority_mail.host_check(name([address]), core_seams=True) == (priority_mail.REFUSED, False), ("off", address))
    must(priority_mail.host_refusal(name([address]), core_seams=True) == priority_mail.REFUSED, ("off", address))
    must(priority_mail.public_refusal(name([address])) == priority_mail.REFUSED, ("off", address))
RESOLVE["public.example"] = ["93.184.216.34"]
must(priority_mail.host_check("public.example", core_seams=True) == (None, False), "public passes with the setting off")
must(priority_mail.host_check("", core_seams=True)[0] == priority_mail.REFUSED, "an empty name")
for address in JUST_OUTSIDE_PUBLIC:
    must(priority_mail.host_check(name([address]), core_seams=True) == (None, False), ("public edge", address))

# ------------------------------------------------------------------------------------------------ setting on, Core's own call
RELAY["value"] = True
for address in PRIVATE_OK:
    must(priority_mail.host_check(name([address]), core_seams=True) == (None, True), ("on", address))
for address in ALWAYS_REFUSED:
    must(priority_mail.host_check(name([address]), core_seams=True) == (priority_mail.REFUSED, False), ("on still refuses", address))
must(priority_mail.host_check("public.example", core_seams=True) == (None, False), "a public name does not count as private_relay")
must(priority_mail.host_check("missing.example", core_seams=True)[0] == priority_mail.REFUSED, "an unresolvable name is refused")
RESOLVE["empty.example"] = []
must(priority_mail.host_check("empty.example", core_seams=True)[0] == priority_mail.REFUSED, "a name with no address is refused")
# hostile mixes are judged address by address
for mix in (["93.184.216.34", "10.1.1.1", "127.0.0.1"], ["10.1.1.1", "169.254.169.254"], ["192.168.0.2", "224.0.0.1"], ["10.0.0.1", "0.0.0.0"]):
    must(priority_mail.host_check(name(mix), core_seams=True) == (priority_mail.REFUSED, False), mix)
must(priority_mail.host_check(name(["93.184.216.34", "10.1.1.1"]), core_seams=True) == (None, True), "public plus private is fine when on")
must(priority_mail.refused_reason("10.0.0.5") == "not public" and priority_mail.refused_reason("10.0.0.5", allow_private=True) is None,
     "the relaxed rule is opt-in per call")

# ------------------------------------------------------------------------------------------------ not Core's own call: public only
for label, kwargs in (("no core seams", {}), ("explicit false", {"core_seams": False})):
    LOGS.clear()
    must(priority_mail.host_check(name(["10.0.0.5"]), **kwargs) == (priority_mail.REFUSED, False), label)
    must(any("not available to this caller" in line for line in LOGS), (label, "one warning is logged"))
must(priority_mail.host_refusal(name(["10.0.0.5"])) == priority_mail.REFUSED, "host_refusal without the flag is public-only")

# send_p1_email from Core's frame, defaults: the private path, and the audit row says so
name(["10.0.0.5"])
must(run_send() == 1 and CORE.sent == [["root@example.test"]], (CORE.sent, ROWS))
must(len(ROWS) == 1 and ROWS[0]["private_relay"] is True and ROWS[0]["outcome"] == "sent" and ROWS[0]["code"] == "none", ROWS)
must(set(ROWS[0]) == {"recipients", "sent", "refused", "outcome", "code", "requested_by", "private_relay"}, "no new field but private_relay")
must(all(isinstance(v, (int, str, bool)) for v in ROWS[0].values()), "counts, codes and a flag only")
must("10.0.0.5" not in repr(ROWS) and "relay.example" not in repr(ROWS), "no address or host in the row")
# a public name: private_relay false
name(["93.184.216.34"])
must(run_send() == 1 and ROWS[0]["private_relay"] is False, ROWS)
# a refused name: nothing sent, private_relay false
name(["127.0.0.1"])
must(run_send() == 0 and CORE.sent == [] and ROWS[0]["private_relay"] is False and ROWS[0]["code"] == "mail_host_refused", ROWS)
# setting off: the private name is refused and the row says false
RELAY["value"] = False
name(["10.0.0.5"])
must(run_send() == 0 and ROWS[0]["private_relay"] is False and ROWS[0]["code"] == "mail_host_refused", ROWS)
RELAY["value"] = True

# an injected host seam or send seam is never Core's own call
LOGS.clear()
must(run_send(host=lambda: "relay.example") == 0 and ROWS[0]["code"] == "mail_host_refused" and ROWS[0]["private_relay"] is False, ROWS)
must(any("not available to this caller" in line for line in LOGS), "the warning is logged")
sent_via_seam = []
must(run_send(send=lambda a, s, b: sent_via_seam.append(a) or True) == 0 and sent_via_seam == [], "an injected send seam gets public-only")
must(ROWS[0]["code"] == "mail_host_refused", ROWS)

# ------------------------------------------------------------------------------------------------ a module frame on the stack
MODULE_SRC = '''
def via_send(mfn, notice, users, **seams):
    return mfn.send_p1_email(notice, users, **seams)

def via_sweep(mfn, **seams):
    return mfn.sweep_failed_jobs(**seams)

def via_host_refusal(pm, host):
    return pm.host_refusal(host, core_seams=True)

def via_host_check(pm, host):
    return pm.host_check(host, core_seams=True)

def via_callback(fn):
    return fn()
'''


def run_module_file(plugin_id):
    path = EXT / plugin_id / "caller.py"
    path.write_text(MODULE_SRC, encoding="utf-8")
    ns = {"__name__": "mod_" + plugin_id}
    exec(compile(MODULE_SRC, str(path), "exec"), ns)  # noqa: S102 - test-only: real path, so the frame lies inside the module folder
    return ns


for plugin_id in ("alerts", "userinvite"):  # userinvite stands for an enabled category: server module
    ns = run_module_file(plugin_id)
    name(["10.0.0.5"])
    must(caller_identity.module_frame_on_stack() is False, "this test's own frame is not a module frame")
    must(ns["via_callback"](caller_identity.module_frame_on_stack) is True, (plugin_id, "a module frame is seen"))
    LOGS.clear()
    must(ns["via_host_refusal"](priority_mail, "relay.example") == priority_mail.REFUSED, (plugin_id, "host_refusal from a module"))
    must(ns["via_host_check"](priority_mail, "relay.example") == (priority_mail.REFUSED, False), (plugin_id, "host_check from a module"))
    must(any("not available to this caller" in line for line in LOGS), "warning logged")
    # send_p1_email called by a module with every default seam: the stack check still refuses the private path
    MARKERS.clear()
    ROWS.clear()
    CORE.sent.clear()
    got = ns["via_send"](mfn, NOTICE, [ADMIN], configured=lambda: True, recent=lambda since: 0, audit=lambda j, md: ROWS.append(dict(md)),
                         have=lambda ids: set(), mark=lambda u, c: MARKERS.add(c), server="srv", now=NOW)
    must(got == 0 and CORE.sent == [] and ROWS and ROWS[0]["code"] == "mail_host_refused" and ROWS[0]["private_relay"] is False, (plugin_id, ROWS))
    # a public name still works for the module's call (no fallback to a different sender, no refusal of the public path)
    name(["93.184.216.34"])
    MARKERS.clear()
    ROWS.clear()
    got = ns["via_send"](mfn, NOTICE, [ADMIN], configured=lambda: True, recent=lambda since: 0, audit=lambda j, md: ROWS.append(dict(md)),
                         have=lambda ids: set(), mark=lambda u, c: MARKERS.add(c), server="srv", now=NOW)
    must(got == 1 and ROWS[0]["private_relay"] is False, ROWS)

# sweep_failed_jobs from a module file: public-only; from Core's frame: the private path
name(["10.0.0.5"])


def sweep(caller=None):
    ROWS.clear()
    CORE.sent.clear()
    seams = dict(now=NOW, jobs=[JOB], recipients_for=lambda who: [ADMIN], publish=lambda recipients, n: 0, existing=lambda ids: set(),
                 configured=lambda: True, recent=lambda since: 0, audit=lambda j, md: ROWS.append(dict(md)), email_have=lambda ids: set(),
                 mark_sent=lambda u, c: None)
    return caller(mfn, **seams) if caller else mfn.sweep_failed_jobs(**seams)


module_ns = run_module_file("alerts")
sweep(module_ns["via_sweep"])
must(CORE.sent == [] and ROWS and ROWS[0]["code"] == "mail_host_refused" and ROWS[0]["private_relay"] is False, ("module sweep", ROWS))
sweep()
must(CORE.sent == [["root@example.test"]] and ROWS[0]["private_relay"] is True, ("core sweep", ROWS, CORE.sent))

# the stack check fails closed: an unreadable registry reads as 'a module frame is present'
REGISTRY_FAIL["on"] = True
must(caller_identity.module_frame_on_stack() is True, "registry error fails closed")
name(["10.0.0.5"])
must(run_send() == 0 and ROWS[0]["private_relay"] is False, "with an unreadable registry the private path is not taken")
REGISTRY_FAIL["on"] = False

# ------------------------------------------------------------------------------------------------ the reader fails closed
RELAY["raises"] = True
must(priority_mail._private_relay_on() is False and priority_mail.host_check(name(["10.0.0.5"]), core_seams=True)[0] == priority_mail.REFUSED,
     "an error reads as off")
RELAY["raises"] = False
for odd in (1, "true", "yes", None, [True], 0):
    RELAY["value"] = odd
    must(priority_mail._private_relay_on() is False, ("odd value is off", odd))
RELAY["value"] = True
saved = sys.modules.pop("tec_tac.runtime_settings")
pkg.__dict__.pop("runtime_settings", None)
try:
    must(priority_mail._private_relay_on() is False, "a missing settings module reads as off")
finally:
    sys.modules["tec_tac.runtime_settings"] = saved

# ------------------------------------------------------------------------------------------------ source and docs
mail_src = (APP / "priority_mail.py").read_text(encoding="utf-8")
for banned in ("smtplib", "SMTP(", "email_host_password", "smtp_host_password"):
    must(banned not in mail_src, banned)
must("get_priority_mail_private_relay" not in (APP / "capabilities.py").read_text(encoding="utf-8"), "not a capability")
contracts_src = (APP / "contracts.py").read_text(encoding="utf-8")
must("get_priority_mail_private_relay" not in contracts_src, "the reader is not in the public Python contract")
must("priority_mail_private_relay" in contracts_src and "AD-30" in contracts_src, "the HTTP setting is in the contract rows")
docs = (ROOT / "docs" / "runtime-settings.md").read_text(encoding="utf-8")
must("priority_mail_private_relay" in docs and "AD-30" in docs and "loopback" in docs, "docs/runtime-settings.md")
must("AD-29" in (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8"), "docs/resource-directory.md cites AD-29")
must((ROOT / "framwork" / "tec_tac" / "migrations" / "0029_priority_mail_private_relay.py").exists(), "migration 0029")
must('"0028_session_theme"' in (APP / "migrations" / "0029_priority_mail_private_relay.py").read_text(encoding="utf-8"), "migration 0029 follows 0028")

print("[TEST] PASS priority mail private relay 1.17.26")

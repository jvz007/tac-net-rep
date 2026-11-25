#!/usr/bin/env python3
"""1.18.51 regression: the two held 1.18.50 Medium findings on access events (Core-internal now, caller checked).

1. core.access_events is no longer a capability: nothing is registered, apps.py has no registration call, the two contract rows are gone, the
   guidance says Core-internal, the docs and the tunnel metadata say Core's own and not a capability.
2. The Signal is private (_access_changed) and every function checks its caller from the call stack. notify_access_changed accepts only Django's
   signal dispatcher, mark_changed only probe_tunnel.update_site, changed_at only probe_tunnel.access_changed_at. A stub module frame, a
   threading.Thread target, a functools.partial and a plain test frame are refused (0 or None, nothing written, nothing sent, one warning a
   minute). A fault in the check refuses.

Runs the real framwork/tec_tac/access_events.py under the stubs of tests/probe_transport_harness.py. Django is not installed on this PC. The
stub dispatcher and stub module frames are code compiled under a file name, which is exactly what the check reads."""
from __future__ import annotations

import ast
import importlib.util
import logging
import sys
import threading
from functools import partial
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("probe_transport_harness", HERE / "probe_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
must, reset, CACHE, WALL, ae, tun, APP = H.must, H.reset, H.CACHE, H.WALL, H.ae, H.tun, H.APP


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.rows = []

    def emit(self, record):
        self.rows.append(record)


LOG = Capture()
logging.getLogger("tec_tac.access_events").addHandler(LOG)
logging.getLogger("tec_tac.access_events").setLevel(logging.DEBUG)
logging.getLogger("tec_tac.access_events").propagate = False


def warnings():
    return [r for r in LOG.rows if r.levelno >= logging.WARNING]


# ------------------------------------------------------------------------------------------------ stub callers: code compiled under a file name
FAKE_DISPATCHER = str(HERE / "_stub_django" / "dispatch" / "dispatcher.py")
sys.modules["django.dispatch.dispatcher"] = SimpleNamespace(__file__=FAKE_DISPATCHER)


def code_as(filename, source):
    ns = {"ae": ae}
    exec(compile(source, filename, "exec"), ns)  # noqa: S102 - test stand-ins: code compiled under a chosen file name
    return ns


MODULE = code_as("<stub-module:somemodule>/tasks.py", "def call(fn, *a):\n    return fn(*a)\n")  # an installed module's frame
DISPATCHER = code_as(FAKE_DISPATCHER, "def send(fn, *a):\n    return fn(*a)\n")  # Django's signal dispatcher (the stub of it)
TUNNEL_UPDATE = code_as(str(APP / "probe_tunnel.py"), "def update_site(fn, *a):\n    return fn(*a)\n")
TUNNEL_READ = code_as(str(APP / "probe_tunnel.py"), "def access_changed_at(fn, *a):\n    return fn(*a)\n")
TUNNEL_OTHER = code_as(str(APP / "probe_tunnel.py"), "def some_other_function(fn, *a):\n    return fn(*a)\n")


def fresh():
    reset()
    ae.clear_callers_for_tests()
    LOG.rows.clear()
    WALL[0] = 1_000_000.0


def seen():
    return list(ae._access_changed.sent)


def markers():
    return [k for k in CACHE.data if k.startswith(ae.MARKER_PREFIX)]


def nothing_changed(label):
    must(not seen() and not markers(), (label, seen(), markers()))


def run_thread(target, *args):
    thread = threading.Thread(target=target, args=args)
    thread.start()
    thread.join()
    return 0


# ---------------------------------------------------------------- the capability is gone, the Signal is private
fresh()
for gone in ("access_changed", "AccessEventsProvider", "_PROVIDER", "register_core_access_events_capability", "access_events_contract_metadata", "OPERATIONS",
             "CAPABILITY_ID", "CAPABILITY_VERSION"):
    must(not hasattr(ae, gone), "access_events no longer has " + gone)
must(hasattr(ae, "_access_changed") and ae.SCOPE == "core-internal", "the Signal is private and the file says Core-internal")
registered = []
stub_caps = sys.modules.get("tec_tac.capabilities") or SimpleNamespace()
stub_caps.register_capability = lambda **kw: registered.append(kw)
sys.modules["tec_tac.capabilities"] = stub_caps
must(not registered and not hasattr(ae, "register_core_access_events_capability"), "nothing registers core.access_events")

apps = (APP / "apps.py").read_bytes().decode("utf-8")
must("register_core_access_events_capability" not in apps and "core.access_events" not in apps, "apps.py has no registration call")
must("connect_receivers" in apps, "apps.py still connects the receivers")
guarded = False
for node in ast.walk(ast.parse(apps)):
    if isinstance(node, ast.Try) and "id='connect_receivers'" in ast.dump(ast.Module(body=node.body, type_ignores=[])):
        guarded = bool(node.handlers)
must(guarded, "the receivers connect in a guarded block")
for name in ("apps.py", "contracts.py"):
    data = (APP / name).read_bytes()
    must(b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " keeps CRLF")
must(b"\r" not in (APP / "access_events.py").read_bytes(), "access_events.py is LF")

contracts = (APP / "contracts.py").read_bytes().decode("utf-8")
must('"area": "access-events"' not in contracts and "tec_tac.access_events" not in contracts, "the contract export has no access-events rows")
must('"name": "access_changed"' not in contracts and '"name": "changed_at"' not in contracts, "no access_changed or changed_at row")
guidance = [line for line in contracts.split("\r\n") if "Access changes (" in line]
must(len(guidance) == 1 and "Core-internal" in guidance[0] and "1.18.51" in guidance[0] and "Johan" in guidance[0], guidance)
must("connects a receiver" not in guidance[0] and "has_capability" not in guidance[0], "the guidance offers nothing to modules")
tunnel_line = [line for line in contracts.split("\r\n") if "Network Probe tunnel scope" in line]
must(len(tunnel_line) == 1 and "core.access_events" not in tunnel_line[0], "the tunnel scope guidance does not name the capability")

# ---------------------------------------------------------------- the caller check: refused callers
fresh()
refused = (
    ("a plain test frame", lambda: ae.notify_access_changed([10], "role_scope")),
    ("a stub module frame", lambda: MODULE["call"](ae.notify_access_changed, [10], "role_scope")),
    ("a threading target", lambda: run_thread(ae.notify_access_changed, [10], "role_scope")),
    ("a functools.partial run by a stub module", lambda: MODULE["call"](partial(ae.notify_access_changed, [10], "role_scope"))),
    ("a tunnel file function that is not update_site", lambda: TUNNEL_OTHER["some_other_function"](ae.notify_access_changed, [10], "role_scope")),
    ("the tunnel writer calling notify", lambda: TUNNEL_UPDATE["update_site"](ae.notify_access_changed, [10], "role_scope")),
    ("the dispatcher calling mark_changed", lambda: DISPATCHER["send"](ae.mark_changed, [10])),
)
for label, call in refused:
    fresh()
    result = call()
    if label == "a threading target":
        result = 0  # the thread's return value is dropped; the checks below are what counts
    must(not result, (label, result))
    nothing_changed(label)
for label, call in (
    ("a stub module frame", lambda: MODULE["call"](ae.mark_changed, [10])),
    ("a plain test frame", lambda: ae.mark_changed([10])),
    ("a threading target", lambda: run_thread(ae.mark_changed, [10])),
    ("a functools.partial run by a stub module", lambda: MODULE["call"](partial(ae.mark_changed, [10]))),
    ("the reader's function calling mark_changed", lambda: TUNNEL_READ["access_changed_at"](ae.mark_changed, [10])),
):
    fresh()
    must(call() in (0, None), label)
    nothing_changed("mark_changed from " + label)
    must(len(warnings()) <= 1, "one warning at most")

# the reader answers a marker only to probe_tunnel.access_changed_at
fresh()
CACHE.data[ae.marker_key(10)] = WALL[0]
must(ae.changed_at(10) is None, "a test frame gets None")
must(MODULE["call"](ae.changed_at, 10) is None, "a stub module frame gets None")
must(DISPATCHER["send"](ae.changed_at, 10) is None, "Django's dispatcher is not a reader")
must(TUNNEL_UPDATE["update_site"](ae.changed_at, 10) is None, "the tunnel writer function is not the reader")
must(TUNNEL_OTHER["some_other_function"](ae.changed_at, 10) is None, "another tunnel function is not the reader")
must(not warnings(), "a refused read is logged at debug only (it runs every tick)")
must(TUNNEL_READ["access_changed_at"](ae.changed_at, 10) == WALL[0], "the tunnel reader function gets the marker")
must(tun.access_changed_at(10) == WALL[0], "the real probe_tunnel.access_changed_at reads it")
must(tun.access_changed_at(11) is None and tun.access_changed_at(True) is None, "no marker, no answer")

# ---------------------------------------------------------------- the caller check: accepted callers
fresh()
must(DISPATCHER["send"](ae.notify_access_changed, [10, 11], "role_scope") == 2, "Django's dispatcher may notify")
must(len(markers()) == 2 and seen() == [{"user_ids": frozenset({10, 11}), "reason": "role_scope"}], (markers(), seen()))
must(not warnings(), "an accepted call logs nothing")
fresh()
must(TUNNEL_UPDATE["update_site"](ae.mark_changed, [10]) == 1 and CACHE.data.get(ae.marker_key(10)) == WALL[0] and not seen(), "update_site may mark, no signal")

# ---------------------------------------------------------------- the real receivers through a dispatcher frame
class Sig:
    """A Django model signal whose send runs under the dispatcher file name, as Django's own does."""

    def __init__(self):
        self.rows = {}

    def connect(self, receiver, sender=None, weak=True, dispatch_uid=None):
        self.rows.setdefault(dispatch_uid or id(receiver), (receiver, sender))

    def send(self, sender, **kw):
        ns = code_as(FAKE_DISPATCHER, "def send(receiver, **kw):\n    return receiver(**kw)\n")
        for receiver, wanted in list(self.rows.values()):
            if wanted is None or wanted is sender:
                ns["send"](receiver, sender=sender, **kw)


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def values_list(self, field, flat=False):
        return list(self.rows)


class _Users:
    def filter(self, role_id=None):
        return _Query({1: [10, 11], 2: [20]}.get(role_id, []))


class Role:
    objects = SimpleNamespace(filter=lambda pk__in=(): _Query([]))
    can_view_clients = SimpleNamespace(through=type("ClientsThrough", (), {}))
    can_view_sites = SimpleNamespace(through=type("SitesThrough", (), {}))


class User:
    objects = _Users()


class ExtensionRolePermission:
    pass


post_save, pre_delete, post_delete, m2m_changed = Sig(), Sig(), Sig(), Sig()
H.stub("accounts")
H.stub("accounts.models", Role=Role, User=User)
H.stub("django.db.models")
H.stub("django.db.models.signals", post_save=post_save, pre_delete=pre_delete, post_delete=post_delete, m2m_changed=m2m_changed)
H.stub("tec_tac.models", ExtensionRolePermission=ExtensionRolePermission)
# the receivers read users of a role through accounts.models.User.objects.filter(role_id=...)
fresh()
ae.connect_receivers()
post_save.send(Role, instance=SimpleNamespace(pk=1, name="Admin"), created=False)
must(set(markers()) == {ae.marker_key(10), ae.marker_key(11)} and seen()[-1]["reason"] == "role_permissions", (markers(), seen()))
fresh()
post_save.send(User, instance=SimpleNamespace(pk=40), created=False, update_fields=None)
must(markers() == [ae.marker_key(40)] and seen()[-1]["reason"] == "user_changed", "a user save marks the user")
fresh()
post_delete.send(User, instance=SimpleNamespace(pk=42))
must(markers() == [ae.marker_key(42)] and seen()[-1]["reason"] == "user_removed", "a user delete marks the user")
fresh()
m2m_changed.send(Role.can_view_sites.through, instance=SimpleNamespace(pk=1, name="Admin"), action="post_add", reverse=False, pk_set={5})
must(set(markers()) == {ae.marker_key(10), ae.marker_key(11)} and seen()[-1]["reason"] == "role_scope", "a scope change marks the role's people")

# ---------------------------------------------------------------- refusals are quiet, bounded and fail closed
fresh()
for _ in range(100):
    MODULE["call"](ae.notify_access_changed, [10], "role_scope")
    MODULE["call"](ae.mark_changed, [10])
nothing_changed("a loop of refused calls")
must(len(warnings()) == 1, ("100 refused calls log one warning in a minute", len(warnings())))
WALL[0] += ae.WARN_SECONDS + 1
MODULE["call"](ae.mark_changed, [10])
must(len(warnings()) == 2, "the next minute may log again")
must("somemodule" not in warnings()[0].getMessage() and "10" not in warnings()[0].getMessage(), "the warning names no module or person")
fresh()
original = ae._real
ae._real = lambda path: (_ for _ in ()).throw(RuntimeError("the path could not be read"))
try:
    must(DISPATCHER["send"](ae.notify_access_changed, [10], "role_scope") == 0, "a fault in the check refuses a writer")
    must(TUNNEL_UPDATE["update_site"](ae.mark_changed, [10]) == 0, "a fault in the check refuses mark_changed")
    must(TUNNEL_READ["access_changed_at"](ae.changed_at, 10) is None, "a fault in the check refuses the reader")
finally:
    ae._real = original
nothing_changed("a fault in the check")
must(len(warnings()) == 1, "one warning for the fault")
fresh()
real_sys = ae.sys
ae.sys = SimpleNamespace(modules=sys.modules)  # a stack that cannot be read (no _getframe)
try:
    must(ae._caller_allowed("mark_changed") is False, "no stack, no answer")
finally:
    ae.sys = real_sys

# ---------------------------------------------------------------- the words
text = (APP / "access_events.py").read_text(encoding="utf-8")
for needle in ("Core-internal", "hostile code", "signed-module-review", "docs/caller-identity.md"):
    must(needle in text, "the file says " + needle)
doc = (H.ROOT / "docs" / "access-events.md").read_text(encoding="utf-8")
capdoc = (H.ROOT / "docs" / "capabilities.md").read_bytes().decode("utf-8")
section = capdoc[capdoc.index("## Core access events"):capdoc.index("## Core agent downloads")]
transport = (H.ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
meta_text = str(H.pt.probe_transport_contract_metadata()["tunnel"]["scope"])
for label, body in (("access-events.md", doc), ("capabilities.md section", section), ("probe-transport.md", transport), ("tunnel metadata", meta_text), ("guidance", guidance[0])):
    must("has_capability" not in body and "connects a receiver" not in body and "may connect a receiver" not in body, label + " offers nothing to modules")
    must("core.access_events" not in body or "withdraws" in body or "offered" in body, label + " does not present core.access_events as live")
for label, body in (("access-events.md", doc), ("capabilities.md section", section), ("guidance", guidance[0])):
    must("Core-internal" in body, label + " says Core-internal")
for needle in ("Core-internal", "not a capability", "hostile code", "signed-module review", "docs/caller-identity.md", "threading", "functools.partial", "one warning a minute",
               "dispatcher", "probe_tunnel.update_site", "probe_tunnel.access_changed_at", "backstop", "queryset.update", "role_permissions", "role_scope", "user_changed", "user_removed"):
    must(needle.lower() in doc.lower(), "docs/access-events.md says " + needle)
must("Core's own" in meta_text and "not a capability" in meta_text, "the tunnel metadata names the marker as Core's own, not a capability")
must("not a capability" in transport and "Core's own" in transport, "probe-transport.md names the marker as Core's own")
for forbidden in ("a module cannot raise it", "cannot be raised by a module"):
    must(forbidden not in doc.lower() and forbidden not in text.lower() and forbidden not in section.lower(), "no unlimited claim: " + forbidden)
print("PASS access events 1.18.51")

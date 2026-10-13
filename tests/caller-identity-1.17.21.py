#!/usr/bin/env python3
"""1.17.21 regression (Johan CQ65 a, AD-26): a verified calling-module identity, read from the call stack. Core is never a caller.

A temporary extensions folder holds real ``.py`` files, run with ``exec(compile(source, real_path, "exec"))`` against a stub registry and a
stub module state. Covered: an enabled module that calls the provider directly is identified; the provider's own frames (any depth) are
skipped; a Core frame gives None and the Core caller special case is gone (no kind core anywhere, checked on every identity built); a
module's callable that Core runs (handler, row lookup, functools.partial, eval lambda) is the module only when its own frame calls the
provider directly; the real module_failure_notices has no trusted entry, and sweep_failed_jobs and send_p1_email with every seam set to a
partial of the provider function or an eval lambda give None, also with send_p1_email rebound; a generated (<string>) frame or a standard
library frame between the provider and the module gives None and never reaches the module further up; a library frame inside the provider
gives None; calling_module not called by the provider gives None; a disabled module gives None and does NOT fall through; a legacy plugin
gives None; a file outside every root gives None; module A calling a function of module B is seen as B; a thread a module started is
identified; a '..' path and a symlink are resolved with realpath; a registry error, a state error and a missing sys._getframe each give
None; the enabled state is read on every call; the function takes no argument a caller can use to choose the identity; the capability
core.caller_identity 1.0.0 registers with module_id core; the contract export row and docs/caller-identity.md state each limit.
"""
from __future__ import annotations

import ast
import dataclasses
import functools
import importlib
import inspect
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
logging.disable(logging.CRITICAL)
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------------------------------------ stubs
TMP = Path(tempfile.mkdtemp(prefix="tectac-caller-"))
EXT = TMP / "extensions"
EXT.mkdir()
ENABLED: dict = {}
PLUGINS: dict = {}
FAIL = {"registry": False, "state": False}
STATE_READS = []


def plugin(plugin_id, plugin_type="extension", legacy=False, version="1.2.3", enabled=True):
    root = EXT / plugin_id
    root.mkdir(exist_ok=True)
    PLUGINS[plugin_id] = SimpleNamespace(plugin_id=plugin_id, plugin_type=plugin_type, root=root, version=version, legacy=legacy)
    ENABLED[plugin_id] = enabled
    return root


def discover_plugins():
    if FAIL["registry"]:
        raise RuntimeError("registry unreadable")
    return tuple(PLUGINS.values())


def is_enabled(module_id, state=None):
    STATE_READS.append(module_id)
    if FAIL["state"]:
        raise RuntimeError("state unreadable")
    return ENABLED.get(module_id, True)


CAPS = []


def mod(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


pkg = mod("tec_tac")
pkg.__path__ = [str(APP)]
pkg.registry = mod("tec_tac.registry", discover_plugins=discover_plugins)
pkg.module_state = mod("tec_tac.module_state", is_enabled=is_enabled)
pkg.capabilities = mod("tec_tac.capabilities", register_capability=lambda **kw: CAPS.append(kw) or SimpleNamespace(**kw))
ci = importlib.import_module("tec_tac.caller_identity")
must(Path(ci.__file__).resolve() == (APP / "caller_identity.py").resolve(), ci.__file__)

# AD-26: every identity calling_module builds is recorded, and none may ever be kind core (checked at the end)
MINTED = []


@dataclasses.dataclass(frozen=True)
class _RecordedIdentity(ci.CallerIdentity):
    def __post_init__(self):
        MINTED.append(self)


ci.CallerIdentity = _RecordedIdentity


def run_file(path, source, write=True):
    """Compile ``source`` under the real path ``path`` (the file is written too, unless ``write`` is false) and return its namespace."""
    path = Path(path)
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(source, encoding="utf-8")
    ns = {"__name__": "mod_" + path.stem, "ci": ci}
    exec(compile(source, str(path), "exec"), ns)
    return ns


PROVIDER_SRC = '''
def whoami():
    return ci.calling_module(provider_module_id="globalsettings")

def deep(n):
    return deep(n - 1) if n else whoami()

def into(out):
    out.append(whoami())
'''
CALLER_SRC = '''
import contextlib, threading

def call(fn, *args):
    return fn(*args)

def via_stdlib(fn):
    stack = contextlib.ExitStack()
    out = []
    stack.callback(lambda: out.append(fn()))
    stack.close()
    return out[0]

def via_stdlib_direct(fn):
    out = []
    stack = contextlib.ExitStack()
    stack.callback(fn, out)
    stack.close()
    return out[0]

def via_thread_direct(fn):
    out = []
    thread = threading.Thread(target=fn, args=(out,))
    thread.start()
    thread.join()
    return out[0]

def via_thread(fn):
    out = []
    thread = threading.Thread(target=lambda: out.append(fn()))
    thread.start()
    thread.join()
    return out[0]
'''

plugin("globalsettings", version="0.4.0")
plugin("alerts", version="0.6.0")
plugin("checks", version="0.11.0")
plugin("disabledmod", enabled=False, version="0.1.0")
plugin("legacymod", plugin_type="extension", legacy=True, version="0.1.0")
plugin("reportset-like", plugin_type="reportset", version="0.1.0")

prov = run_file(EXT / "globalsettings" / "service.py", PROVIDER_SRC)
alerts = run_file(EXT / "alerts" / "caller.py", CALLER_SRC)
checks = run_file(EXT / "checks" / "caller.py", CALLER_SRC)
disabled = run_file(EXT / "disabledmod" / "caller.py", CALLER_SRC)
legacy = run_file(EXT / "legacymod" / "caller.py", CALLER_SRC)
reportset = run_file(EXT / "reportset-like" / "caller.py", CALLER_SRC)
outside = run_file(TMP / "elsewhere" / "caller.py", CALLER_SRC)
core_caller = run_file(APP / "_caller_identity_test_core.py", CALLER_SRC, write=False)  # compiled under the framework path; never written
must(not (APP / "_caller_identity_test_core.py").exists(), "the test leaves no file in the framework")

# ------------------------------------------------------------------------------------------------ identification
who = prov["whoami"]
got = alerts["call"](who)
must(got == ci.CallerIdentity("alerts", "module", "0.6.0"), got)
must(isinstance(got, ci.CallerIdentity) and got.kind == "module", got)
try:
    got.module_id = "x"
    raise AssertionError("CallerIdentity is mutable")
except Exception as exc:
    must(type(exc).__name__ in ("FrozenInstanceError", "AttributeError"), exc)

# the provider's own frames are skipped, at any depth
must(alerts["call"](prov["deep"], 5) == ci.CallerIdentity("alerts", "module", "0.6.0"), "provider depth is skipped")
must(checks["call"](prov["deep"], 0).module_id == "checks", "depth 0")

# AD-26 (Johan, 11 October 2026): Core is never a caller. A Core frame that calls the provider directly gives None.
must(core_caller["call"](who) is None, "a Core frame gives None")
for gone in ("KIND_CORE", "CORE_MODULE_ID", "_CORE_ENTRIES", "_capture_core_entries", "_is_core_entry", "_framework_version"):
    must(not hasattr(ci, gone), ("the Core caller special case is gone", gone))

# A module's callable that Core runs: a stub executor compiled under the framework path runs it. It is the module only when its own frame
# calls the provider directly, else None.
EXECUTOR_SRC = '''
def run_handler(handler):
    return handler()

def run_row_lookup(fn, pk):
    return fn(pk)
'''
executor = run_file(APP / "_caller_identity_test_executor.py", EXECUTOR_SRC, write=False)
must(executor["run_handler"](functools.partial(who)) is None, "a Scheduler handler that is a partial of the provider function gives None")
must(executor["run_handler"](who) is None, "the provider function itself registered as a handler gives None")
must(executor["run_row_lookup"](functools.partial(lambda pk, f: f(), f=who), 1) is None, "a test-file lambda (outside every module) gives None")
HANDLER_SRC = '''
import functools

def handler():
    return WHO()

def row_lookup(pk):
    return WHO()

def partial_handler():
    return functools.partial(WHO)

def eval_handler():
    return eval("lambda *a, **k: WHO()", {"WHO": WHO})
'''
handlers = run_file(EXT / "alerts" / "handlers.py", HANDLER_SRC)
handlers["WHO"] = who
must(executor["run_handler"](handlers["handler"]) == ci.CallerIdentity("alerts", "module", "0.6.0"), "a module handler that calls the provider directly is the module")
must(executor["run_row_lookup"](handlers["row_lookup"], 1) == ci.CallerIdentity("alerts", "module", "0.6.0"), "a module row lookup is the module")
must(executor["run_handler"](handlers["partial_handler"]()) is None, "a module's functools.partial run by Core gives None")
must(executor["run_handler"](handlers["eval_handler"]()) is None, "a module's eval lambda run by Core gives None")
must(executor["run_handler"](lambda: alerts["call"](who)) == ci.CallerIdentity("alerts", "module", "0.6.0"), "module code under Core's executor is the module")

# The REAL module_failure_notices. The trusted entry of the earlier review rounds is gone; every seam that runs a provider function gives None.
importlib.import_module("tec_tac.module_replacement")  # the real one: notice_for_job and the email text use its helpers
sys.modules.pop("tec_tac.module_failure_notices", None)
real = importlib.import_module("tec_tac.module_failure_notices")
must(Path(real.__file__).resolve() == (APP / "module_failure_notices.py").resolve(), real.__file__)
must(not hasattr(real, "_deliver_p1_via_provider"), "the Priority 1 delivery entry is removed")

SEAM_PROVIDER_SRC = '''
def record(out, *args, **kwargs):
    out.append(ci.calling_module(provider_module_id="globalsettings"))

def record_have(out, *args, **kwargs):
    out.append(ci.calling_module(provider_module_id="globalsettings"))
    return set()

def record_users(out, *args, **kwargs):
    out.append(ci.calling_module(provider_module_id="globalsettings"))
    return [USER]

def record_flag(out, *args, **kwargs):
    out.append(ci.calling_module(provider_module_id="globalsettings"))
    return True

def record_host(out, *args, **kwargs):
    out.append(ci.calling_module(provider_module_id="globalsettings"))
    return HOST

def record_count(out, *args, **kwargs):
    out.append(ci.calling_module(provider_module_id="globalsettings"))
    return 0
'''
seam = run_file(EXT / "globalsettings" / "seams.py", SEAM_PROVIDER_SRC)
SEAM_CALLER_SRC = '''
import functools

def via_send(real, notice, users, provider_fn, out):
    return real.send_p1_email(notice, users, configured=lambda: True, host=lambda: "smtp.example.com", have=lambda ids: set(),
                              mark=lambda u, c: None, recent=lambda since: 0, audit=lambda j, m: None,
                              send=functools.partial(provider_fn, out))

def via_have(real, notice, users, provider_fn, out):
    return real.send_p1_email(notice, users, configured=lambda: True, host=lambda: "smtp.example.com",
                              have=functools.partial(provider_fn, out), mark=lambda u, c: None, recent=lambda since: 0,
                              audit=lambda j, m: None, send=lambda a, s, b: True)

def via_mark(real, notice, users, provider_fn, out):
    return real.send_p1_email(notice, users, configured=lambda: True, host=lambda: "smtp.example.com", have=lambda ids: set(),
                              send=lambda a, s, b: True, recent=lambda since: 0, audit=lambda j, m: None,
                              mark=functools.partial(provider_fn, out))

def direct(real, notice, users):
    return real.send_p1_email(notice, users)

def sweep(real, job, **seams):
    return real.sweep_failed_jobs(jobs=[job], **seams)

def generated(provider_fn, out):
    return eval("lambda *a, **k: PROVIDER(OUT)", {"PROVIDER": provider_fn, "OUT": out})
'''
seam_caller = run_file(EXT / "alerts" / "seam_caller.py", SEAM_CALLER_SRC)
real_notice = {"client_id": "module-job-failed:abc", "level": "error", "title": "Module job failed", "message": "x", "action_label": "a",
               "action_route": "/m", "requested_by": "", "module": "checks"}
real_user = SimpleNamespace(pk=1, email="admin@example.com")
seam["USER"], seam["HOST"] = real_user, "smtp.example.com"
# 1.17.25: the public-address check resolves the mail server's name; a fake resolver keeps this test off the network
priority_mail = importlib.import_module("tec_tac.priority_mail")
priority_mail.resolve_addresses = lambda name: ["93.184.216.34"]
for name, fn, provider_fn in (("send=partial(provider_fn)", seam_caller["via_send"], seam["record"]),
                              ("have=partial(provider_fn)", seam_caller["via_have"], seam["record_have"]),
                              ("mark=partial(provider_fn)", seam_caller["via_mark"], seam["record"])):
    out = []
    fn(real, real_notice, [real_user], provider_fn, out)
    must(len(out) == 1, (name, out))
    must(out[0] is None, (name, "the provider function sits behind send_p1_email, a Core frame", out[0]))
# called directly from a module file, with the real module's own sender swapped for the provider function
direct_out = []
saved_defaults = (real._default_recent, real._default_mark_sent, real._default_existing, real._default_audit,
                  priority_mail.is_configured, priority_mail.smtp_host, priority_mail.send_one)
real._default_recent = lambda since: 0
real._default_mark_sent = lambda user, client_id: None
real._default_existing = lambda ids: set()
real._default_audit = lambda job_id, metadata: None
priority_mail.is_configured = lambda: True
priority_mail.smtp_host = lambda: "smtp.example.com"
priority_mail.send_one = functools.partial(seam["record"], direct_out)
try:
    seam_caller["direct"](real, real_notice, [real_user])
finally:
    (real._default_recent, real._default_mark_sent, real._default_existing, real._default_audit,
     priority_mail.is_configured, priority_mail.smtp_host, priority_mail.send_one) = saved_defaults
must(len(direct_out) == 1 and direct_out[0] is None, ("direct call", direct_out))


def failed_job():
    return {"id": "abc", "status": "failed", "action": "install", "module_id": "checks", "finished_at": datetime.now(timezone.utc).isoformat()}


QUIET = {"recipients_for": lambda requested_by: [real_user], "publish": lambda users, n: 1, "existing": lambda ids: set(),
         "configured": lambda: True, "host": lambda: "smtp.example.com", "send": lambda address, subject, body: True,
         "recent": lambda since: 0, "audit": lambda job_id, metadata: None, "email_have": lambda ids: set(), "mark_sent": lambda u, c: None}
# The review's case, called from a module file: the real sweep_failed_jobs with real.send_p1_email rebound to (a) functools.partial of the
# provider function and (b) an eval lambda that calls it. Both give None.
saved_send = real.send_p1_email
try:
    for label, make in (("partial", lambda out: functools.partial(seam["record"], out)),
                        ("eval lambda", lambda out: seam_caller["generated"](seam["record"], out))):
        out = []
        real.send_p1_email = make(out)
        seam_caller["sweep"](real, failed_job(), **QUIET)
        must(len(out) == 1 and out[0] is None, ("send_p1_email rebound to a " + label, out))
finally:
    real.send_p1_email = saved_send
# Every seam of sweep_failed_jobs set to a partial of the provider function, and to an eval lambda that calls it: each gives None.
SEAM_FN = {"recipients_for": "record_users", "publish": "record", "existing": "record_have", "configured": "record_flag",
           "host": "record_host", "send": "record", "recent": "record_count", "audit": "record", "email_have": "record_have",
           "mark_sent": "record"}
for seam_name, provider_name in SEAM_FN.items():
    for label, make in (("partial", lambda out, p=provider_name: functools.partial(seam[p], out)),
                        ("eval lambda", lambda out, p=provider_name: seam_caller["generated"](seam[p], out))):
        out = []
        seam_caller["sweep"](real, failed_job(), **{**QUIET, seam_name: make(out)})
        must(out and all(item is None for item in out), (seam_name, label, out))
# a module function rebound in place of send_p1_email is that module (its own frame calls the provider), never Core
rebind_provider = run_file(EXT / "globalsettings" / "rebind_provider.py", "def answer():\n    return ci.calling_module(provider_module_id='globalsettings')\n")
rebind = run_file(EXT / "alerts" / "rebind.py", "def fake_send(notice, recipients, **kw):\n    OUT.append(ANSWER())\n")
rebind["OUT"], rebind["ANSWER"] = [], rebind_provider["answer"]
try:
    real.send_p1_email = rebind["fake_send"]
    seam_caller["sweep"](real, failed_job(), **QUIET)
finally:
    real.send_p1_email = saved_send
must(rebind["OUT"] == [ci.CallerIdentity("alerts", "module", "0.6.0")], rebind["OUT"])

# module A calling a function of module B is seen as B (the code making the call)
bridge = run_file(EXT / "checks" / "bridge.py", "def relay(fn):\n    return fn()\n")
must(alerts["call"](bridge["relay"], who).module_id == "checks", "alerts calls checks' code, and checks' code makes the call: seen as checks")

# a disabled module gives None and does not fall through to the enabled module above it
must(disabled["call"](who) is None, "disabled")
must(checks["call"](lambda: disabled["call"](who)) is None, "no fall-through from a disabled module to an enabled caller above it")
# a legacy plugin and a non-extension plugin give None, also without fall-through
must(legacy["call"](who) is None and checks["call"](lambda: legacy["call"](who)) is None, "legacy")
must(reportset["call"](who) is None and checks["call"](lambda: reportset["call"](who)) is None, "non-extension")
# a file outside every root, with no identified frame at all, gives None
must(outside["call"](who) is None, "outside every root")

# AD-26 condition 3: a generated (<string>) frame or any skipped gap between the provider and the module frame gives None. The walk never
# skips such a frame to reach a module further up.
generated = {}
exec(compile("def hop(fn):\n    return fn()\n", "<string>", "exec"), generated)
must(alerts["call"](generated["hop"], who) is None, "a <string> frame between the module and the provider gives None")
must(alerts["call"](lambda: generated["hop"](who)) is None, "a <string> frame gives None, never the module further up")
must(alerts["call"](eval("lambda: WHO()", {"WHO": who})) is None, "an eval lambda gives None")
must(alerts["call"](functools.partial(who)) == ci.CallerIdentity("alerts", "module", "0.6.0"), "a partial adds no frame: the module frame calls the provider directly")
must(alerts["via_stdlib"](who).module_id == "alerts", "a module lambda run by the standard library is the module (its frame is the direct caller)")
must(alerts["via_stdlib_direct"](prov["into"]) is None, "the standard library calling the provider directly gives None")
must(alerts["via_thread_direct"](prov["into"]) is None, "a thread whose target is the provider function gives None (threading's frame calls it)")
must(outside["via_stdlib"](who) is None, "stdlib frames alone identify nobody")
# the frame that calls calling_module must be the provider's: a module asking about itself, or generated provider code, gives None
ASK_SRC = "def whoami():\n    return ci.calling_module(provider_module_id='globalsettings')\n"
must(run_file(EXT / "alerts" / "self_ask.py", ASK_SRC)["whoami"]() is None, "not called by the provider")
gen_provider = {"ci": ci}
exec(compile(ASK_SRC, "<string>", "exec"), gen_provider)
must(alerts["call"](gen_provider["whoami"]) is None, "generated code that calls calling_module is not the provider")
# a gap inside the provider (provider -> stdlib -> provider) is a gap too: refuse
GAP_PROVIDER_SRC = '''
import contextlib

def whoami():
    return ci.calling_module(provider_module_id="globalsettings")

def via_stdlib():
    out = []
    with contextlib.ExitStack() as stack:
        stack.callback(lambda: out.append(whoami()))
    return out[0]
'''
gap_provider = run_file(EXT / "globalsettings" / "gap.py", GAP_PROVIDER_SRC)
must(alerts["call"](gap_provider["via_stdlib"]) is None, "a library frame between two provider frames gives None")

# a thread a module started is identified as the module
must(alerts["via_thread"](who) == ci.CallerIdentity("alerts", "module", "0.6.0"), "a module thread")
must(checks["via_thread"](who).module_id == "checks", "another module thread")

# the enabled state is read on every call, never cached
del STATE_READS[:]
ENABLED["alerts"] = True
must(alerts["call"](who).module_id == "alerts", "enabled")
ENABLED["alerts"] = False
must(alerts["call"](who) is None, "a module disabled a moment ago is refused at once")
ENABLED["alerts"] = True
must(alerts["call"](who).module_id == "alerts" and STATE_READS.count("alerts") == 3, STATE_READS)

# ------------------------------------------------------------------------------------------------ paths
# a '..' path resolves with realpath before the comparison: it is the module it lands in, not the one it starts in
dotted = str(EXT / "alerts" / ".." / "checks" / "dotted.py")
dotted_ns = run_file(dotted, CALLER_SRC)
must(dotted_ns["call"](who).module_id == "checks", "'..' resolves to the folder it lands in")
# a path that climbs into the provider's folder is the provider's own frame, so it is skipped
into_provider = run_file(str(EXT / "alerts" / ".." / "globalsettings" / "own.py"), CALLER_SRC)
must(into_provider["call"](who) is None, "a '..' path into the provider is the provider's own frame")

# a symlink to a module folder resolves to that module. Where the platform refuses a symlink (Windows without the privilege), a
# directory junction does the same job; where neither can be made the case is skipped and says so.
def make_link(link, target):
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError, AttributeError):
        pass
    if os.name == "nt":
        import subprocess

        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False)
        return done.returncode == 0 and link.exists()
    return False


link = TMP / "link-to-alerts"
(TMP / "elsewhere").mkdir(exist_ok=True)
if make_link(link, EXT / "alerts"):
    linked = run_file(str(link / "linked.py"), CALLER_SRC, write=False)
    must(linked["call"](who).module_id == "alerts", "a symlink resolves before the comparison")
    out_link = TMP / "link-to-elsewhere"
    must(make_link(out_link, TMP / "elsewhere"), "second link")
    shadow = run_file(str(out_link / "shadow.py"), CALLER_SRC, write=False)
    must(shadow["call"](who) is None, "a link into a folder outside every root is outside")
else:
    print("[TEST] note: neither symlinks nor junctions are available here; the link case did not run")

# case: the comparison is case-normalised, as the platform does it
if os.name == "nt":
    upper = run_file(str(EXT / "ALERTS" / "upper.py"), CALLER_SRC)
    must(upper["call"](who).module_id == "alerts", "case is normalised on Windows")

# ------------------------------------------------------------------------------------------------ fail closed
FAIL["registry"] = True
must(alerts["call"](who) is None, "a registry error gives None")
FAIL["registry"] = False
FAIL["state"] = True
must(alerts["call"](who) is None, "a state error gives None")
FAIL["state"] = False
saved_sys = ci.sys
ci.sys = SimpleNamespace()  # no _getframe
must(alerts["call"](who) is None, "no sys._getframe gives None")
ci.sys = saved_sys
must(alerts["call"](who).module_id == "alerts", "back to normal")
# a provider that is not an installed extension, or an empty or non-string id, gives None
for bad in ("nosuchmodule", "", "  ", None, 5, "legacymod", "reportset-like"):
    must(ci.calling_module(provider_module_id=bad) is None, bad)

# ------------------------------------------------------------------------------------------------ no argument chooses the identity
signature = inspect.signature(ci.calling_module)
must(list(signature.parameters) == ["provider_module_id"], signature)
must(all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in signature.parameters.values()), signature)
for call in (lambda: ci.calling_module("globalsettings"), lambda: ci.calling_module(provider_module_id="globalsettings", module_id="alerts"),
             lambda: ci.calling_module(provider_module_id="globalsettings", caller="alerts"), lambda: ci.calling_module()):
    try:
        call()
        raise AssertionError("accepted an argument that could choose the identity")
    except TypeError:
        pass
source = (APP / "caller_identity.py").read_text(encoding="utf-8")
code = ast.parse(source)
for node in ast.walk(code):
    if isinstance(node, ast.FunctionDef) and node.name == "calling_module":
        must(node.args.vararg is None and node.args.kwarg is None and not node.args.args and len(node.args.kwonlyargs) == 1, node.name)
must("lru_cache" not in source and "_CACHE" not in source and "@cache" not in source, "the enabled state is never cached")
must('getattr(sys, "_getframe"' in source and "inspect.stack" not in source and "import inspect" not in source, "uses sys._getframe, not inspect.stack")

# ------------------------------------------------------------------------------------------------ the documented forgery limit
ns = {"ci": ci}
exec(compile("def call(fn):\n    return fn()\n", str(EXT / "alerts" / "not_really.py"), "exec"), ns)
must(ns["call"](who).module_id == "alerts", "code that forges its file name is seen as the module it names: hostile code, review is the defence")

# ------------------------------------------------------------------------------------------------ capability
del CAPS[:]
ci.register_core_caller_identity_capability()
must(len(CAPS) == 1, CAPS)
cap = CAPS[0]
must(cap["id"] == "core.caller_identity" and cap["module_id"] == "core" and cap["version"] == "1.0.0", cap)
must(tuple(cap["operations"]) == ("calling_module",) and cap["provider"].calling_module is ci.calling_module, cap)
meta = cap["metadata"]
must(meta["id"] == "core.caller_identity" and meta["version"] == "1.0.0" and meta["operations"] == ["calling_module"], meta)
must(len(meta["limits"]) == 4 and meta["requires_framework"] == ">=1.17.21", meta)
json.dumps(meta)

apps = (APP / "apps.py").read_text(encoding="utf-8")
block = re.search(r"        try:\n(?:(?!\n        except).)*?register_core_tactical_operations_capability\(\)(?:(?!\n        except).)*\n        except Exception:", apps, re.S)
must(block and "register_core_caller_identity_capability()" in block.group(0), "apps.py registers core.caller_identity in the guarded block")
must("from .caller_identity import register_core_caller_identity_capability" in block.group(0), "imported inside the guard")

# ------------------------------------------------------------------------------------------------ contract export row and docs
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
rows = None
for node in tree.body:
    if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "CORE_CONTRACTS" for t in node.targets):
        rows = ast.literal_eval(node.value)
must(rows, "CORE_CONTRACTS read")
row = next((r for r in rows if r.get("import_path") == "tec_tac.caller_identity" and r.get("name") == "calling_module"), None)
must(row and row["kind"] == "python" and row["area"] == "caller-identity", row)
docs = " ".join((ROOT / "docs" / "caller-identity.md").read_text(encoding="utf-8").split())  # one line, so a wrapped sentence still matches
COMMON = ("Core is never a caller", "seen as the module whose code makes the call", "callback surface", "forges its own file name", "compile()",
          "signed-module review", "not which person", "enabled right now", "generated file name", "functools.partial", "calls the provider directly")
for phrase in COMMON + ("None as refuse", "kind is always module", "Priority 1"):
    must(phrase.lower() in row["purpose"].lower(), ("contract row", phrase))
for phrase in COMMON + ("`None` means refuse", "always `\"module\"`", "No gap is skipped"):
    must(phrase.lower() in docs.lower(), ("docs", phrase))
for text, where in ((row["purpose"], "contract row"), (docs, "docs"), (" ".join(ci.LIMITS), "limits")):
    must("is seen as core" not in text.lower().replace("never seen as core", "") and "_deliver_p1_via_provider" not in text, (where, "no Core entry is described"))
for phrase in ("core.caller_identity", "1.17.21", "calling_module", "Priority 1"):
    must(phrase in docs, phrase)
must("changes nothing in ResourceAccessContext" in row["purpose"], "the row says what does not change")
for rel in ("docs/capabilities.md", "docs/developer-contracts.md"):
    must("docs/caller-identity.md" in (ROOT / rel).read_text(encoding="utf-8"), rel)

must(MINTED and all(item.kind == "module" and item.module_id != "core" for item in MINTED), MINTED)
must("KIND_CORE" not in source and 'CallerIdentity("core"' not in source and "CallerIdentity('core'" not in source, "no code path builds a Core identity")
must(meta["kinds"] == ["module"] and meta["core_is_caller"] is False, meta)

shutil.rmtree(TMP, ignore_errors=True)
print("[TEST] PASS caller identity 1.17.21")

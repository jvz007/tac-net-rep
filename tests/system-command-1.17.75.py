#!/usr/bin/env python3
"""1.17.75 regression (AD-49, fixed command templates only): the third kind of system action, ``agent.command`` (system_commands.py). Runs without Django: the file is loaded on its own and the cache,
audit and send are replaced by small fakes.

Covered: the confirmed parameters (shells, timeout) are strict; ``resolve`` accepts exactly the five keys and refuses everything else (shell not confirmed,
timeout above the confirmed maximum, control characters, a bad command_id, a bool agent number); the claim is once per (endpoint, command_id), differs per
endpoint, and an unreachable cache refuses (fail closed); ``run_one`` writes the strict audit row BEFORE the send, a closing row after, and neither row nor
the logs hold the command text or the output; the output is cut at 1 MiB; a timeout reads 'unreachable'; a failed send keeps the claim (at most once); a
failed 'before' row sends nothing and frees the claim; and the source wires the row (kind command, callers communicator, dangerous registration,
run_command operation, capability 1.5.0, keep_run for a batch).
"""
from __future__ import annotations

import importlib.util
import logging
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "framwork" / "tec_tac"
FAILED = []


def must(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        FAILED.append(label)


# ---- fakes: django.core.cache, the audit module, the Scheduler error, and system_actions (only what run_one reads)
store, broken = {}, {"cache": False}


class FakeCache:
    def add(self, key, value, timeout=None):
        if broken["cache"]:
            raise RuntimeError("cache down")
        if key in store:
            return False
        store[key] = value
        return True

    def delete(self, key):
        store.pop(key, None)


django = types.ModuleType("django")
core = types.ModuleType("django.core")
cache_mod = types.ModuleType("django.core.cache")
cache_mod.cache = FakeCache()
sys.modules.update({"django": django, "django.core": core, "django.core.cache": cache_mod})

rows, audit_fail = [], {"before": False}


class FakeAudit:
    @staticmethod
    def record(**kw):
        if audit_fail["before"] and kw["action"] == "run":
            raise RuntimeError("audit down")
        rows.append(kw)


class TransientError(Exception):
    pass


pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(ROOT)]
sys.modules["tec_tac"] = pkg
sa = types.ModuleType("tec_tac.system_actions")
sa._audit = lambda: FakeAudit
sa._actor_for = lambda owner: "actor"
sys.modules["tec_tac.system_actions"] = sa
pkg.system_actions = sa
sched = types.ModuleType("tec_tac.scheduler")
sched.SchedulerTransientError = TransientError
sys.modules["tec_tac.scheduler"] = sched
spec = importlib.util.spec_from_file_location("tec_tac.system_commands", ROOT / "system_commands.py")
sc = importlib.util.module_from_spec(spec)
sys.modules["tec_tac.system_commands"] = sc
spec.loader.exec_module(sc)

# ---- registration
import os
import tempfile

ROOT_DIR = os.path.realpath(tempfile.mkdtemp())
OUTSIDE_DIR = os.path.realpath(tempfile.mkdtemp())
sa._registered_plugin = lambda mid: types.SimpleNamespace(root=Path(ROOT_DIR)) if mid in ("communicator", "other") else (_ for _ in ()).throw(RuntimeError("not installed"))
who = {"id": "communicator"}
ci = types.ModuleType("tec_tac.caller_identity")
ci.calling_module_for_core_provider = lambda provider_file: types.SimpleNamespace(module_id=who["id"]) if who["id"] else None
sys.modules["tec_tac.caller_identity"] = ci

SLOTS = {"text": {"type": "text", "max": 40, "chars": "abcdefghijklmnopqrstuvwxyz 0123456789.:-/", "spaces": True}, "mins": {"type": "int", "min": 1, "max": 60}}
reg = sc.register_command_template("communicator", "communicator.notice", shell="cmd", text="msg * /time:{mins} {text}", slots=SLOTS, timeout=20)
must(reg["id"] == "communicator.notice" and len(reg["hash"]) == 64, "a template registers and gets a 64-character hash")
must(sc.register_command_template("communicator", "communicator.notice", shell="cmd", text="msg * /time:{mins} {text}", slots=SLOTS, timeout=20) == reg, "the same content again is accepted")


def refused(label, **kw):
    args = {"module_id": "communicator", "template_id": "communicator.x", "shell": "cmd", "text": "echo {text}", "slots": SLOTS, "timeout": 5}
    args.update(kw)
    mid, tid = args.pop("module_id"), args.pop("template_id")
    try:
        sc.register_command_template(mid, tid, **args)
        must(False, label)
    except sc.CommandTemplateError:
        must(True, label)


refused("a second registration with different content is refused", template_id="communicator.notice", text="msg * {text} {mins}")
refused("a second registration with a different shell is refused", template_id="communicator.notice", shell="powershell", text="msg * /time:{mins} {text}")
refused("a module off the allow-list may not register", module_id="other", template_id="other.x")
refused("a template id of another module is refused", template_id="other.x")
refused("a slot used but not specified is refused", text="echo {nope}")
refused("a text slot allowing a quote is refused", text="echo {text}", slots={"text": {"type": "text", "max": 5, "chars": "ab'"}})
refused("a text slot allowing a pipe is refused", text="echo {text}", slots={"text": {"type": "text", "max": 5, "chars": "a|b"}})
refused("a bad shell is refused", shell="zsh")
refused("text and file together are refused", file="/nonexistent/x")
must(sc.template_hashes(["communicator.notice"]) == {"communicator.notice": reg["hash"]}, "template_hashes returns the current hash")

who["id"] = "other"
refused("a module impersonating another by its module_id argument is refused", template_id="communicator.imp")
who["id"] = None
refused("an unverified caller is refused")
try:
    sc.template_hashes(["communicator.notice"])
    must(False, "template_hashes refuses an unverified caller")
except ValueError:
    must(True, "template_hashes refuses an unverified caller")
who["id"] = "communicator"
outside = Path(OUTSIDE_DIR) / "x.ps1"
outside.write_text("echo hi", encoding="utf-8")
refused("a template file outside the module directory is refused", template_id="communicator.out", text=None, file=str(outside), slots={})
inside = Path(ROOT_DIR) / "real.ps1"
inside.write_text("echo hi", encoding="utf-8")
link = Path(ROOT_DIR) / "link.ps1"
try:
    os.symlink(outside, link)
    refused("a symlinked template file is refused", template_id="communicator.lnk", text=None, file=str(link), slots={})
except (OSError, NotImplementedError):
    must(True, "symlink creation not permitted on this PC; the realpath check is covered by the outside-directory case")
refused("a space in chars needs spaces: true", text="echo {text}", slots={"text": {"type": "text", "max": 5, "chars": "ab "}})
# a file template: the hash is recorded at registration and a changed file is refused
tmp = Path(ROOT_DIR) / "reboot.ps1"
tmp.write_text("Write-Output {mins}", encoding="utf-8")
freg = sc.register_command_template("communicator", "communicator.filetpl", shell="powershell", file=str(tmp), slots={"mins": {"type": "int", "min": 1, "max": 9}}, timeout=10)

# ---- parameters
h, fh = reg["hash"], freg["hash"]
ok = sc.parameters({"allowed_templates": ["communicator.notice"], "template_hashes": {"communicator.notice": h}, "max_timeout": 10})
must(ok == {"allowed_templates": ["communicator.notice"], "template_hashes": {"communicator.notice": h}, "max_timeout": 10}, "parameters are cleaned")
for bad in ({}, None, {"allowed_templates": [], "template_hashes": {}}, {"allowed_templates": ["communicator.notice"]},
            {"allowed_templates": ["communicator.notice"], "template_hashes": {"communicator.notice": "zz"}},
            {"allowed_templates": ["communicator.notice"], "template_hashes": {"communicator.other": h}},
            {"allowed_templates": ["communicator.nothere"], "template_hashes": {"communicator.nothere": h}},
            {"allowed_templates": ["communicator.notice"], "template_hashes": {"communicator.notice": h}, "max_timeout": 61},
            {"allowed_templates": ["communicator.notice"], "template_hashes": {"communicator.notice": h}, "allowed_shells": ["cmd"]},
            {"allowed_templates": "communicator.notice", "template_hashes": {}}):
    try:
        sc.parameters(bad)
        must(False, f"parameters refuse {bad!r}")
    except ValueError:
        must(True, f"parameters refuse {bad!r}")

# ---- resolve
cleaned = sc.parameters({"allowed_templates": ["communicator.notice", "communicator.filetpl"], "template_hashes": {"communicator.notice": h, "communicator.filetpl": fh}, "max_timeout": 10})
good = {"agent_id": 7, "command_id": "run1-7", "template_id": "communicator.notice", "params": {"text": "reboot soon", "mins": 5}}
call, agent = sc.resolve(good, cleaned)
must(agent == 7 and call["command"] == "msg * /time:5 reboot soon" and call["shell"] == "cmd" and call["timeout"] == 10 and call["template_hash"] == h,
     "Core renders the command from the template; the shell comes from the template; the timeout is cut to the confirmed maximum")
for label, change, reason in (
    ("a free command field", {"command": "whoami"}, "bad_command"), ("a free shell field", {"shell": "cmd"}, "bad_command"),
    ("a quote in a text slot", {"params": {"text": "a'b", "mins": 5}}, "bad_command"), ("a semicolon in a text slot", {"params": {"text": "a;b", "mins": 5}}, "bad_command"),
    ("an ampersand in a text slot", {"params": {"text": "a&b", "mins": 5}}, "bad_command"), ("a newline in a text slot", {"params": {"text": "a\nb", "mins": 5}}, "bad_command"),
    ("a text slot too long", {"params": {"text": "a" * 41, "mins": 5}}, "bad_command"), ("an int out of range", {"params": {"text": "a", "mins": 61}}, "bad_command"),
    ("a bool for an int", {"params": {"text": "a", "mins": True}}, "bad_command"), ("a missing param", {"params": {"text": "a"}}, "bad_command"),
    ("an extra param", {"params": {"text": "a", "mins": 5, "x": 1}}, "bad_command"), ("a template not confirmed", {"template_id": "communicator.other"}, "action_not_allowed"),
    ("a bad command_id", {"command_id": "a b"}, "bad_command"), ("a bool agent", {"agent_id": True}, "bad_agents"),
    ("a space in the middle is allowed only where declared: leading space", {"params": {"text": " a", "mins": 5}}, "bad_command"),
    ("a leading dash (a flag)", {"params": {"text": "-rf", "mins": 5}}, "bad_command"), ("a leading slash (a switch)", {"params": {"text": "/c calc", "mins": 5}}, "bad_command"),
):
    try:
        sc.resolve({**good, **change}, cleaned)
        must(False, f"resolve refuses {label}")
    except sc.CommandRefused as exc:
        must(exc.reason == reason, f"resolve refuses {label} as {reason}")
try:  # confirmed, but never registered
    sc.resolve({**good, "template_id": "communicator.ghost"}, {**cleaned, "allowed_templates": ["communicator.ghost"], "template_hashes": {"communicator.ghost": h}})
    must(False, "an unregistered template id is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "bad_command", "an unregistered template id is refused")
try:  # the module was updated: the confirmed hash differs
    sc.resolve(good, {**cleaned, "template_hashes": {**cleaned["template_hashes"], "communicator.notice": "0" * 64}})
    must(False, "a template whose hash differs from the confirmed one is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "template_changed", "a template whose hash differs from the confirmed one is refused (template_changed)")
filecall = {"agent_id": 7, "command_id": "f1", "template_id": "communicator.filetpl", "params": {"mins": 3}}
must(sc.resolve(filecall, cleaned)[0]["command"] == "Write-Output 3", "a file template renders while the file is unchanged")
tmp.write_text("Write-Output {mins}; Remove-Item C:\\x", encoding="utf-8")
try:
    sc.resolve(filecall, cleaned)
    must(False, "a file template whose content changed is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "template_changed", "a file template whose content changed is refused (template_changed)")
tmp.unlink()
try:
    sc.resolve(filecall, cleaned)
    must(False, "a missing template file is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "function_unavailable", "a missing template file is refused (fail closed)")

# ---- no free-text command kind anywhere in the table
src_sa = (ROOT / "system_actions.py").read_text(encoding="utf-8")
must('"command", "timeout"' not in (ROOT / "system_commands.py").read_text(encoding="utf-8") and '"command_id", "shell"' not in src_sa, "the call shape has no free command or shell field")

# ---- claim
must(sc.claim(7, "a") is True and sc.claim(7, "a") is False and sc.claim(8, "a") is True and sc.claim(7, "b") is True, "one claim per endpoint and command_id")
broken["cache"] = True
try:
    sc.claim(9, "z")
    must(False, "an unreachable cache refuses")
except sc.CommandRefused as exc:
    must(exc.reason == "function_unavailable", "an unreachable cache refuses (fail closed)")
broken["cache"] = False

# ---- run_one
SECRET, OUT = "SECRETCOMMANDTEXT", "SECRETOUTPUT"
definition = types.SimpleNamespace(id="remote-background.command", module_id="remote-background", function="agent.command")
run = types.SimpleNamespace(id="r1")
verified = types.SimpleNamespace(schedule_id="s1")
sent = []
logged = []


class Catch(logging.Handler):
    def emit(self, record):
        logged.append(record.getMessage())


logging.getLogger("tec_tac.system_actions").addHandler(Catch())


def go(command_id, reply, agent_pk=70):
    sc._send = lambda pk, call, username: (sent.append((pk, call["command_id"])), reply)[1]
    return sc.run_one(definition=definition, run=run, verified=verified, owner=None, provenance={"creator": "johan"}, extra={}, agent_pk=agent_pk,
                      call={"command_id": command_id, "template_id": "communicator.notice", "template_hash": "ab" * 32, "shell": "cmd", "command": SECRET, "timeout": 5})


res = go("c1", OUT)
must(res["outcome"] == "ran" and res["output"] == OUT and res["truncated"] is False, "a normal run returns the output")
must([r["action"] for r in rows] == ["run", sc.CLOSING_ACTION] and all(r["strict"] for r in rows), "a strict row before and a closing row after")
must(SECRET not in repr(rows) and OUT not in repr(rows) and SECRET not in repr(logged), "neither the command nor the output is audited or logged")
must(rows[0]["metadata"]["command_length"] == len(SECRET) and rows[0]["metadata"]["agent_id"] == 70 and rows[0]["metadata"]["kind"] == "command"
     and rows[0]["metadata"]["template_id"] == "communicator.notice" and rows[0]["metadata"]["template_hash"] == "ab" * 32, "the row holds the endpoint, the length, the template id and hash")
try:
    go("c1", OUT)
    must(False, "a repeated command_id is refused")
except sc.CommandRefused as exc:
    must(exc.reason == "duplicate_command" and len(sent) == 1, "a repeated command_id is refused and nothing is sent again")
big = go("c2", "x" * (sc.MAX_OUTPUT_BYTES + 10))
must(big["truncated"] is True and len(big["output"].encode()) == sc.MAX_OUTPUT_BYTES, "the output is cut at 1 MiB and says so")
must(go("c3", "timeout")["outcome"] == "unreachable", "a timeout reads unreachable")


def boom(pk, call, username):
    raise RuntimeError("nats down")


sc._send = boom
res = sc.run_one(definition=definition, run=run, verified=verified, owner=None, provenance={}, extra={}, agent_pk=71, call={"command_id": "c4", "template_id": "communicator.notice", "template_hash": "ab" * 32, "shell": "cmd", "command": SECRET, "timeout": 5})
must(res["outcome"] == "failed" and sc.claim(71, "c4") is False, "a failed send keeps the claim (at most once)")
audit_fail["before"] = True
before_sent = len(sent)
try:
    go("c5", OUT, agent_pk=72)
    must(False, "a failed before-row refuses")
except TransientError:
    must(len(sent) == before_sent and sc.claim(72, "c5") is True, "a failed 'before' row sends nothing and frees the claim")
audit_fail["before"] = False

# ---- the wiring in system_actions.py
src = (ROOT / "system_actions.py").read_text(encoding="utf-8")
for needle in ('"agent.command": SystemFunction(', 'kind=KIND_COMMAND', 'callers=("communicator",)', 'a command action must be registered with dangerous=True',
               'CAPABILITY_VERSION = "1.5.0"', '"run_command"', 'def run_system_command(', 'common["keep_run"] = True', 'verified.held_at_creation("can_send_cmd")',
               "keep_run: bool = False", '"duplicate_command"', '"bad_command"', '"template_changed"', 'register_command_template = _sc.register_command_template'):
    must(needle in src, f"system_actions.py has: {needle}")

print("PASS" if not FAILED else f"FAIL: {len(FAILED)} check(s)")
sys.exit(1 if FAILED else 0)

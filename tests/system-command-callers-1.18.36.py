#!/usr/bin/env python3
"""1.18.36 regression (ORDER of 21 November 2026, AD-13 check: CQ175 / AD-46, AD-60 J2 and J3): the command row ``agent.command`` has two callers.
``softwarerepository`` is the caller (fixed templates, right ``softwarerepository.deploy``); ``communicator`` stays on ``LEGACY_CALLERS`` so the installed
0.6.17 keeps working. Runs without Django: system_commands.py is loaded alone with small fakes.

Covered: the constants and the row text; registration (default right, a right of another module, an unknown module, a caller that is not the module it names);
``parameters`` (one module per schedule, per-module rights, Communicator cases unchanged); ``resolve`` (a template of another module is action_not_allowed in both
directions, permission_lost, typed-slot rendering and limits, template_changed on a changed file); ``templates_belong_to``; the contract text; the audit rows name the
real calling module and never hold the command, the token or the host; ``_run`` passes the verified caller.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "framwork" / "tec_tac"
FAILED = []


def must(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        FAILED.append(label)


class Cache:
    def add(self, *a, **k):
        return True

    def delete(self, *a, **k):
        pass

    def incr(self, key):
        return 1


cache_mod = types.ModuleType("django.core.cache")
cache_mod.cache = Cache()
sys.modules.update({"django": types.ModuleType("django"), "django.core": types.ModuleType("django.core"), "django.core.cache": cache_mod})
pkg = types.ModuleType("tt36")
pkg.__path__ = [str(ROOT)]
sys.modules["tt36"] = pkg
for _name in ("module_category", "tactical_operations"):
    spec = importlib.util.spec_from_file_location(f"tt36.{_name}", ROOT / f"{_name}.py")
    _mod = importlib.util.module_from_spec(spec)
    sys.modules[f"tt36.{_name}"] = _mod
    spec.loader.exec_module(_mod)

TMP = os.path.realpath(tempfile.mkdtemp(prefix="tt36-"))
CALLER = {"module": None}
caller_identity = types.ModuleType("tt36.caller_identity")
caller_identity.calling_module_for_core_provider = lambda provider_file=None: types.SimpleNamespace(module_id=CALLER["module"]) if CALLER["module"] else None
sys.modules["tt36.caller_identity"] = caller_identity
AUDITS = []
sa = types.ModuleType("tt36.system_actions")
sa._actor_for = lambda owner: "actor"
sa._audit = lambda: types.SimpleNamespace(record=lambda **kw: AUDITS.append(kw))
INSTALLED = {"softwarerepository", "communicator", "endpoint-comms", "take-control"}
sa._registered_plugin = lambda module_id: types.SimpleNamespace(root=TMP) if module_id in INSTALLED else (_ for _ in ()).throw(KeyError(module_id))
sys.modules["tt36.system_actions"] = sa
sched = types.ModuleType("tt36.scheduler")
sched.SchedulerTransientError = RuntimeError
sys.modules["tt36.scheduler"] = sched
spec = importlib.util.spec_from_file_location("tt36.system_commands", ROOT / "system_commands.py")
sc = importlib.util.module_from_spec(spec)
sys.modules["tt36.system_commands"] = sc
spec.loader.exec_module(sc)

SA_SRC = (ROOT / "system_actions.py").read_text(encoding="utf-8")
SC_SRC = (ROOT / "system_commands.py").read_text(encoding="utf-8")


def refused(fn, exc_type=(sc.CommandTemplateError, ValueError, sc.CommandRefused), reason=None):
    try:
        fn()
    except exc_type as exc:
        return reason is None or getattr(exc, "reason", None) == reason
    return False


def register(module, template_id, **kw):
    CALLER["module"] = module
    try:
        return sc.register_command_template(kw.pop("module_id", module), template_id, **kw)
    finally:
        CALLER["module"] = None


# ---- (a) constants and the row text
must(sc.CALLERS == ("softwarerepository",) and sc.LEGACY_CALLERS == ("communicator",) and sc.REGISTRANTS == ("softwarerepository", "communicator"), "CALLERS, LEGACY_CALLERS and REGISTRANTS")
must(sc.RIGHT_DEPLOY == "softwarerepository.deploy" and sc.RIGHTS == ("communicator.send", "communicator.reboot"), "RIGHT_DEPLOY and the Communicator pair kept for compatibility")
must(sc.RIGHTS_BY_MODULE == {"communicator": ("communicator.send", "communicator.reboot"), "softwarerepository": ("softwarerepository.deploy",)}
     and sc.BASE_RIGHT == {"communicator": "communicator.send", "softwarerepository": "softwarerepository.deploy"}, "rights per module and the base right of each")
must("callers=_sc.REGISTRANTS," in SA_SRC and 'callers=("communicator",)' not in SA_SRC, "the agent.command row text reads callers=_sc.REGISTRANTS")
must("caller=identity.module_id" in SA_SRC.split("def _run(")[1].split("def ")[0] and "_sc.resolve(command, cleaned, caller=identity.module_id)" in SA_SRC, "_run passes the verified caller to resolve")

# ---- (b) registration
SLOTS = {"token": {"type": "text", "max": 64, "chars": "0123456789abcdef"}, "sha": {"type": "text", "max": 64, "chars": "0123456789abcdef"},
         "size": {"type": "text", "max": 12, "chars": "0123456789"}, "host": {"type": "text", "max": 100, "chars": "abcdefghijklmnopqrstuvwxyz0123456789.-"},
         "n": {"type": "int", "min": 1, "max": 10**9}}
TEXT = "launch {token} {sha} {size} {host} {n}"
r1 = register("softwarerepository", "softwarerepository.launch", shell="powershell", text=TEXT, slots=SLOTS, timeout=30)
rec = sc._TEMPLATES["softwarerepository.launch"]
must(rec["right"] == "softwarerepository.deploy" and rec["module_id"] == "softwarerepository" and r1["hash"] == rec["hash"], "softwarerepository registers with the default right and gets softwarerepository.deploy")
must(register("softwarerepository", "softwarerepository.launch", shell="powershell", text=TEXT, slots=SLOTS, timeout=30) == r1, "the same content again is accepted")
must(register("softwarerepository", "softwarerepository.launch", shell="powershell", text=TEXT, slots=SLOTS, timeout=30, right="softwarerepository.deploy") == r1, "the explicit own right is the same registration")
must(refused(lambda: register("softwarerepository", "softwarerepository.other", shell="cmd", text="echo hi", right="communicator.send")), "a communicator.* right on a softwarerepository template is refused")
must(refused(lambda: register("softwarerepository", "softwarerepository.other", shell="cmd", text="echo hi", right="communicator.reboot")), "communicator.reboot on a softwarerepository template is refused")
must(refused(lambda: register("softwarerepository", "softwarerepository.launch", shell="powershell", text=TEXT + " x", slots=SLOTS, timeout=30)), "different content under the same id is refused")
for other in ("endpoint-comms", "take-control"):
    must(refused(lambda other=other: register(other, f"{other}.x", shell="cmd", text="echo hi")), f"{other} may not register command templates")
must(refused(lambda: register("communicator", "softwarerepository.sneaky", shell="cmd", text="echo hi", module_id="softwarerepository")), "a caller that is not the module it names is refused")
must(refused(lambda: sc.register_command_template("softwarerepository", "softwarerepository.nobody", shell="cmd", text="echo hi")), "a call with no verified module is refused")
register("communicator", "communicator.notice", shell="cmd", text="msg * {n}", slots={"n": {"type": "int", "min": 1, "max": 60}}, timeout=20)
register("communicator", "communicator.restart", shell="cmd", text="shutdown /r", timeout=20, right="communicator.reboot")
must(sc._TEMPLATES["communicator.notice"]["right"] == "communicator.send" and sc._TEMPLATES["communicator.restart"]["right"] == "communicator.reboot",
     "communicator still registers (default right send, right=communicator.reboot kept): the compatibility path")
must(refused(lambda: register("communicator", "communicator.bad", shell="cmd", text="echo hi", right="softwarerepository.deploy")), "a softwarerepository right on a communicator template is refused")

# ---- (c) parameters
H = {tid: sc._TEMPLATES[tid]["hash"] for tid in sc._TEMPLATES}


def p(templates, rights, **extra):
    return {"allowed_templates": templates, "template_hashes": {t: H[t] for t in templates}, "rights": rights, **extra}


ok = sc.parameters(p(["softwarerepository.launch"], ["softwarerepository.deploy"], max_timeout=30))
must(ok["rights"] == ["softwarerepository.deploy"] and ok["allowed_templates"] == ["softwarerepository.launch"] and ok["max_timeout"] == 30, "parameters accepted with softwarerepository.deploy")
must(refused(lambda: sc.parameters(p(["softwarerepository.launch"], ["communicator.send"]))), "parameters refused with communicator.send for a softwarerepository template")
must(refused(lambda: sc.parameters(p(["softwarerepository.launch"], ["softwarerepository.deploy", "communicator.send"]))), "parameters refused with another module's right added")
must(refused(lambda: sc.parameters(p(["softwarerepository.launch"], []))) and refused(lambda: sc.parameters(p(["softwarerepository.launch"], ["can_send_cmd"]))), "empty or unknown rights are refused")
must(refused(lambda: sc.parameters(p(["softwarerepository.launch", "communicator.notice"], ["softwarerepository.deploy", "communicator.send"]))), "templates of two modules in one schedule are refused")
must(sc.parameters(p(["communicator.notice"], ["communicator.send"]))["rights"] == ["communicator.send"], "Communicator: send only is accepted (unchanged)")
must(sc.parameters(p(["communicator.notice", "communicator.restart"], ["communicator.send", "communicator.reboot"]))["rights"] == ["communicator.reboot", "communicator.send"], "Communicator: send and reboot are accepted (unchanged)")
must(refused(lambda: sc.parameters(p(["communicator.restart"], ["communicator.reboot"]))), "Communicator: reboot alone is refused (unchanged)")
must(refused(lambda: sc.parameters(p(["communicator.restart"], ["communicator.send"]))), "Communicator: a restart template needs reboot (unchanged)")
must(refused(lambda: sc.parameters(p(["communicator.notice"], ["softwarerepository.deploy"]))), "Communicator: a softwarerepository right alone is refused")

# ---- (d) resolve
SR = sc.parameters(p(["softwarerepository.launch"], ["softwarerepository.deploy"], max_timeout=30))
CM = sc.parameters(p(["communicator.notice"], ["communicator.send"]))
TOKEN, SHA, HOST = "a1b2c3d4" * 4, "0f" * 32, "repo.example.co.za"
GOOD = {"agent_id": 7, "command_id": "run-1", "template_id": "softwarerepository.launch", "params": {"token": TOKEN, "sha": SHA, "size": "1073741824", "host": HOST, "n": 5}}
call, pk = sc.resolve(GOOD, SR, caller="softwarerepository")
must(pk == 7 and call["command"] == f"launch {TOKEN} {SHA} 1073741824 {HOST} 5" and call["timeout"] == 30 and call["shell"] == "powershell", "token, SHA-256, size (digits-only text) and host slots render")
must(sc.resolve(GOOD, SR)[0]["command"] == call["command"], "a call with no caller still resolves (the check is made when a caller is given)")
cm_cmd = {"agent_id": 7, "command_id": "c-1", "template_id": "communicator.notice", "params": {"n": 5}}
must(sc.resolve(cm_cmd, CM, caller="communicator")[0]["command"] == "msg * 5", "a communicator run resolves its own template (compatibility proof)")
must(refused(lambda: sc.resolve({**GOOD, "template_id": "communicator.notice", "params": {"n": 5}}, {**SR, "allowed_templates": ["communicator.notice"], "template_hashes": {"communicator.notice": H["communicator.notice"]}, "rights": ["communicator.send"]}, caller="softwarerepository"), reason="action_not_allowed"),
     "a softwarerepository run naming a communicator template is action_not_allowed")
must(refused(lambda: sc.resolve({**cm_cmd, "template_id": "softwarerepository.launch", "params": GOOD["params"]}, {**CM, "allowed_templates": ["softwarerepository.launch"], "template_hashes": {"softwarerepository.launch": H["softwarerepository.launch"]}, "rights": ["softwarerepository.deploy"]}, caller="communicator"), reason="action_not_allowed"),
     "a communicator run naming a softwarerepository template is action_not_allowed")
must(refused(lambda: sc.resolve(GOOD, {**SR, "rights": []}, caller="softwarerepository"), reason="permission_lost") and refused(lambda: sc.resolve(GOOD, {k: v for k, v in SR.items() if k != "rights"}, caller="softwarerepository"), reason="permission_lost"),
     "a missing deploy right is permission_lost")
must(refused(lambda: sc.resolve(GOOD, {**SR, "rights": ["communicator.send"]}, caller="softwarerepository"), reason="permission_lost"), "the module cannot attest another module's right: permission_lost")
for label, bad in (("a dash first", {"host": "-evil.example"}), ("a slash first", {"token": "/abc"}), ("a quote", {"host": 'a"b'}), ("an equals sign", {"token": "ab=="}),
                   ("an uppercase letter outside the set", {"token": "ABCDEF"}), ("a space", {"host": "a b"}), ("an int over its range", {"n": 10**9 + 1}), ("a bool for an int", {"n": True}),
                   ("too long", {"size": "1" * 13})):
    must(refused(lambda bad=bad: sc.resolve({**GOOD, "params": {**GOOD["params"], **bad}}, SR, caller="softwarerepository"), reason="bad_command"), f"{label} in a slot is bad_command")
must(refused(lambda: sc.resolve({**GOOD, "params": {k: v for k, v in GOOD["params"].items() if k != "n"}}, SR, caller="softwarerepository"), reason="bad_command"), "a missing slot is bad_command")
must(refused(lambda: sc.resolve({**GOOD, "command": "x"}, SR, caller="softwarerepository"), reason="bad_command"), "a free command text is bad_command")
must(refused(lambda: sc.resolve({**GOOD, "template_id": "softwarerepository.launch2"}, SR, caller="softwarerepository"), reason="action_not_allowed"), "a template outside the confirmed list is action_not_allowed")
# template_changed on a changed file hash (a file template inside the module's install directory)
FILE = os.path.join(TMP, "check.ps1")
Path(FILE).write_text("Write-Output {sha}\n", encoding="utf-8")
rf = register("softwarerepository", "softwarerepository.check", shell="powershell", file=FILE, slots={"sha": SLOTS["sha"]}, timeout=20)
FP = sc.parameters({"allowed_templates": ["softwarerepository.check"], "template_hashes": {"softwarerepository.check": rf["hash"]}, "rights": ["softwarerepository.deploy"]})
fcmd = {"agent_id": 7, "command_id": "run-f", "template_id": "softwarerepository.check", "params": {"sha": SHA}}
must(sc.resolve(fcmd, FP, caller="softwarerepository")[0]["command"].strip() == f"Write-Output {SHA}", "a file template renders")
Path(FILE).write_text("Write-Output changed {sha}\n", encoding="utf-8")
must(refused(lambda: sc.resolve(fcmd, FP, caller="softwarerepository"), reason="template_changed"), "template_changed still fires on a changed file hash")
Path(FILE).write_text("Write-Output {sha}\n", encoding="utf-8")

# ---- (e) templates_belong_to
sc.templates_belong_to(SR, "softwarerepository")
sc.templates_belong_to(CM, "communicator")
must(refused(lambda: sc.templates_belong_to(SR, "communicator"), ValueError) and refused(lambda: sc.templates_belong_to(CM, "softwarerepository"), ValueError), "templates_belong_to refuses another module's templates")
must(refused(lambda: sc.templates_belong_to({"allowed_templates": ["softwarerepository.unknown"]}, "softwarerepository"), ValueError), "templates_belong_to refuses an unregistered template")
CALLER["module"] = "softwarerepository"
must(sc.template_hashes(["softwarerepository.launch"]) == {"softwarerepository.launch": H["softwarerepository.launch"]}, "softwarerepository reads its template hashes")
CALLER["module"] = "endpoint-comms"
must(refused(lambda: sc.template_hashes(["softwarerepository.launch"]), ValueError), "endpoint-comms may not read template hashes")
CALLER["module"] = None

# ---- the audit rows name the real calling module and hold no command, token or host
sc._service_user = lambda: object()
sc.route_agent_id = lambda pk: "x" * 27
sc._check_route = lambda path: None
sc._resolve_view = lambda path: None
sc.count_run = lambda run_id: 1
sc.claim = lambda *a, **k: True
sc.release = lambda *a, **k: None
sc._build_view_request = lambda *a, **k: object()
sc._dispatch_view = lambda match, request: types.SimpleNamespace(status_code=200, content=b'"done"')
definition = types.SimpleNamespace(function="agent.command", module_id="remote-background", id="remote-background.command")
for module, command, cleaned_, caller in (("softwarerepository", GOOD, SR, "softwarerepository"), ("communicator", cm_cmd, CM, "communicator")):
    call, pk = sc.resolve(command, cleaned_, caller=caller)
    AUDITS.clear()
    out = sc.run_one(definition=definition, run=types.SimpleNamespace(id="r1"), verified=types.SimpleNamespace(schedule_id="s1"), owner=None, provenance={"creator": "johan"}, extra={}, agent_pk=pk, call=call)
    before, closing = AUDITS[0], AUDITS[1]
    meta = before["metadata"]
    must(out["outcome"] == "ran" and len(AUDITS) == 2, f"{module}: the run sends and writes the before and closing rows")
    must(meta["run_as"] == module and meta["caller_module"] == module and f"as the {module} module" in before["message"], f"{module}: the strict before row names the calling module")
    must(meta["service_user"] == "tectac-communicator" and meta["template_id"] == command["template_id"] and meta["template_hash"] == call["template_hash"]
         and meta["agent_id"] == pk and meta["command_id"] == command["command_id"], f"{module}: template, hash, endpoint and command_id are in the row")
    must(closing["metadata"]["run_as"] == module and closing["metadata"]["caller_module"] == module, f"{module}: the closing row names the calling module")
    blob = repr(AUDITS)
    must(call["command"] not in blob and "done" not in blob.replace("A scheduled command", "") and TOKEN not in blob and HOST not in blob and SHA not in blob, f"{module}: no row holds the command, the output, the token or the host")
must("The command service user (tectac-communicator) is not installed" in SC_SRC and "The Communicator service user is not installed" not in SC_SRC, "the service user refusal text names the command service user")
must("Run as the communicator module" not in SC_SRC and '"run_as": "communicator"' not in SC_SRC, "no audit text hard-codes communicator")

# ---- the contract text
must('"callers": list(_sc.CALLERS)' in SA_SRC and '"legacy_callers": list(_sc.LEGACY_CALLERS)' in SA_SRC and "legacy_callers_reason" in SA_SRC and "rights_by_module" in SA_SRC, "the contract metadata lists callers and legacy_callers")
cx = (ROOT / "contracts.py").read_text(encoding="utf-8")
purpose = cx[cx.index('"name": "run_system_command"'):]
purpose = purpose[:purpose.index("\n    },")] if "\n    }," in purpose else purpose[:6000]
must("softwarerepository" in purpose and "communicator" in purpose and "legacy" in purpose.lower() and "only a verified Scheduler run of communicator may call it" not in purpose, "the contracts.py text names both callers and no longer claims 'only communicator'")
must('CAPABILITY_VERSION = "1.6.0"' in SA_SRC, "core.system_actions stays at 1.6.0 (additive)")
docs = (ROOT.parent.parent / "docs" / "system-actions.md").read_text(encoding="utf-8")
must("softwarerepository" in docs and "legacy_callers" in docs and "Only a verified Scheduler run of Communicator may call it" not in docs, "docs/system-actions.md names both callers")

print("PASS" if not FAILED else f"FAIL: {len(FAILED)} check(s)")
sys.exit(1 if FAILED else 0)

#!/usr/bin/env python3
"""1.17.120 regression: '%' in a sandbox command word is refused, fail closed (held Medium finding on 1.17.119).

systemd reads '%' in the command of a transient unit as a specifier, and whether '%%' is a safe escape depends on the systemd version, which
cannot be tested on this PC. Until the dev02 canary shows how real systemd treats it, no '%' reaches ``systemd-run``:

* registration (``registry.py``, Django-free here, and the root helper's ``parse_runners``) refuses '%' in a literal argv word, a string
  default, an enum choice and the executable path;
* ``validate_run_parameters`` refuses a string value or an enum value with '%'; ``render_command`` and ``build_argv`` refuse it again for any
  command word (python, launcher, executable, literal, rendered value), before a property or a unit exists;
* the refusal text never repeats the value (a value can be a secret);
* a value without '%' still works end to end with a real child; ``--property=`` and ``--setenv=`` items are not command words and stay as they
  are; ``server_maintenance_actions`` and the module-manager paths keep allowing '%'.

Not runnable here: real systemd.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_120d", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
sh, must, make_runner, BASE, header, start, joined, end_of = H.sh, H.must, H.make_runner, H.BASE, H.header, H.start, H.joined, H.end_of
ROOT = H.ROOT
sys.path.insert(0, str(ROOT / "framwork"))
from tec_tac import registry  # noqa: E402

SECRET = "tok%en-SECRET-1234"


def raises(call, exc, part=""):
    try:
        call()
    except exc as caught:
        text = str(caught)
        must(part in text, (part, text))
        must("SECRET-1234" not in text and SECRET not in text, ("the refusal repeats the value", text))
        return caught
    raise AssertionError(f"no {exc.__name__}: expected {part!r}")


# ---- 1. the helper's registration parser
def payload(**over):
    entry = {"id": "ai.chat", "description": "Chat", "executable": "sandbox/runners/chat.py", "argv": ["--m", {"param": "mode"}],
             "parameters": {"mode": {"type": "enum", "choices": ["a", "b"]}}}
    entry.update(over)
    return {"id": "ai", "type": "extension", "version": "1.0.0", "publisher_permissions": ["sandbox.register"],
            "requires": {"framework": ">=1.17.116"}, "sandbox_runners": [entry]}


def helper_parse(**over):
    return sh.parse_runners("ai", payload(**over), lambda *a: None)


version, runners = helper_parse()
must(len(runners) == 1, "a runner without '%' parses")
raises(lambda: helper_parse(argv=["--lit", "100%"]), RuntimeError, "'%'")
raises(lambda: helper_parse(parameters={"mode": {"type": "enum", "choices": ["a", "b%"]}}), RuntimeError, "'%'")
raises(lambda: helper_parse(parameters={"mode": {"type": "string", "default": "50%"}}), RuntimeError, "'%'")
raises(lambda: helper_parse(executable="sandbox/runners/ch%at.py"), RuntimeError, "'%'")
# a '%' inside a pattern is a regex, not a command word: it is not refused (only the value that arrives is)
must(helper_parse(parameters={"mode": {"type": "string", "pattern": "[0-9]+%?"}})[1], "'%' in a pattern is allowed at registration")

# ---- 2. validate_run_parameters, render_command and build_argv
schema = {"s": {"type": "string"}, "e": {"type": "enum", "choices": ["ok", "50%"]}, "i": {"type": "integer"}, "b": {"type": "boolean"}}
V = sh.validate_run_parameters
must(V(schema, {"s": "plain $ text", "e": "ok", "i": 5, "b": True}) == {"s": "plain $ text", "e": "ok", "i": 5, "b": True}, "no '%' works")
for name, value in (("s", SECRET), ("s", "%"), ("s", "a%%b"), ("e", "50%")):
    refusal = raises(lambda: V(schema, {name: value}), sh.Refusal, "may not contain '%'")
    must(refusal.code == "invalid_input", refusal.code)
raises(lambda: V({"s": {"type": "string", "default": "x%y"}}, {}), sh.Refusal, "may not contain '%'")
must(V({"s": {"type": "string", "default": "x%y"}}, {"s": "fine"}) == {"s": "fine"}, "a caller value replaces the default, and only it is checked")
raises(lambda: V({"s": {"type": "string", "max_length": 4}}, {"s": "ab%cdefgh"}), sh.Refusal)

RUN_ID = "cd" * 16
EXISTS = lambda path: str(path).startswith(str(BASE)) or str(path) == str(sh.LAUNCHER_FILE) or str(path).startswith("/opt/tec-tac")
row = make_runner("ai.pct", parameters={"text": {"type": "string", "max_length": 80}}, argv=["--t", {"param": "text"}])
R = lambda rw, params: sh.build_argv(rw, RUN_ID, params, credential_names=[], exists=EXISTS)
built = R(row, {"text": "a$b"})
must(built[-1] == "a$$b" and built[-2] == "--t", built[-2:])
refusal = raises(lambda: R(row, {"text": SECRET}), sh.Refusal, "'%'")  # render_command refuses a rendered word even if validation was skipped
must(refusal.code == "invalid_input", refusal.code)
for label, bad in (
    ("literal argv", dict(row, argv=["--lit", "x%y", {"param": "text"}])),
    ("executable path", dict(row, executable=row["executable"] + "%h")),
):
    raises(lambda bad=bad: R(bad, {"text": "fine"}), sh.Refusal, "'%'")
real_python, real_launcher = sh.UNIT_PYTHON, sh.LAUNCHER_FILE
try:
    sh.UNIT_PYTHON = "/usr/bin/py%thon"
    raises(lambda: R(row, {"text": "fine"}), sh.Refusal, "'%'")
finally:
    sh.UNIT_PYTHON = real_python
try:
    sh.LAUNCHER_FILE = Path(str(real_launcher) + "%x")
    raises(lambda: sh.build_argv(row, RUN_ID, {"text": "fine"}, credential_names=[], exists=lambda p: True), sh.Refusal, "'%'")
finally:
    sh.LAUNCHER_FILE = real_launcher
# options before '--' are not command words: a '%' in an environment value is a --setenv= item and is unchanged
env_row = make_runner("ai.env", environment={"MSG": "100% sure"}, argv=[])
argv = R(env_row, {})
must("--setenv=MSG=100% sure" in argv and "--" in argv, argv)
# the helper's own properties hold no '%' from caller text, and the refusal came before any property was built
built_props = []
real_props = sh.build_properties
sh.build_properties = lambda *a, **k: built_props.append(1) or real_props(*a, **k)
try:
    raises(lambda: R(dict(row, argv=["x%"]), {"text": "t"}), sh.Refusal, "'%'")
finally:
    sh.build_properties = real_props
must(built_props, "build_argv builds its properties first, then refuses; no unit is started by build_argv itself")

# ---- 3. a start: refused with invalid_input, nothing started, nothing left behind
def logs():
    folder = BASE / "log"
    return sorted(p.name for p in folder.glob("*.json")) if folder.is_dir() else []


# a value without '%' works end to end with a real child
make_runner("ai.ok", body="print(sys.argv[1:])", parameters={"text": {"type": "string", "max_length": 50}}, argv=["--t", {"param": "text"}])
code, frames = start(header("ai.ok", parameters={"text": "a$HOME b"}))
must(joined(frames, "out").decode().strip() == repr(["--t", "a$HOME b"]), joined(frames, "out"))
before = logs()
cases = [
    ("string parameter", make_runner("ai.p1", parameters={"text": {"type": "string", "max_length": 50}}, argv=[{"param": "text"}]), {"text": SECRET}),
    ("enum choice", make_runner("ai.p2", parameters={"mode": {"type": "enum", "choices": ["a%b", "c"]}}, argv=[{"param": "mode"}]), {"mode": "a%b"}),
    ("string default", make_runner("ai.p3", parameters={"text": {"type": "string", "default": "50%"}}, argv=[{"param": "text"}]), {}),
    ("literal argv", make_runner("ai.p4", argv=["--lit", "x%y"]), {}),
]
for label, _row, params in cases:
    code, frames = start(header(_row["id"], parameters=params))
    refused = [f for f in frames if f["t"] == "refused"]
    must(refused and refused[0]["code"] == "invalid_input" and "'%'" in refused[0]["message"], (label, frames))
    must("SECRET-1234" not in json.dumps(frames) and SECRET not in json.dumps(frames), (label, "the refusal repeats the value"))
    must(not [f for f in frames if f["t"] in ("out", "end")], (label, "nothing ran"))
must(logs() == before, ("no systemd-run call was made for a refused start", set(logs()) - set(before)))
must(not H.leftovers(), H.leftovers())

# ---- 4. registry.py (Django-free), against temp module folders
def entry(**over):
    value = {"id": "ai.claude", "description": "Run it", "executable": "sandbox/runners/claude.sh", "argv": ["--m", {"param": "model"}],
             "parameters": {"model": {"type": "enum", "choices": ["a", "b"]}}}
    value.update(over)
    return value


def manifest(runners):
    return {"id": "ai", "type": "extension", "version": "0.9.0", "category": "premium", "publisher_permissions": ["sandbox.register"],
            "requires": {"framework": ">=1.17.116"}, "sandbox_runners": runners}


def make_module(payload, files=("sandbox/runners/claude.sh",), module_id="ai"):
    root = Path(tempfile.mkdtemp(dir=BASE, prefix="pct-"))
    folder = root / "extensions" / module_id
    folder.mkdir(parents=True)
    for name in files:
        target = folder / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"#!/bin/sh\necho hi\n")
    (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")
    return folder


def load(payload, files=("sandbox/runners/claude.sh",)):
    return registry._load_manifest("extension", make_module(payload, files))


must(len(load(manifest([entry()])).sandbox_runners) == 1, "the plain runner registers")
for label, bad, files in (
    ("literal argv", entry(argv=["--lit", "100%"]), ("sandbox/runners/claude.sh",)),
    ("string default", entry(parameters={"model": {"type": "string", "default": "50%"}}), ("sandbox/runners/claude.sh",)),
    ("enum choice", entry(parameters={"model": {"type": "enum", "choices": ["a", "b%h"]}}), ("sandbox/runners/claude.sh",)),
    ("executable path", entry(executable="sandbox/runners/cl%aude.sh"), ("sandbox/runners/cl%aude.sh",)),
):
    try:
        load(manifest([bad]), files)
    except registry.RegistryError as exc:
        must("'%'" in str(exc), (label, str(exc)))
    else:
        raise AssertionError(f"registry accepted a '%' in {label}")

# ---- 5. compatibility: server_maintenance_actions share the parameter parser and keep allowing '%'
sm = {"id": "vendor.rotate", "description": "Rotate", "permission": "vendor.rotate", "executable": "server_maintenance/actions/rotate.sh",
      "argv": ["--fmt", "100%", {"param": "certificate_id"}],
      "parameters": {"certificate_id": {"type": "string", "required": True, "pattern": "^[A-Za-z0-9_.%-]{1,64}$", "max_length": 64, "default": "x%y"},
                     "unit": {"type": "enum", "choices": ["10%", "20%"]}},
      "timeout_seconds": 300, "success_exit_codes": [0], "revision": "1"}
sm_payload = {"id": "vendor", "type": "extension", "version": "1.2.0", "category": "server", "publisher_permissions": ["server_maintenance.register"],
              "permission_groups": {"Vendor": ["vendor.rotate"]}, "server_maintenance_actions": [sm]}
root = Path(tempfile.mkdtemp(dir=BASE, prefix="sm-"))
folder = root / "extensions" / "vendor"
(folder / "server_maintenance" / "actions").mkdir(parents=True)
(folder / "server_maintenance" / "actions" / "rotate.sh").write_bytes(b"#!/bin/sh\necho rotated\n")
(folder / "tec_tac.json").write_text(json.dumps(sm_payload), encoding="utf-8")
spec = registry._load_manifest("extension", folder)
must(spec.server_maintenance_actions and spec.server_maintenance_actions[0]["argv"][1] == "100%", "server_maintenance_actions with '%' still parse")
must(spec.server_maintenance_actions[0]["parameters"]["unit"]["choices"] == ["10%", "20%"], "enum choices with '%' still parse there")

print("[TEST] PASS sandbox percent refuse 1.17.120")

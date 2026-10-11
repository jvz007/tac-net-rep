#!/usr/bin/env python3
"""1.17.18 regression: refuse installing a disabled module up front, and say why (Johan CQ59; the patching 0.6.0 install on the dev server).

Runs the real registry.py, module_state.py, module_replacement.py and module_manager_v2.py against a temporary extensions folder, the
way tests/module-replacement-1.17.9.py does (Django is not needed; fcntl and cryptography are stubbed). Covered: the exact Windows
Patching / Advanced Patch Management sentence, the generic sentence for a module disabled by hand, no state entry and an enabled
module give None, names fall back to ids, an unreadable state gives None, queue_v2_install and queue_batch_install raise
ModuleManagerV2Error with the sentence before anything is queued, and install-extension.sh calls the check before anything is copied or
backed up (in the fresh and --replace path alike), prints it as an ERROR line and has no import_string path ahead of it. The two job
helpers surface the sentence as the job error. The live install, which needs root, systemd and Tactical, cannot run here.
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules.setdefault(name, module)


_stub("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
for _name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric"):
    _stub(_name)
_stub("cryptography.hazmat.primitives.serialization")
_stub("cryptography.hazmat.primitives.asymmetric.ed25519", Ed25519PublicKey=object)
_stub("cryptography.exceptions", InvalidSignature=Exception)

from tec_tac import capabilities, module_manager, module_manager_v2 as v2, module_replacement as mr, module_state, registry  # noqa: E402,F401
from tec_tac import module_category  # noqa: E402

module_category.is_development_server = lambda: True
logging.disable(logging.CRITICAL)
TMP = Path(tempfile.mkdtemp(prefix="tectac-disabled-install-"))
EXT, REP = TMP / "extensions", TMP / "reportsets"
EXT.mkdir()
REP.mkdir()
registry.EXTENSIONS_ROOT, registry.REPORTSETS_ROOT = EXT, REP
STATE = {"schema": 1, "modules": {}}
module_state.load_state = lambda: STATE
v2.load_state = lambda: STATE
module_manager.get_plugins = registry.get_plugins


def manifest(module_id, **extra):
    folder = EXT / module_id
    folder.mkdir(parents=True, exist_ok=True)
    payload = {"id": module_id, "type": "extension", "version": "1.0.0", "name": module_id}
    payload.update(extra)
    if "replaces" in extra:
        payload.setdefault("category", "premium")
    (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")


def reset(**state):
    for folder in list(EXT.iterdir()) + list(REP.iterdir()):
        for child in folder.iterdir():
            child.unlink()
        folder.rmdir()
    STATE["modules"] = {name: {"enabled": on} for name, on in state.items()}


CAPS = {"patching.windows": "1.2.0"}
WP, APM = "Windows Patching", "Advanced Patch Management"
SENTENCE = f"{WP} is disabled because {APM} replaces it. Disable {APM} and enable {WP}, then install again."


def world(patching=False, pm=True):
    reset(patching=patching, patchmanagement=pm)
    manifest("patching", category="core", name=WP, capabilities=CAPS)
    manifest("patchmanagement", replaces="patching", name=APM, capabilities=CAPS)


# ---- the exact sentence for a replaced module
world(patching=False, pm=True)
must(mr.disabled_install_refusal("patching") == SENTENCE, mr.disabled_install_refusal("patching"))
must(mr.disabled_install_refusal("patching", "Windows Patching (new build)").startswith("Windows Patching (new build) is disabled because"), "the incoming manifest name wins")
must("\n" not in mr.disabled_install_refusal("patching", "Line\nBreak") and mr.disabled_install_refusal("patching", "Line\nBreak").startswith("Line Break is disabled"), "one plain line")
# the replacement itself is enabled: nothing to refuse
must(mr.disabled_install_refusal("patchmanagement") is None, "an enabled module installs")

# ---- disabled by hand: the generic sentence (the replacement is not enabled, so it is not honoured)
world(patching=False, pm=False)
must(mr.disabled_install_refusal("patching") == f"{WP} is disabled. Enable it, then install again.", mr.disabled_install_refusal("patching"))
must(mr.disabled_install_refusal("patchmanagement") == f"{APM} is disabled. Enable it, then install again.", "a disabled replacement")
# a module with no replacement, disabled
reset(plain=False)
manifest("plain", category="core", name="Plain Module")
must(mr.disabled_install_refusal("plain") == "Plain Module is disabled. Enable it, then install again.", mr.disabled_install_refusal("plain"))
# the replacement does not cover the capabilities: not honoured, so the generic sentence
reset(patching=False, patchmanagement=True)
manifest("patching", category="core", name=WP, capabilities={"patching.windows": "1.2.0", "patching.scan": "1.0.0"})
manifest("patchmanagement", replaces="patching", name=APM, capabilities={"patching.windows": "1.2.0"})
must(mr.disabled_install_refusal("patching") == f"{WP} is disabled. Enable it, then install again.", "a replacement that is not honoured is not named")

# ---- names fall back to ids; a module that is no longer installed but has a state entry
reset(ghost=False)
must(mr.disabled_install_refusal("ghost") == "ghost is disabled. Enable it, then install again.", mr.disabled_install_refusal("ghost"))
manifest("noname", category="core")
(EXT / "noname" / "tec_tac.json").write_text(json.dumps({"id": "noname", "type": "extension", "version": "1.0.0", "category": "core"}), encoding="utf-8")
STATE["modules"]["noname"] = {"enabled": False}
must(mr.disabled_install_refusal("noname") == "noname is disabled. Enable it, then install again.", "the id is the fallback name")

# ---- None: first install (no state entry), enabled, state with only a visibility entry, bad ids, a state that cannot be read
world(patching=False, pm=True)
STATE["modules"].pop("patching")
must(mr.disabled_install_refusal("patching") is None, "no state entry: a first install")
STATE["modules"]["patching"] = {"visible": False}
must(mr.disabled_install_refusal("patching") is None, "a visibility-only entry is enabled")
STATE["modules"]["patching"] = {"enabled": True}
must(mr.disabled_install_refusal("patching") is None, "enabled")
for bad in (None, "", "   "):
    must(mr.disabled_install_refusal(bad) is None, bad)
STATE["modules"]["patching"] = {"enabled": False}
saved = dict(STATE)
STATE.clear()
STATE.update({"_corrupt": True, "modules": {"patching": {"enabled": False}}})
must(mr.disabled_install_refusal("patching") is None, "a corrupt state says nothing (the later steps handle it)")
STATE.clear()
STATE.update(saved)
module_state.load_state = lambda: (_ for _ in ()).throw(RuntimeError("state unreadable"))
must(mr.disabled_install_refusal("patching") is None, "a failing check never raises")
module_state.load_state = lambda: STATE
must(mr.disabled_install_refusal("patching") == SENTENCE, "and works again")

# ---- queue_v2_install and queue_batch_install refuse before anything is queued
QUEUED = []
v2._queue_v2 = lambda payload: QUEUED.append(payload) or {"id": "job"}
module_manager.queue_install = lambda *a, **k: QUEUED.append(("v1", a, k)) or {"id": "job1"}
PREVIEW = {"id": "patching", "name": "Windows Patching 0.6.0", "extension_version": "0.6.0", "installable": True, "publisher_permissions": []}
v2._load_stage = lambda upload_id: {"package_path": "/staged/patching.zip", "sha256": "x", "upload_id": upload_id}
v2._package_metadata = lambda path: dict(PREVIEW)
v2._verify_stage_trust = lambda *a, **k: (_ for _ in ()).throw(AssertionError("the refusal comes before the trust check"))
world(patching=False, pm=True)
for queue in (v2.queue_v2_install, v2.queue_batch_install):
    v2._load_batch = lambda batch_id: {"artifacts": [{"kind": "package", "upload_id": "u1"}]}
    QUEUED.clear()
    try:
        queue("u1", None, "tech", None, None)
        raise AssertionError(f"{queue.__name__} accepted a disabled module")
    except v2.ModuleManagerV2Error as exc:
        must(str(exc) == SENTENCE.replace(WP, "Windows Patching 0.6.0"), str(exc))
    must(not QUEUED, "nothing was queued")
# a bundle child
v2._load_batch = lambda batch_id: {"artifacts": [{"kind": "bundle", "upload_id": "b1"}]}
v2._load_bundle = lambda upload_id: {"bundle_path": "/staged/b.zip", "filename": "b.zip"}
v2._inspect_bundle = lambda path: {"id": "suite", "packages": [dict(PREVIEW, id="other"), dict(PREVIEW)]}
v2._verify_stage_trust = lambda *a, **k: {"state": "unsigned"}
try:
    v2.queue_batch_install("b1", None, "tech", None, None)
    raise AssertionError("a bundle with a disabled child was accepted")
except v2.ModuleManagerV2Error as exc:
    must("is disabled because" in str(exc) and "install again." in str(exc), str(exc))
# an enabled module passes the new check (the rest of the flow is not run here)
world(patching=True, pm=False)
v2._refuse_disabled_install(dict(PREVIEW))
v2._refuse_disabled_install({"id": "brand-new"})

# ---- install-extension.sh
script = (ROOT / "scripts/install-extension.sh").read_text(encoding="utf-8")
subprocess_ok = subprocess.run(["bash", "-n", str(ROOT / "scripts/install-extension.sh")], capture_output=True, text=True) if os.name != "nt" else None
if subprocess_ok is not None:
    must(subprocess_ok.returncode == 0, subprocess_ok.stderr)
call = script.index("disabled_install_refusal")
discovery = script.index('DISCOVERY="$(')
installed_check = script.index("is already installed. Re-run with --replace")
first_copy = script.index('cp -a "${SOURCE_EXTENSION}"')
backup = script.index('BACKUP_DIR=""')
backup_mkdir = script.index('mkdir -p "${BACKUP_DIR}/extensions"')
live_copy = script.index('cp -a "${STAGE_ROOT}/extensions/${PLUGIN_ID}" "${DEST_EXTENSION}"')
must(discovery < installed_check < call < first_copy < backup < backup_mkdir < live_copy, "the check runs after discovery and the already-installed check, before any copy, backup or install")
before = script[:call]
must("import_string" not in before and "runuser" not in before and "call_command" not in before, "no Django or Tactical step ahead of the check")
must(not re.search(r'^\s*(cp|mv|rm|mkdir)\b', script[installed_check:call], re.M), "nothing is copied, moved or removed between the already-installed check and the refusal")
block = script[call - 700:call + 900]
must('"${SYSTEM_PYTHON}" -I -' in block and '"${FRAMEWORK_DIR}"' in block and '"${PLUGIN_ID}"' in block, "python -I with the framework dir, like the registry step")
must('fail "${DISABLED_REFUSAL}"' in script, "printed through fail: [TEC-TAC] ERROR: <message>, exit 1, no traceback")
must("log()  { printf '[TEC-TAC] %s\\n' \"$*\"; }" in script and "fail() { printf '[TEC-TAC] ERROR: %s\\n' \"$*\" >&2; exit 1; }" in script, "fail prints the ERROR line")
# the python block of the script, run in this process against the harness
snippet = script.split('DISABLED_REFUSAL="$(', 1)[1].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
world(patching=False, pm=True)


def run_snippet(name="-", module="patching"):
    out = io.StringIO()
    saved_argv = sys.argv
    sys.argv = ["-", str(ROOT / "framwork"), module, name]
    try:
        with contextlib.redirect_stdout(out):
            exec(compile(snippet, "install-extension.sh (snippet)", "exec"), {"__name__": "__main__"})
    finally:
        sys.argv = saved_argv
    return out.getvalue().strip()


must(run_snippet() == SENTENCE, run_snippet())
must(run_snippet("Windows Patching 0.6.0").startswith("Windows Patching 0.6.0 is disabled because"), "the package name is passed")
must(run_snippet(module="patchmanagement") == "", "an enabled module prints nothing")
must(run_snippet(module="brand-new") == "", "a first install prints nothing")
module_state.load_state = lambda: (_ for _ in ()).throw(RuntimeError("broken"))
must(run_snippet() == "", "a failing check prints nothing and never a traceback")
module_state.load_state = lambda: STATE
# discovery prints the manifest name as a sixth line, and the script reads it
must('PACKAGE_NAME="${DISCOVERY_LINES[5]:--}"' in script and 'print(" ".join(str(ext_payload.get("name", "") or "").split()) or "-")' in script, "package name from the manifest")

# ---- the job helpers surface the sentence
for helper_name in ("module-job-helper.py", "module-v2-job-helper.py"):
    text = (ROOT / "scripts" / helper_name).read_text(encoding="utf-8")
    tree = ast.parse(text)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "installer_refusal")
    pattern = next(n for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "_INSTALLER_REFUSAL" for t in n.targets))
    env = {"re": re, "os": os, "Path": Path}
    exec(compile(ast.Module(body=[pattern, fn], type_ignores=[]), helper_name, "exec"), env)
    surface = env["installer_refusal"]
    log = TMP / f"{helper_name}.log"
    log.write_text("[TEC-TAC] Package extension ID: patching\n[TEC-TAC] ERROR: " + SENTENCE + "\n", encoding="utf-8")
    must(surface(log) == SENTENCE, (helper_name, surface(log)))
    log.write_text(f"[TEC-TAC] ERROR: {WP} is disabled. Enable it, then install again.\n", encoding="utf-8")
    must(surface(log) == f"{WP} is disabled. Enable it, then install again.", "the generic sentence")
    for other in ("[TEC-TAC] ERROR: Run this installer as root.\n", "[TEC-TAC] ERROR: unsafe archive path: 'x'\n", "x [TEC-TAC] ERROR: a is disabled. Enable it, then install again.\n", "", "Traceback (most recent call last):\n"):
        log.write_text(other, encoding="utf-8")
        must(surface(log) is None, (helper_name, other))
    must(surface(TMP / "missing.log") is None and surface(None) is None, "no log, no sentence")
    big = TMP / "big.log"
    big.write_text("[TEC-TAC] ERROR: " + SENTENCE + "\n" + "x" * 40000 + "\n", encoding="utf-8")
    must(surface(big) is None, "only the tail of the log is read")
    must("installer_refusal(" in text, "the helper uses it")
v1 = (ROOT / "scripts/module-job-helper.py").read_text(encoding="utf-8")
must('job["error_type"] = "ModuleDisabled"' in v1 and 'refusal = installer_refusal(log_path)' in v1, "the v1 helper sets the job error")
must(v1.index("installer_refusal(log_path)") < v1.index('job["status"] = "failed"'), "before the failed status is written")
must("if rc != 0 and job[\"action\"] == \"install\" and not job.get(\"error\")" in v1, "only an install failure that has no other reason")
v2h = (ROOT / "scripts/module-v2-job-helper.py").read_text(encoding="utf-8")
must("raise RuntimeError(refusal)" in v2h and v2h.index("installer_refusal(getattr(log") < v2h.index('raise RuntimeError(f"install failed for {module_id}'), "the v2 helper raises the sentence first")

print("[TEST] PASS installer refuses a disabled module 1.17.18")

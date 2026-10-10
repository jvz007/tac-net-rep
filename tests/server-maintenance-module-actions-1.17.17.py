#!/usr/bin/env python3
"""1.17.17 regression: a signed module registers its own Core server-maintenance actions from its manifest (item F2).

New manifest key ``server_maintenance_actions`` (extensions only, at most 16 entries). Covered here:

* registry.py: the key parses into ``PluginSpec.server_maintenance_actions`` and is refused for a wrong id prefix, an absolute or
  ``..`` executable, a symlink, an undeclared permission, a missing publisher_permissions ``server_maintenance.register``, more than 16
  entries, a reportset, an unknown entry key and shell-looking argv;
* scripts/server-maintenance-helper.py ``--register-module`` / ``--unregister-module``: the executable is copied root-owned 0755 into the
  Core action root with its SHA-256, the registry file carries owner_module and permission, an upgrade drops what the manifest dropped,
  one module never touches another's, a tampered executable fails at dispatch and run, an untrusted manifest or executable is refused,
  and a ``protected: true`` entry is not registered;
* scripts/module-v2-job-helper.py and scripts/module-job-helper.py: install registers after the sync, uninstall unregisters, a failed
  install restores and re-registers or unregisters, a registration failure fails the job with a plain message, and a module that declares
  nothing is not touched when the Core helper is not there;
* the sudoers text: ``--register-module`` and ``--unregister-module`` are not reachable through the Tactical account's sudo rule.

What cannot run here: the helper as root (chown, systemd dispatch, sudo), a signed install of a real module on the dev server. The
os-level owner, mode and symlink answers are produced by a fake file system layer that is limited to this test's temp folders; the rule
that reads them (``_untrusted``) is tested on its own. See tests/server-maintenance-module-actions-runtime-1.17.17.py (dev server only).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
HARNESS = Path(__file__).resolve().parent / "module-replacement-helper-handback-1.17.12.py"
_source = HARNESS.read_text(encoding="utf-8")
G = {"__name__": "stubs", "__file__": str(HARNESS)}
# stubs for fcntl, pwd and cryptography, the os shims and the v2 job helper loaded as ``helper`` (the 1.17.13 tests do the same)
exec(compile(_source[: _source.index("# ------------------------------------------------------------------------------------------ CQ32: enable switches the replacement off")], str(HARNESS), "exec"), G)
must, ROOT = G["must"], G["ROOT"]
v2 = G["helper"]
APP = ROOT / "framwork" / "tec_tac"
sys.modules.setdefault("grp", types.ModuleType("grp"))
from tec_tac import registry  # noqa: E402

BASE = Path(tempfile.mkdtemp(prefix="tectac-sm-actions-"))


# ------------------------------------------------------------------------------------------------ registry.py
def action(action_id="vendor.rotate", exe="rotate.sh", **over):
    entry = {
        "id": action_id, "description": "Rotate a certificate", "permission": "vendor.rotate",
        "executable": f"server_maintenance/actions/{exe}", "argv": ["--id", {"param": "certificate_id"}],
        "parameters": {"certificate_id": {"type": "string", "required": True, "pattern": "^[A-Za-z0-9_.-]{1,64}$", "max_length": 64}},
        "timeout_seconds": 300, "success_exit_codes": [0], "revision": "1",
    }
    entry.update(over)
    return entry


def manifest(actions=None, **over):
    payload = {
        "id": "vendor", "type": "extension", "version": "1.2.0", "category": "server",
        "publisher_permissions": ["server_maintenance.register"],
        "permission_groups": {"Vendor": ["vendor.rotate", "vendor.other", "vendor.danger"]},
        "server_maintenance_actions": [action()] if actions is None else actions,
    }
    payload.update(over)
    return {key: value for key, value in payload.items() if value is not None}


def make_module(root: Path, module_id="vendor", payload=None, files=("rotate.sh",), kind="extensions", content=b"#!/bin/sh\necho rotated\n"):
    folder = root / kind / module_id
    (folder / "server_maintenance" / "actions").mkdir(parents=True, exist_ok=True)
    for name in files:
        target = folder / "server_maintenance" / "actions" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    (folder / "tec_tac.json").write_text(json.dumps(payload if payload is not None else manifest()), encoding="utf-8")
    return folder


def parse(payload, files=("rotate.sh",), kind="extension", module_id="vendor"):
    root = Path(tempfile.mkdtemp(dir=BASE, prefix="reg-"))
    folder = make_module(root, module_id, payload, files, kind="extensions" if kind == "extension" else "reportsets")
    return registry._load_manifest(kind, folder)


def refused(payload, part, **kw):
    try:
        parse(payload, **kw)
    except registry.RegistryError as exc:
        must(part in str(exc), (part, str(exc)))
        return
    raise AssertionError(f"manifest accepted, expected {part!r}: {json.dumps(payload)[:300]}")


spec = parse(manifest([action(), action("vendor.other", "sub/other.sh", permission="vendor.other", protected=True)]), files=("rotate.sh", "sub/other.sh"))
must("server_maintenance_actions" in registry.SUPPORTED_KEYS, "key supported")
must(len(spec.server_maintenance_actions) == 2 and spec.server_maintenance_actions[0]["id"] == "vendor.rotate", spec.server_maintenance_actions)
first = spec.server_maintenance_actions[0]
must(first["permission"] == "vendor.rotate" and first["executable"] == "server_maintenance/actions/rotate.sh" and first["protected"] is False, first)
must(first["argv"] == ["--id", {"param": "certificate_id"}] and first["timeout_seconds"] == 300 and first["success_exit_codes"] == [0], first)
must(spec.server_maintenance_actions[1]["protected"] is True, "protected is kept")
must(isinstance(hash(spec), int), "a spec with actions is still hashable")
# defaults: only id, permission and executable are needed
minimal = parse(manifest([{"id": "vendor.rotate", "permission": "vendor.rotate", "executable": "server_maintenance/actions/rotate.sh"}]))
entry = minimal.server_maintenance_actions[0]
must(entry["argv"] == [] and entry["parameters"] == {} and entry["timeout_seconds"] == 3600 and entry["success_exit_codes"] == [0] and entry["revision"] == "1" and entry["description"] == "", entry)
# absent, empty: no actions, and a module that declares none is untouched by the rule
must(parse(manifest(None, server_maintenance_actions=None)).server_maintenance_actions == (), "absent")
must(parse(manifest([], publisher_permissions=None)).server_maintenance_actions == (), "an empty array needs no publisher permission")

refused(manifest([action("other.rotate")]), "must begin with the module ID prefix")
refused(manifest([action("vendor.")]), "must begin with the module ID prefix")
refused(manifest([action("vendorx.rotate")]), "must begin with the module ID prefix")
refused(manifest([action(), action()]), "more than once")
refused(manifest([action(permission="vendor.undeclared")]), "permission that this module declares")
refused(manifest([action(permission="other.rotate")]), "permission that this module declares")
refused(manifest([{k: v for k, v in action().items() if k != "permission"}]), "permission that this module declares")
refused(manifest(publisher_permissions=None), "publisher_permissions")
refused(manifest(publisher_permissions=["module.install"]), "server_maintenance.register")
refused(manifest([action(f"vendor.a{i}", permission="vendor.rotate") for i in range(17)]), "more than 16")
# 16 is allowed
sixteen = parse(manifest([action(f"vendor.a{i}") for i in range(16)]))
must(len(sixteen.server_maintenance_actions) == 16, "16 entries")
refused(manifest("nope"), "must be a JSON array")
refused(manifest(["nope"]), "must be a JSON object")
refused(manifest([action(colour="red")]), "unsupported keys")
for bad_exe in ("/etc/passwd", "/usr/bin/id", "C:/x.sh", "server_maintenance/actions/../../tec_tac.json", "server_maintenance/actions/..", "server_maintenance/actions/./a.sh",
                "server_maintenance/actions//a.sh", "server_maintenance/actions/", "server_maintenance/actions", "rotate.sh", "other/rotate.sh",
                "server_maintenance\\actions\\rotate.sh", "server_maintenance/actions/a\x00b.sh", "", 5, None, ["rotate.sh"]):
    refused(manifest([action(executable=bad_exe)]), "executable")
refused(manifest([action(exe="missing.sh")]), "does not exist")
for bad_argv in ("--x", ["--x", 5], [{"param": "nope"}], [{"param": "certificate_id", "extra": 1}], [["a"]], ["a\x00b"], ["x" * 4097], ["a"] * 65, [{"flag": "x"}]):
    refused(manifest([action(argv=bad_argv)]), "argv")
for bad_params in ("x", {"a b": {"type": "string"}}, {"p": "string"}, {"p": {"type": "float"}}, {"p": {"type": "enum"}}, {"p": {"type": "enum", "choices": []}}, {"p": {"type": "string", "pattern": "("}},
                   {f"p{i}": {"type": "string"} for i in range(65)}):
    refused(manifest([action(parameters=bad_params, argv=[])]), "parameter")
for bad_timeout in (0, -1, 7 * 24 * 60 * 60 + 1, "300", 1.5, True):
    refused(manifest([action(timeout_seconds=bad_timeout)]), "timeout_seconds")
for bad_codes in ([], "0", [0, "1"], [True], None):
    refused(manifest([action(success_exit_codes=bad_codes)]), "success_exit_codes")
refused(manifest([action(protected="yes")]), "protected")
refused(manifest([action(description="x" * 501)]), "description")
refused(manifest([action(description="a\nb")]), "description")
refused(manifest([action(revision="")]), "revision")
# a reportset may not declare it
refused({"id": "vendor", "type": "reportset", "version": "1.0.0", "server_maintenance_actions": [action()]}, "may not declare server_maintenance_actions", kind="reportset")
# a symlink: the executable itself, or a folder on the way (reported by Path.is_symlink, so this runs where a symlink cannot be made)
_real_is_symlink, LINKS = Path.is_symlink, set()
Path.is_symlink = lambda self: str(self) in LINKS or _real_is_symlink(self)
try:
    root = Path(tempfile.mkdtemp(dir=BASE, prefix="reg-link-"))
    folder = make_module(root, files=("rotate.sh",))
    for linked in (folder / "server_maintenance" / "actions" / "rotate.sh", folder / "server_maintenance" / "actions", folder / "server_maintenance"):
        LINKS.clear()
        LINKS.add(str(linked))
        try:
            registry._load_manifest("extension", folder)
            raise AssertionError(f"a symlink at {linked.name} was accepted")
        except registry.RegistryError as exc:
            must("symlink" in str(exc), exc)
    LINKS.clear()
    must(len(registry._load_manifest("extension", folder).server_maintenance_actions) == 1, "no symlink: accepted")
finally:
    Path.is_symlink = _real_is_symlink

# ------------------------------------------------------------------------------------------------ the root helper
for _shim, _value in (("getgid", lambda: 0),):
    if not hasattr(os, _shim):
        setattr(os, _shim, _value)
HELPER = ROOT / "scripts" / "server-maintenance-helper.py"
sm = types.ModuleType("sm_helper_f2")
sm.__file__ = str(HELPER)
exec(compile(HELPER.read_text(encoding="utf-8"), str(HELPER), "exec"), sm.__dict__)
sm.print = lambda *a, **k: None   # the helper prints the registered ids for the job log

EXT, REG, ACT, STATE = BASE / "ext", BASE / "reg", BASE / "act", BASE / "state"
for folder in (EXT, REG, ACT, STATE):
    folder.mkdir()
sm._ROOT_LAYOUT_ERROR = None
sm.EXTENSIONS_ROOT, sm.REGISTRY_ROOT, sm.ACTION_ROOT = EXT, REG, ACT
sm.STATE_ROOT = STATE
sm.JOBS_ROOT, sm.CANCEL_ROOT, sm.LOGS_ROOT, sm.RUNNING_ROOT = STATE / "jobs", STATE / "cancel-requests", STATE / "logs", STATE / "running"
sm.AUDIT_FILE, sm.LOCK_FILE = STATE / "audit.jsonl", STATE / "server-maintenance.lock"


def norm(path):
    return os.path.normcase(os.path.abspath(str(path)))


NOTROOT, WRITABLE, SYMLINKS, FD_PATH = set(), set(), set(), {}
CHMODS, CHOWNS, REPLACED = {}, {}, []
_real = {name: getattr(os, name) for name in ("stat", "lstat", "fstat", "open", "chmod", "replace", "geteuid")}
_real["chown"] = getattr(os, "chown", None)


_VISIBLE = ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime")


def _fake(st, path, *, link=False):
    key = norm(path)
    kind = stat.S_IFLNK if (link and key in SYMLINKS) else stat.S_IFMT(st.st_mode)
    perms = 0o755 if stat.S_ISDIR(st.st_mode) else 0o644
    if key in WRITABLE:
        perms |= 0o020
    fields = list(st)[:10]
    fields[0], fields[4] = kind | perms, (1000 if key in NOTROOT else 0)
    extras = {name: getattr(st, name) for name in dir(st) if name.startswith("st_") and name not in _VISIBLE}
    return os.stat_result(fields, extras)


def _open(path, flags, *a, **k):
    fd = _real["open"](path, flags, *a, **k)
    FD_PATH[fd] = norm(path)
    return fd


def _replace(src, dst, *a, **k):
    _real["replace"](src, dst, *a, **k)
    CHMODS[norm(dst)], CHOWNS[norm(dst)] = CHMODS.get(norm(src)), CHOWNS.get(norm(src))
    REPLACED.append(norm(dst))


def _chmod(path, mode, *a, **k):
    CHMODS[norm(path)] = mode
    try:
        _real["chmod"](path, mode)
    except OSError:
        pass


os.stat = lambda path, *a, **k: _fake(_real["stat"](path, *a, **k), path)
os.lstat = lambda path, *a, **k: _fake(_real["lstat"](path, *a, **k), path, link=True)
os.fstat = lambda fd: _fake(_real["fstat"](fd), FD_PATH.get(fd, "?"))
os.open, os.replace, os.chmod = _open, _replace, _chmod
os.chown = lambda path, uid, gid, *a, **k: CHOWNS.__setitem__(norm(path), (uid, gid))
os.geteuid = lambda: 0
os.fchown = lambda *a, **k: None
os.fchmod = lambda *a, **k: None


def put_module(module_id, payload, files=("rotate.sh",), content=b"#!/bin/sh\necho rotated\n"):
    folder = EXT / module_id
    if folder.exists():
        import shutil
        shutil.rmtree(folder)
    make_module(BASE / "stage", module_id, payload, files, content=content)
    import shutil
    shutil.copytree(BASE / "stage" / "extensions" / module_id, folder)
    shutil.rmtree(BASE / "stage" / "extensions" / module_id)
    return folder


def audit_events():
    path = sm.AUDIT_FILE
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.is_file() else []


def reg_file(action_id):
    return REG / f"{action_id}.json"


def reg_json(action_id):
    return json.loads(reg_file(action_id).read_text(encoding="utf-8"))


def fails(call, part):
    try:
        call()
    except RuntimeError as exc:
        must(part in str(exc), (part, str(exc)))
        return
    raise AssertionError(f"accepted, expected {part!r}")


try:
    # ---- the owner and mode rule on its own
    must(sm._untrusted(types.SimpleNamespace(st_uid=0, st_mode=0o100644)) is False and sm._untrusted(types.SimpleNamespace(st_uid=0, st_mode=0o100755)) is False, "root 0644 and 0755 are trusted")
    for uid, mode in ((1000, 0o100644), (0, 0o100664), (0, 0o100646), (0, 0o100666), (1000, 0o100755)):
        must(sm._untrusted(types.SimpleNamespace(st_uid=uid, st_mode=mode)) is True, (uid, oct(mode)))

    # ---- register: the executable is copied root-owned 0755 with its hash, the registry file names the owner
    content = b"#!/bin/sh\necho rotated\n"
    put_module("vendor", manifest([action(), action("vendor.other", "sub/other.sh", permission="vendor.other"),
                                   action("vendor.danger", "danger.sh", permission="vendor.danger", protected=True)]),
               files=("rotate.sh", "sub/other.sh", "danger.sh"), content=content)
    sm.register_module("vendor")
    copied = ACT / "vendor" / "rotate.sh"
    must(copied.read_bytes() == content and (ACT / "vendor" / "sub" / "other.sh").read_bytes() == content, "copied")
    must(CHMODS[norm(copied)] == 0o755 and CHOWNS[norm(copied)] == (0, 0), (CHMODS.get(norm(copied)), CHOWNS.get(norm(copied))))
    must(CHMODS[norm(ACT / "vendor")] == 0o755 and CHOWNS[norm(ACT / "vendor")] == (0, 0), "the module's action folder is root-owned 0755")
    rotate = reg_json("vendor.rotate")
    digest = hashlib.sha256(content).hexdigest()
    must(rotate["executable_sha256"] == digest and rotate["owner_module"] == "vendor" and rotate["permission"] == "vendor.rotate", rotate)
    must(rotate["executable"] == str(copied.resolve()) or norm(rotate["executable"]) == norm(copied), rotate["executable"])
    must(norm(rotate["executable"]).startswith(norm(ACT)) and not norm(rotate["executable"]).startswith(norm(EXT)), "never executes from the module folder")
    must(rotate["registered_by"] == "module-manifest" and rotate["owner_version"] == "1.2.0" and rotate["enabled"] is True and rotate["revision"] == "1", rotate)
    must(rotate["argv"] == ["--id", {"param": "certificate_id"}] and rotate["timeout_seconds"] == 300 and rotate["success_exit_codes"] == [0], rotate)
    must(CHMODS[norm(reg_file("vendor.rotate"))] == 0o644 and CHOWNS[norm(reg_file("vendor.rotate"))] == (0, 0), "the registry file is root-owned 0644")
    must(reg_json("vendor.other")["executable_sha256"] == digest, "second action")
    must(not reg_file("vendor.danger").exists() and not (ACT / "vendor" / "danger.sh").exists(), "protected: true is not registered")
    events = [(e["event"], e["detail"].get("action")) for e in audit_events()]
    must(("action.registered", "vendor.rotate") in events and ("action.registered", "vendor.other") in events and ("action.skipped_protected", "vendor.danger") in events, events)
    must(any(e["event"] == "module.actions_registered" and e["detail"]["module"] == "vendor" for e in audit_events()), "a summary row")
    registered_row = next(e for e in audit_events() if e["event"] == "action.registered")
    must(registered_row["detail"]["module"] == "vendor" and registered_row["detail"]["module_version"] == "1.2.0" and registered_row["detail"]["executable_sha256"] == digest, registered_row)
    # the dispatch path accepts it and its hash matches
    must(sm.load_action("vendor.rotate")["owner_module"] == "vendor", "loads with a matching hash")

    # ---- an administrator's hand registration, with no hash, is checked as before
    manual_exe = ACT / "manual-action"
    manual_exe.write_bytes(b"#!/bin/sh\n")
    (REG / "manual.echo.json").write_text(json.dumps({"id": "manual.echo", "revision": "1", "executable": str(manual_exe), "argv": [], "parameters": {}, "timeout_seconds": 5,
                                                       "success_exit_codes": [0], "enabled": True}), encoding="utf-8")
    must(sm.load_action("manual.echo")["id"] == "manual.echo" and "executable_sha256" not in sm.load_action("manual.echo"), "hand registration unchanged")

    # ---- a tampered executable fails at dispatch and at run
    copied.write_bytes(b"#!/bin/sh\necho TAMPERED\n")
    fails(lambda: sm.load_action("vendor.rotate"), "SHA-256")
    jid = "88888888-8888-4888-8888-888888888888"
    sm.JOBS_ROOT.mkdir(parents=True, exist_ok=True)
    sm.RUNNING_ROOT.mkdir(parents=True, exist_ok=True)
    sm.LOGS_ROOT.mkdir(parents=True, exist_ok=True)
    job = {"schema": 1, "id": jid, "action": "vendor.rotate", "action_revision": "1", "status": "queued", "stage": "queued", "created_at": "2026-10-10T00:00:00+00:00", "started_at": None,
           "finished_at": None, "cancel_requested_at": None, "context": {"source_module": "t", "source_action": "t.run", "requested_by": "tester"},
           "parameters": {"certificate_id": "abc"}, "public_parameters": {"certificate_id": "abc"}, "lock": {"scope": "global", "state": "pending", "acquired_at": None},
           "exit_result": None, "failure": None}
    (sm.JOBS_ROOT / f"{jid}.json").write_text(json.dumps(job), encoding="utf-8")
    fails(lambda: sm.dispatch(jid), "SHA-256")
    failed = json.loads((sm.JOBS_ROOT / f"{jid}.json").read_text(encoding="utf-8"))
    must(failed["status"] == "failed" and failed["failure"]["classification"] == "validation_failed" and "SHA-256" in failed["failure"]["message"], failed)
    # run_job re-checks too (a claimed job that is already dispatched)
    jid2 = "99999999-9999-4999-8999-999999999999"
    claimed = sm.claimed_dir(jid2)
    claimed.mkdir(parents=True)
    sm.claimed_job_path(jid2).write_text(json.dumps({**job, "id": jid2, "status": "dispatched", "stage": "dispatched"}), encoding="utf-8")
    fails(lambda: sm.run_job(jid2), "SHA-256")
    # a registry file whose hash was removed fails closed; one with a wrong hash does too
    payload = reg_json("vendor.other")
    (reg_file("vendor.other")).write_text(json.dumps({k: v for k, v in payload.items() if k != "executable_sha256"}), encoding="utf-8")
    fails(lambda: sm.load_action("vendor.other"), "executable_sha256")
    (reg_file("vendor.other")).write_text(json.dumps({**payload, "executable_sha256": "0" * 64}), encoding="utf-8")
    fails(lambda: sm.load_action("vendor.other"), "SHA-256")
    (reg_file("vendor.other")).write_text(json.dumps({**payload, "executable_sha256": "not-a-hash"}), encoding="utf-8")
    fails(lambda: sm.load_action("vendor.other"), "executable_sha256")
    # registering again repairs both
    sm.register_module("vendor")
    must(sm.load_action("vendor.rotate")["executable_sha256"] == digest and sm.load_action("vendor.other")["executable_sha256"] == digest, "re-registered")

    # ---- an upgrade replaces the executable and drops what the manifest dropped
    new_content = b"#!/bin/sh\necho rotated v2\n"
    put_module("vendor", manifest([action(revision="2")], version="1.3.0"), files=("rotate.sh",), content=new_content)
    sm.register_module("vendor")
    must(copied.read_bytes() == new_content and reg_json("vendor.rotate")["executable_sha256"] == hashlib.sha256(new_content).hexdigest(), "replaced")
    must(reg_json("vendor.rotate")["owner_version"] == "1.3.0" and reg_json("vendor.rotate")["revision"] == "2", "new version and revision")
    must(not reg_file("vendor.other").exists() and not (ACT / "vendor" / "sub").exists(), "the dropped action and its executable are gone")
    must(any(e["event"] == "action.unregistered" and e["detail"].get("action") == "vendor.other" and e["detail"]["module"] == "vendor" for e in audit_events()), "audit of the drop")
    must((REG / "manual.echo.json").is_file() and manual_exe.is_file(), "another registration is untouched")
    # a manifest that no longer declares the key drops all of the module's actions
    put_module("vendor", manifest(None, server_maintenance_actions=None), files=("rotate.sh",))
    sm.register_module("vendor")
    must(not reg_file("vendor.rotate").exists() and not (ACT / "vendor" / "rotate.sh").exists(), "no key: nothing stays registered")

    # ---- protected: an hand-registered one stays, one an earlier version registered from the manifest is dropped
    put_module("vendor", manifest([action(), action("vendor.danger", "danger.sh", permission="vendor.danger")]), files=("rotate.sh", "danger.sh"))
    sm.register_module("vendor")
    must(reg_file("vendor.danger").is_file(), "registered while not protected")
    put_module("vendor", manifest([action(), action("vendor.danger", "danger.sh", permission="vendor.danger", protected=True)]), files=("rotate.sh", "danger.sh"))
    sm.register_module("vendor")
    must(not reg_file("vendor.danger").exists() and not (ACT / "vendor" / "danger.sh").exists(), "now protected: no longer auto-registered")
    manual = {"id": "vendor.danger", "revision": "1", "executable": str(manual_exe), "argv": [], "parameters": {}, "timeout_seconds": 5, "success_exit_codes": [0], "enabled": True,
              "owner_module": "vendor", "permission": "vendor.danger"}
    reg_file("vendor.danger").write_text(json.dumps(manual), encoding="utf-8")
    sm.register_module("vendor")
    must(reg_file("vendor.danger").is_file() and reg_json("vendor.danger") == manual, "a hand registration of a protected action stays")
    reg_file("vendor.danger").unlink()

    # ---- another module: register, then unregister vendor and nothing of the other module's goes
    put_module("other", manifest([action("other.run", "run.sh", permission="other.run")], id="other", permission_groups={"Other": ["other.run"]}), files=("run.sh",))
    sm.register_module("other")
    must(reg_file("other.run").is_file() and (ACT / "other" / "run.sh").is_file() and reg_file("vendor.rotate").is_file(), "both registered")
    sm.unregister_module("vendor")
    must(not reg_file("vendor.rotate").exists() and not (ACT / "vendor").exists(), "vendor's actions and folder are gone")
    must(reg_file("other.run").is_file() and (ACT / "other" / "run.sh").is_file() and (REG / "manual.echo.json").is_file() and manual_exe.is_file(), "nothing of another module's, nor the hand registration")
    must(any(e["event"] == "action.unregistered" and e["detail"].get("module") == "vendor" for e in audit_events()), "audit of the removal")
    sm.unregister_module("vendor")   # a second call is harmless
    sm.unregister_module("never-installed")
    # unregister removes everything the module owns, however it was registered
    reg_file("other.manual").write_text(json.dumps({**manual, "id": "other.manual", "owner_module": "other"}), encoding="utf-8")
    sm.unregister_module("other")
    must(not reg_file("other.run").exists() and not reg_file("other.manual").exists() and not (ACT / "other").exists(), "all of the module's own")

    # ---- another module's action cannot be taken over
    put_module("vendor", manifest(), files=("rotate.sh",))
    reg_file("vendor.rotate").write_text(json.dumps({**manual, "id": "vendor.rotate", "owner_module": "rival"}), encoding="utf-8")
    fails(lambda: sm.register_module("vendor"), "already registered by module rival")
    reg_file("vendor.rotate").unlink()
    # a hand registration with no owner is replaced (the migration path from a manual register-actions step)
    reg_file("vendor.rotate").write_text(json.dumps({**manual, "id": "vendor.rotate", "owner_module": None}), encoding="utf-8")
    sm.register_module("vendor")
    must(reg_json("vendor.rotate")["registered_by"] == "module-manifest", "replaced")

    # ---- refusals: nothing is registered
    def clean():
        sm.unregister_module("vendor")

    clean()
    before = sorted(p.name for p in REG.iterdir())
    folder = put_module("vendor", manifest(), files=("rotate.sh",))
    manifest_path = folder / "tec_tac.json"
    for label, make_bad in (
        ("manifest not root-owned", lambda: NOTROOT.add(norm(manifest_path))),
        ("manifest group/world writable", lambda: WRITABLE.add(norm(manifest_path))),
        ("module folder writable", lambda: WRITABLE.add(norm(folder))),
        ("module folder not root-owned", lambda: NOTROOT.add(norm(folder))),
        ("executable not root-owned", lambda: NOTROOT.add(norm(folder / "server_maintenance" / "actions" / "rotate.sh"))),
        ("executable writable", lambda: WRITABLE.add(norm(folder / "server_maintenance" / "actions" / "rotate.sh"))),
        ("actions folder writable", lambda: WRITABLE.add(norm(folder / "server_maintenance" / "actions"))),
        ("executable is a symlink", lambda: SYMLINKS.add(norm(folder / "server_maintenance" / "actions" / "rotate.sh"))),
        ("a folder on the way is a symlink", lambda: SYMLINKS.add(norm(folder / "server_maintenance"))),
    ):
        NOTROOT.clear(), WRITABLE.clear(), SYMLINKS.clear()
        make_bad()
        fails(lambda: sm.register_module("vendor"), "")
        must(sorted(p.name for p in REG.iterdir()) == before and not (ACT / "vendor").exists(), f"{label}: nothing registered")
    NOTROOT.clear(), WRITABLE.clear(), SYMLINKS.clear()
    # the installed manifest is checked again: the Python rules are not trusted from the web side
    for label, payload, part in (
        ("wrong id prefix", manifest([action("other.rotate")]), "must start with"),
        ("undeclared permission", manifest([action(permission="vendor.undeclared")]), "permission"),
        ("no publisher permission", manifest(publisher_permissions=["module.install"]), "server_maintenance.register"),
        ("17 entries", manifest([action(f"vendor.a{i}") for i in range(17)]), "at most 16"),
        ("absolute executable", manifest([action(executable="/etc/passwd")]), "relative path"),
        ("dotdot executable", manifest([action(executable="server_maintenance/actions/../../tec_tac.json")]), "below server_maintenance/actions/"),
        ("unknown key", manifest([action(colour=1)]), "documented keys"),
        ("id mismatch", manifest(id="rival"), "does not match the module folder"),
        ("a reportset type", manifest(type="reportset"), "only an extension"),
        ("bad argv", manifest([action(argv=[{"param": "nope"}])]), "argv"),
        ("bad permission value", manifest([action(permission="has space")], permission_groups={"V": ["has space"]}), "permission"),
        ("a duplicate id", manifest([action(), action()]), "declared twice"),
    ):
        put_module("vendor", payload, files=("rotate.sh",))
        fails(lambda: sm.register_module("vendor"), part)
        must(sorted(p.name for p in REG.iterdir()) == before and not (ACT / "vendor").exists(), f"{label}: nothing registered")
    for bad in ("../x", "", "a b", "a/b", ".hidden", "x" * 101, None, 5):
        fails(lambda bad=bad: sm.register_module(bad), "module id is invalid")
        fails(lambda bad=bad: sm.unregister_module(bad), "module id is invalid")
    # a module with no installed folder
    fails(lambda: sm.register_module("not-installed"), "")

    # ---- main(): the two new modes, and the old ones
    put_module("vendor", manifest(), files=("rotate.sh",))
    saved_argv = sys.argv
    try:
        sys.argv = ["tec-tac-server-maintenance", "--register-module", "vendor"]
        sm.main()
        must(reg_file("vendor.rotate").is_file(), "--register-module")
        sys.argv = ["tec-tac-server-maintenance", "--unregister-module", "vendor"]
        sm.main()
        must(not reg_file("vendor.rotate").exists(), "--unregister-module")
        for argv in (["x", "--bogus", "vendor"], ["x", "--register-module"], ["x"]):
            sys.argv = argv
            try:
                sm.main()
                raise AssertionError("usage expected")
            except SystemExit as exc:
                must("register-module" in str(exc) or "usage" in str(exc), exc)
    finally:
        sys.argv = saved_argv
    must("--register-module|--unregister-module <module-id>" in HELPER.read_text(encoding="utf-8"), "usage text names the new modes")
finally:
    for _name, _fn in _real.items():
        if _fn is not None:
            setattr(os, _name, _fn)

# ------------------------------------------------------------------------------------------------ no sudo reach
install = (ROOT / "install.sh").read_text(encoding="utf-8")
rule = [line for line in install.splitlines() if line.startswith("${TACTICAL_USER} ALL=(root) NOPASSWD: ${SERVER_MAINTENANCE_HELPER}")]
must(len(rule) == 1 and "--dispatch *" in rule[0] and "--cancel *" in rule[0], rule)
must("register-module" not in rule[0] and "--register" not in rule[0] and "unregister" not in rule[0], "the sudoers text does not name the new modes")
must(len(re.findall(r"NOPASSWD:[^\n]*SERVER_MAINTENANCE_HELPER", install)) == 1, "one sudo rule for the helper, and no other")
must("register-module" not in install, "install.sh never mentions the new modes")
for path in sorted(APP.glob("*.py")):
    must("register-module" not in path.read_text(encoding="utf-8").replace("--register-module", "") or path.name in ("contracts.py", "registry.py"), f"{path.name} does not call the root register mode")
provider_source = (APP / "server_maintenance.py").read_text(encoding="utf-8")
must('_dispatch("--dispatch"' in provider_source and '_dispatch("--cancel"' in provider_source and "register-module" not in provider_source, "the Tactical-side provider only dispatches and cancels")

# ------------------------------------------------------------------------------------------------ the job helpers
v1_path = ROOT / "scripts" / "module-job-helper.py"
v1 = types.ModuleType("module_job_helper_f2")
v1.__file__ = str(v1_path)
exec(compile(v1_path.read_text(encoding="utf-8").replace("TRUSTED_BASH = _resolve_trusted_bash()", 'TRUSTED_BASH = "/bin/bash"'), str(v1_path), "exec"), v1.__dict__)

for label, mod in (("v2", v2), ("v1", v1)):
    repo = BASE / f"repo-{label}"
    for name, declares in (("declares", True), ("quiet", False)):
        folder = repo / "extensions" / name
        folder.mkdir(parents=True, exist_ok=True)
        payload = {"id": name, "type": "extension", "version": "1.0.0"}
        if declares:
            payload["server_maintenance_actions"] = [{"id": f"{name}.run", "permission": f"{name}.run", "executable": "server_maintenance/actions/run.sh"}]
        (folder / "tec_tac.json").write_text(json.dumps(payload), encoding="utf-8")
    (repo / "extensions" / "empty").mkdir(parents=True, exist_ok=True)
    (repo / "extensions" / "empty" / "tec_tac.json").write_text(json.dumps({"id": "empty", "server_maintenance_actions": []}), encoding="utf-8")
    (repo / "extensions" / "broken").mkdir(parents=True, exist_ok=True)
    (repo / "extensions" / "broken" / "tec_tac.json").write_text("{not json", encoding="utf-8")
    must(mod.manifest_declares_server_actions(repo, "declares") is True, label)
    must(all(mod.manifest_declares_server_actions(repo, name) is False for name in ("quiet", "empty", "broken", "missing")), label)

    RUNS = []

    class Log:
        def __init__(self):
            self.text = ""

        def write(self, text):
            self.text += text

        def flush(self):
            pass

    mod.privileged_env = lambda extra=None: {}
    helper_file = BASE / f"sm-helper-{label}"
    helper_file.write_text("#!/bin/sh\n", encoding="utf-8")
    mod.SERVER_MAINTENANCE_HELPER = helper_file
    result = {"rc": 0}
    mod.subprocess = types.SimpleNamespace(run=lambda command, **kw: RUNS.append(command) or types.SimpleNamespace(returncode=result["rc"]), PIPE=-1, STDOUT=-2)
    real_path_stat = Path.stat

    class RootOwned:
        st_uid, st_mode = 0, 0o100755

    Path.stat = lambda self, *a, **k: RootOwned() if self == helper_file else real_path_stat(self, *a, **k)
    try:
        log = Log()
        # declared: --register-module
        mod.sync_server_maintenance_actions(repo, "declares", log)
        must(RUNS[-1] == [str(helper_file), "--register-module", "declares"], RUNS)
        # not declared but the helper is there: --unregister-module (this is how an upgrade drops stale actions)
        mod.sync_server_maintenance_actions(repo, "quiet", log)
        must(RUNS[-1] == [str(helper_file), "--unregister-module", "quiet"], RUNS)
        # remove: always unregister, even if the manifest still declares
        mod.sync_server_maintenance_actions(repo, "declares", log, remove=True)
        must(RUNS[-1] == [str(helper_file), "--unregister-module", "declares"], RUNS)
        # a failure raises with a plain message that names the module and points at the log
        result["rc"] = 3
        for kwargs, word in (({}, "registration"), ({"remove": True}, "removal")):
            try:
                mod.sync_server_maintenance_actions(repo, "declares", log, **kwargs)
                raise AssertionError("a helper failure must fail the job")
            except RuntimeError as exc:
                must(word in str(exc) and "declares" in str(exc) and "status 3" in str(exc) and "job log" in str(exc), exc)
        result["rc"] = 0
        # the Core helper is not installed: a module that declares nothing is not touched, one that declares is refused plainly
        mod.SERVER_MAINTENANCE_HELPER = BASE / "no-such-helper"
        before_runs = len(RUNS)
        mod.sync_server_maintenance_actions(repo, "quiet", log)
        mod.sync_server_maintenance_actions(repo, "declares", log, remove=True)
        must(len(RUNS) == before_runs, "nothing runs when there is nothing to do and no helper")
        try:
            mod.sync_server_maintenance_actions(repo, "declares", log)
            raise AssertionError("a declaring module needs the helper")
        except RuntimeError as exc:
            must("not installed" in str(exc) and "declares" in str(exc), exc)
        # a helper that is not root-owned is never run
        mod.SERVER_MAINTENANCE_HELPER = helper_file
        RootOwned.st_uid = 1000
        try:
            mod.sync_server_maintenance_actions(repo, "declares", log)
            raise AssertionError("a non-root helper must be refused")
        except RuntimeError as exc:
            must("non-root-owned" in str(exc), exc)
        RootOwned.st_uid = 0
        RootOwned.st_mode = 0o100775
        try:
            mod.sync_server_maintenance_actions(repo, "declares", log)
            raise AssertionError("a writable helper must be refused")
        except RuntimeError as exc:
            must("writable" in str(exc), exc)
    finally:
        Path.stat = real_path_stat
        RootOwned.st_uid, RootOwned.st_mode = 0, 0o100755
    must('SERVER_MAINTENANCE_HELPER = Path("/usr/local/sbin/tec-tac-server-maintenance")' in (v1_path if label == "v1" else ROOT / "scripts" / "module-v2-job-helper.py").read_text(encoding="utf-8"), label)

# ---- v2 flow: order, rollback, plain failure
EVENTS = []
v2_log_dir = BASE / "v2-flow"
v2_log_dir.mkdir()
v2.LOGS_ROOT = v2_log_dir
v2.RUNNING_ROOT = v2_log_dir / "running"
v2.BACKUP_ROOT = v2_log_dir / "backup"
v2.RUNNING_ROOT.mkdir()
v2.BACKUP_ROOT.mkdir()
JOB = "00000000-0000-4000-8000-0000000000f2"
JOBS = {}
FAIL_ON = {"module": None}
repo_flow = BASE / "repo-flow"
(repo_flow / "extensions").mkdir(parents=True)
v2.load_job = lambda job_id: (v2_log_dir / "job.json", {"status": "dispatched", "stage": "dispatched", "created_at": "2026-10-10"})
v2.load_running_request = lambda job_id: (None, {"id": JOB, "action": "batch_install", "plugin_id": "a", "package_sha256": "x"})
v2.acquire_lifecycle_lock = lambda: None
v2.load_config = lambda: {"REPO_ROOT": str(repo_flow)}
v2._snapshot_v2_job_artifacts = lambda job_id, job, running: job
v2._verify_v2_job_trust = lambda config, job: None
v2.batch_packages = lambda job, running, trust: [{"id": "a", "path": "a.zip"}, {"id": "b", "path": "b.zip"}]
v2._validate_install_plan_against_signed_artifacts = lambda job, packages, trust: (["a", "b"], [{"id": "a", "action": "install", "version": "1.0.0"}, {"id": "b", "action": "install", "version": "1.0.0"}])
v2.read_installed_manifests = lambda repo_root: {}
v2.verify_install_disables = lambda *a, **k: []
v2.verify_install_categories = lambda *a, **k: {}
v2.remember_version = lambda *a, **k: EVENTS.append("remember")
v2.cleanup_successful_stage = lambda job, log: EVENTS.append("cleanup")
v2._cleanup_claimed_job_inputs = lambda job_id: None
v2._confirmed_disable_modules = lambda job: []
v2.install_packages = lambda repo_root, packages, order, actions, log, backup: EVENTS.append("install") or list(order)
v2.sync_and_reload = lambda config, log, **kw: EVENTS.append("sync")
v2.restore_modules = lambda repo_root, ids, backup, log: EVENTS.append(("restore", list(ids)))
v2.atomic_json = lambda path, payload, mode=0o640, **kw: JOBS.__setitem__("last", dict(payload))
def v2_sync(repo_root, module_id, log, *, remove=False):
    EVENTS.append(("remove" if remove else "register", module_id))
    if FAIL_ON["module"] == module_id and not remove:
        raise RuntimeError(f"server-maintenance action registration failed for module {module_id} (status 5). See the job log for the reason.")


v2.sync_server_maintenance_actions = v2_sync
real_os_chown = getattr(os, "chown", None)
os.chown, os.chmod = (lambda *a, **k: None), (lambda *a, **k: None)
try:
    v2.run_job(JOB)
    job = JOBS["last"]
    must(job["status"] == "succeeded", job)
    must(EVENTS == ["install", "remember", "remember", "sync", ("register", "a"), ("register", "b"), "cleanup"], EVENTS)
    # a registration failure fails the job with a plain message and takes the rollback: restore, then re-register or remove
    del EVENTS[:]
    (repo_flow / "extensions" / "a").mkdir()
    (repo_flow / "extensions" / "a" / "tec_tac.json").write_text("{}", encoding="utf-8")   # a restored version of a exists, b has none
    FAIL_ON["module"] = "b"
    import shutil
    shutil.rmtree(v2.RUNNING_ROOT / JOB)   # the first run left its running folder
    v2.run_job(JOB)
    job = JOBS["last"]
    must(job["status"] == "failed" and "server-maintenance action registration failed for module b" in job["error"] and "job log" in job["error"], job)
    must(EVENTS[:4] == ["install", "remember", "remember", "sync"] and ("register", "a") in EVENTS and ("register", "b") in EVENTS, EVENTS)
    tail = EVENTS[EVENTS.index(("register", "b")) + 1:]
    must(tail[0] == ("restore", ["a", "b"]), tail)
    must(tail[1:3] == [("register", "a"), ("remove", "b")], tail)   # restored a is re-registered, b has no restored version
    must("cleanup" not in EVENTS, "a failed job keeps its staged files")
    # a restore step that itself fails never hides the original error
    del EVENTS[:]
    v2.sync_server_maintenance_actions = lambda repo_root, module_id, log, *, remove=False: (_ for _ in ()).throw(RuntimeError("helper down"))
    log = Log()
    v2.restore_server_maintenance_actions(repo_flow, ["a", "b"], log)
    must("restoring server-maintenance actions of a failed" in log.text and "restoring server-maintenance actions of b failed" in log.text, log.text)
finally:
    if real_os_chown is not None:
        os.chown = real_os_chown
    os.chmod = _real["chmod"]

# a rename unregisters the previous module id (source check: the flow above does not stage a rename)
v2_text = (ROOT / "scripts" / "module-v2-job-helper.py").read_text(encoding="utf-8")
block = v2_text[v2_text.index('job["stage"] = "server-maintenance-actions"'):v2_text.index("cleanup_successful_stage(job, log)", v2_text.index('job["stage"] = "server-maintenance-actions"'))]
must('action.get("action") == "rename"' in block and "remove=True" in block and "for module_id in order:" in block, "rename drops the old id")
must(v2_text.index("sync_and_reload(config, log, refresh_workers=True)\n                    # 1.17.17") < v2_text.index('job["stage"] = "server-maintenance-actions"'), "registration comes after the sync")
must(v2_text.index("restore_modules(repo_root, backup_ids, backup, log)\n                    restore_server_maintenance_actions") > 0, "rollback re-registers after restore_modules")

# ---- v1 flow: install registers after the sync, uninstall unregisters, a failure fails the job
v1_text = v1_path.read_text(encoding="utf-8")
v1_install = v1_text.index('if rc == 0 and job["action"] == "install":\n                    # 1.17.17')
must(v1_text.index("UI module sync failed rc=") < v1_install < v1_text.index("except Exception as exc:", v1_install), "install registers after the UI sync")
must("forget_module_state(job[\"plugin_id\"], log)\n                    # 1.17.17: the module's server-maintenance actions go with it.\n                    sync_server_maintenance_actions(repo_root, job[\"plugin_id\"], log, remove=True)" in v1_text, "uninstall unregisters")
V1_TMP = Path(tempfile.mkdtemp(prefix="tectac-v1-flow-"))
RUNNING, REQUESTS, LOGS, JOBS_DIR = V1_TMP / "running", V1_TMP / "running" / "requests", V1_TMP / "logs", V1_TMP / "jobs"
REPO1 = V1_TMP / "repo"
for folder in (RUNNING, REQUESTS, LOGS, JOBS_DIR, REPO1 / "scripts", REPO1 / "extensions" / "demo"):
    folder.mkdir(parents=True, exist_ok=True)
for script in ("install-extension.sh", "remove-extension.sh"):
    (REPO1 / "scripts" / script).write_text("#!/bin/bash\n", encoding="utf-8")
v1.RUNNING_ROOT, v1.RUNNING_REQUEST_ROOT, v1.LOGS_ROOT, v1.JOBS_ROOT = RUNNING, REQUESTS, LOGS, JOBS_DIR
V1_WRITES, V1_EVENTS = [], []
v1.load_config = lambda: {"REPO_ROOT": str(REPO1), "UI_SYNC_SCRIPT": str(V1_TMP / "no-sync.sh"), "TEC_TAC_ENVIRONMENT": "development"}
v1.acquire_lifecycle_lock = lambda: None
v1._privileged_verify_package = lambda config, job: None
v1.privileged_env = lambda extra=None: {}
v1.development_server = lambda: True
v1.package_category = lambda package, plugin_id: "server"
v1.remember_category = lambda plugin_id, category: None
v1.forget_module_state = lambda plugin_id, log=None: V1_EVENTS.append("forget")
v1.plan_remove_hand_back = lambda repo_root, plugin_id, enable: []
v1.atomic_json = lambda path, payload, mode=0o640, **kw: V1_WRITES.append(dict(payload))
v1.subprocess = types.SimpleNamespace(run=lambda command, **kw: V1_EVENTS.append(("lifecycle", Path(command[1]).name)) or types.SimpleNamespace(returncode=0), PIPE=-1, STDOUT=-2)
real_stat_v1, real_chmod_v1 = Path.stat, os.chmod


class V1Root:
    st_uid, st_mode = 0, 0o100755


Path.stat = lambda self, *a, **k: V1Root() if str(self).startswith(str(REPO1)) else real_stat_v1(self, *a, **k)
os.chmod = lambda *a, **k: None


def stage(action):
    run_dir = RUNNING / JOB
    run_dir.mkdir(exist_ok=True)
    package = run_dir / "package.zip"
    package.write_bytes(b"PK")
    request = {"id": JOB, "action": action, "plugin_id": "demo", "replace": False, "package_path": str(package), "upload_id": JOB}
    (REQUESTS / f"{JOB}.json").write_text(json.dumps(request), encoding="utf-8")
    v1.load_job = lambda job_id: (JOBS_DIR / f"{JOB}.json", {"id": JOB, "action": action, "status": "dispatched", "stage": "dispatched", "created_at": "2026-10-10"})
    v1.load_running_request = lambda job_id: (REQUESTS / f"{JOB}.json", dict(request))
    del V1_WRITES[:], V1_EVENTS[:]


def v1_sync(repo_root, module_id, log, *, remove=False):
    V1_EVENTS.append(("remove" if remove else "register", module_id))
    if FAIL_V1["on"]:
        raise RuntimeError("server-maintenance action registration failed for module demo (status 9). See the job log for the reason.")


FAIL_V1 = {"on": False}
v1.sync_server_maintenance_actions = v1_sync
try:
    stage("install")
    v1.run_job(JOB)
    must(V1_WRITES[-1]["status"] == "succeeded" and V1_EVENTS == [("lifecycle", "install-extension.sh"), ("register", "demo")], (V1_WRITES[-1], V1_EVENTS))
    stage("remove")
    v1.run_job(JOB)
    must(V1_WRITES[-1]["status"] == "succeeded" and V1_EVENTS == [("lifecycle", "remove-extension.sh"), "forget", ("remove", "demo")], V1_EVENTS)
    FAIL_V1["on"] = True
    stage("install")
    v1.run_job(JOB)
    job = V1_WRITES[-1]
    must(job["status"] == "failed" and "registration failed for module demo" in job["error"] and "job log" in job["error"], job)
    stage("remove")
    v1.run_job(JOB)
    must(V1_WRITES[-1]["status"] == "failed" and "demo" in V1_WRITES[-1]["error"], "a failed removal of the actions fails the job")
finally:
    Path.stat, os.chmod = real_stat_v1, real_chmod_v1

# the installer keeps an installed module out of group and world write (the root helper refuses a writable module folder)
install_extension = (ROOT / "scripts" / "install-extension.sh").read_text(encoding="utf-8")
must('chmod -R go-w "${DEST_EXTENSION}"' in install_extension, "install-extension.sh removes group and world write")

print("[TEST] PASS server maintenance module actions 1.17.17")

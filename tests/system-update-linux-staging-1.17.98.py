#!/usr/bin/env python3
"""1.17.98: System Update source checkouts stay Tactical-owned and clean; root installs only from a verified staging copy.

Spec "System Update Checkout and Ownership Fix" (Johan and Sol, 2 November 2026) and the review fix note of 2 November 2026.
The real helper's run_job runs against real Git, real chown and a real second account ("tactical"), with signed release trees
(an Ed25519 key made for this test only; the real Tech Flow Dynamics key is never used or needed). Only three things are
replaced: the state folders point into a temporary directory, the privileged verifier subprocess is the same
verify_release_tree it calls, and the post-install Django checks (manage.py) read the deployed VERSION instead.

Covered (spec regression tests 1 to 13, plus the fix note):
   1, 3, 7, 8  Framework update from a clean branch checkout: HEAD is the exact commit, clean, every path Tactical-owned,
               runtime root:root (even when the installer left it Tactical-owned), installer ran from staging, config path kept.
   2, 4, 5, 6  UI update: clean, vite.config.js and scripts/sync-modules.sh unchanged although the installer rewrites its own copies.
   9           Repeated updates change no ownership.
  10, 11, 12   Failed update: full rollback from a staged backup; source back at the old HEAD, clean, one owner; provenance put back.
  13           install.sh's rule (--runtime-ownership) and the updater's rule give the same runtime.
  fix note     A changed install.sh in the source checkout, in the rollback backup, or in a restored checkout stops the update,
               the rollback and the restore before any installer runs.
  ownership    The source checkout's owners never change across a successful and a failed run.

It skips (exit 0) anywhere but root on Linux with Git, cryptography and useradd. Run it in Docker (desktop-linux):
    docker --context desktop-linux run --rm -v <core>:/ro:ro <python:3.12 image with git and cryptography> \
        sh -c "cp -r /ro /core && python /core/tests/system-update-linux-staging-1.17.98.py"
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from pathlib import Path


def _skip(why):
    print(f"[TEST] SKIP system update linux staging ({why})")
    raise SystemExit(0)


if not sys.platform.startswith("linux") or os.geteuid() != 0 or not shutil.which("git"):
    _skip("needs root on Linux with git")
import pwd  # noqa: E402  (Linux only)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    _skip("needs cryptography")
try:
    pwd.getpwnam("tactical")
except KeyError:
    if not shutil.which("useradd"):
        _skip("needs useradd")
    subprocess.run(["useradd", "--create-home", "--user-group", "tactical"], check=True)
TACT = pwd.getpwnam("tactical")
UID, GID, HOME = TACT.pw_uid, TACT.pw_gid, TACT.pw_dir

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
from tec_tac.trusted_publishers import verify_release_tree  # noqa: E402

spec = importlib.util.spec_from_file_location("system_update_helper", ROOT / "scripts/system-update-helper.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# Round 6: every folder above a checkout must be root-owned and not group/world writable, so not /tmp (1777).
tmp = Path(tempfile.mkdtemp(prefix="suh-staging-", dir="/opt"))
os.chmod(tmp, 0o755)
SRC, STATE, RUNTIME, DEPLOY, TRUST, REMOTES, SEEDS, MARKERS, ETC = (tmp / n for n in ("src", "state", "opt-tec-tac", "ui-deploy", "trust", "remotes", "seeds", "markers", "etc"))
for d in (SRC, STATE, RUNTIME, DEPLOY, TRUST, REMOTES, SEEDS, MARKERS, ETC):
    d.mkdir()
    os.chmod(d, 0o755)
os.chmod(MARKERS, 0o777)
FW, UI = SRC / "framework", SRC / "ui"
CONF = ETC / "tec-tac.conf"
CONF.write_text("\n".join([
    f"TEC_TAC_ROOT={RUNTIME}", f"TEC_TAC_FRAMEWORK_SOURCE={FW}", f"TEC_TAC_UI_SOURCE={UI}", f"TEC_TAC_FRAMEWORK_ROOT={RUNTIME / 'framework'}",
    f"TEC_TAC_SCRIPTS_ROOT={RUNTIME / 'scripts'}", f"TEC_TAC_UI_DEPLOY_ROOT={DEPLOY}", "TACTICAL_USER=tactical", "",
]), encoding="utf-8")
os.chmod(CONF, 0o644)

h.CONFIG = CONF
h.STATE_ROOT = STATE
for name, sub in (("JOBS_ROOT", "jobs"), ("RUNNING_ROOT", "running"), ("LOGS_ROOT", "logs"), ("BACKUPS_ROOT", "backups"),
                  ("HISTORY_ROOT", "history"), ("INSTALL_STAGE_ROOT", "install-stage"), ("PROVENANCE_ROOT", "provenance")):
    setattr(h, name, STATE / sub)
h.RUNNING_REQUEST_ROOT = STATE / "running" / "requests"
h.LOCK_PATH = STATE / "update.lock"
h.UI_SYNC_TOOLS_ROOT = tmp / "usr-local-lib" / "tec-tac-ui-sync"
h.LIFECYCLE_LOCK_PATH = STATE / "lifecycle.lock"
for d in (h.JOBS_ROOT, h.RUNNING_ROOT, h.LOGS_ROOT, h.BACKUPS_ROOT, h.RUNNING_REQUEST_ROOT):
    d.mkdir(parents=True, exist_ok=True)

# The release key of this test only.
PRIVATE = Ed25519PrivateKey.generate()
PUBLIC = PRIVATE.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
(TRUST / "test-publisher").mkdir()
(TRUST / "test-publisher" / "public.key").write_text("ed25519:" + base64.b64encode(PUBLIC).decode() + "\n", encoding="utf-8")
(TRUST / "test-publisher" / "publisher.json").write_text(json.dumps({
    "schema": 1, "publisher_id": "test-publisher", "display_name": "Test", "status": "trusted", "environment": "production",
    "permissions": ["module.install", "framework.update", "ui.update"],
    "keys": [{"key_id": "test-key", "status": "active", "algorithm": "Ed25519", "public_key_file": "public.key"}],
}), encoding="utf-8")


def root_verify(cfg, root, component):
    trust = verify_release_tree(root=Path(root), expected_component=component, required_permissions=(f"{component}.update",),
                                trust_root=TRUST, server_environment="production")
    if not trust.get("signed"):
        raise RuntimeError("unsigned system updates require root-owned development override")
    trust["root_policy"] = {"actual_level": "signed_production", "development_unsigned_override": False}
    return trust


def fake_verify(component, target, expected, log):
    found = ((RUNTIME / "VERSION") if component == "framework" else (DEPLOY / "VERSION")).read_text(encoding="utf-8").strip()
    must(found == expected, f"deployed {component} is {found}, expected {expected}")


h._root_verify_tree = root_verify
h.verify = fake_verify


def run(*args, cwd=None, user=False):
    extra = {"user": UID, "group": GID, "extra_groups": []} if user else {}
    env = {"PATH": "/usr/bin:/bin", "HOME": HOME if user else "/root", "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(list(args), cwd=cwd, check=True, capture_output=True, text=True, env=env, **extra).stdout.strip()


def tgit(*args, cwd):
    return run("git", "-C", str(cwd), *args, user=True)


def fw_files(version):
    install = f"""#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
V="$(cat "$HERE/VERSION")"
echo "framework v=$V from=$HERE staged_for=${{TEC_TAC_STAGED_SOURCE_CHECKOUT:-}} uid=$(id -u)" >> "{MARKERS}/installs.log"
if grep -qx "$V" "{MARKERS}/fail-versions" 2>/dev/null; then exit 1; fi
RT="{RUNTIME}"
rm -rf "$RT/framework" "$RT/scripts" "$RT/templates"
cp -a "$HERE/framwork" "$RT/framework"; cp -a "$HERE/scripts" "$RT/scripts"; cp -a "$HERE/templates" "$RT/templates"
cp -a "$HERE/VERSION" "$RT/VERSION"; cp -a "$HERE/tec_tac_package.json" "$RT/tec_tac_package.json"
# What an older installer could leave behind: a Tactical-owned runtime. The updater's ownership rule must correct it.
chown -R {UID}:{GID} "$RT/framework"; chmod 0664 "$RT/VERSION"
# Like an installer before 1.17.98: it records its own folder (here the staging copy) as the source checkout.
sed -i "s|^TEC_TAC_FRAMEWORK_SOURCE=.*|TEC_TAC_FRAMEWORK_SOURCE=$HERE|" "{CONF}"
"""
    return {
        "VERSION": f"{version}\n", "tec_tac_package.json": json.dumps({"version": version}) + "\n", "install.sh": install,
        "framwork/tec_tac/__init__.py": f"VERSION = {version!r}\n", "scripts/recovery/repair.sh": "#!/bin/bash\necho repair\n",
        "templates/plugin.txt": "template\n",
    }


def ui_files(version):
    install = f"""#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)"
V="$(cat "$HERE/VERSION")"
echo "ui v=$V from=$HERE uid=$(id -u)" >> "{MARKERS}/installs.log"
# A build step that rewrites tracked files in the folder it runs from. That folder is the staging copy, never the checkout.
echo "// rewritten by the build" >> "$HERE/vite.config.js"
echo "# rewritten by the build" >> "$HERE/scripts/sync-modules.sh"
mkdir -p "$HERE/node_modules/.bin" "$HERE/dist"; echo built > "$HERE/dist/index.html"
if grep -qx "ui-$V" "{MARKERS}/fail-versions" 2>/dev/null; then exit 1; fi
mkdir -p "{DEPLOY}"; cp "$HERE/VERSION" "{DEPLOY}/VERSION"; cp "$HERE/dist/index.html" "{DEPLOY}/index.html"
"""
    return {
        "VERSION": f"{version}\n", "package.json": json.dumps({"name": "tec-tac-ui", "version": version}) + "\n",
        "src/App.vue": f"<template>{version}</template>\n", "vite.config.js": "export default {}\n",
        "scripts/sync-modules.sh": "#!/bin/bash\necho sync\n", "scripts/tec-tac-config.sh": "TEC_TAC_ROOT=/opt/tec-tac\n",
        "scripts/install.sh": install,
    }


def make_remote(component, versions):
    """A bare remote whose dev branch gets one signed commit per version. Returns (remote, seed, {version: commit})."""
    seed = SEEDS / component
    remote = REMOTES / f"{component}.git"
    run("git", "init", "-q", "-b", "dev", str(seed))
    run("git", "init", "-q", "--bare", str(remote))
    commits = {}
    for version in versions:
        for path in list(seed.iterdir()):
            if path.name != ".git":
                shutil.rmtree(path) if path.is_dir() else path.unlink()
        files = (fw_files if component == "framework" else ui_files)(version)
        for rel, text in files.items():
            target = seed / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            if rel.endswith(".sh"):
                os.chmod(target, 0o755)
        entries = []
        for rel in sorted(files):
            data = (seed / rel).read_bytes()
            entries.append({"path": rel, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        manifest = {"schema": 2, "component": component, "version": version, "publisher_id": "test-publisher", "key_id": "test-key",
                    "algorithm": "Ed25519", "files": entries}
        raw = (json.dumps(manifest, indent=2) + "\n").encode()
        (seed / h.TREE_MANIFEST).write_bytes(raw)
        (seed / h.TREE_SIGNATURE).write_text("ed25519:" + base64.b64encode(PRIVATE.sign(raw)).decode() + "\n", encoding="utf-8")
        run("git", "-C", str(seed), "add", "-A")
        run("git", "-C", str(seed), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", version)
        commits[version] = run("git", "-C", str(seed), "rev-parse", "HEAD")
    run("git", "-C", str(seed), "push", "-q", str(remote), "dev")
    for current, dirs, names in os.walk(remote):
        for name in [".", *dirs, *names]:
            os.lchown(os.path.join(current, name), UID, GID)
    return remote, seed, commits


def clone_at(remote, checkout, commit):
    checkout.mkdir()
    os.chown(checkout, UID, GID)
    tgit("clone", "-q", "-b", "dev", str(remote), str(checkout), cwd=SRC)
    tgit("reset", "-q", "--hard", commit, cwd=checkout)


def owners(path):
    found = {}
    for current, dirs, names in os.walk(path):
        for name in [".", *dirs, *names]:
            full = os.path.join(current, name)
            info = os.lstat(full)
            found[os.path.relpath(full, path)] = (info.st_uid, info.st_gid)
    return found


def all_tactical(path):
    bad = {rel: own for rel, own in owners(path).items() if own != (UID, GID)}
    must(not bad, f"{path} has paths not owned by tactical: {sorted(bad.items())[:5]}")


def installs():
    log = MARKERS / "installs.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def set_fail(*versions):
    (MARKERS / "fail-versions").write_text("".join(f"{v}\n" for v in versions), encoding="utf-8")


def queue(component, version, commit, seed, *, ref="dev", stype="branch", package_commit=None):
    job_id = str(uuid.uuid4())
    package = h.RUNNING_ROOT / f"{job_id}.zip"
    run("git", "-C", str(seed), "archive", "--format=zip", "-o", str(package), package_commit or commit)
    created = "2026-11-02T00:00:00+00:00"
    (h.JOBS_ROOT / f"{job_id}.json").write_text(json.dumps({"id": job_id, "action": "install", "component": component,
                                                             "status": "dispatched", "stage": "dispatched", "created_at": created}), encoding="utf-8")
    (h.RUNNING_REQUEST_ROOT / f"{job_id}.json").write_text(json.dumps({
        "id": job_id, "action": "install", "component": component, "upload_id": str(uuid.uuid4()), "allow_downgrade": False,
        "package_path": str(package), "package_filename": "pkg.zip", "release_manifest_path": None, "release_signature_path": None,
        "source": {"type": stype, "repository": f"jvz007/{component}", "ref": ref, "commit": commit},
    }), encoding="utf-8")
    return job_id


def update(component, version, commit, seed, **kw):
    job_id = queue(component, version, commit, seed, **kw)
    if h._LIFECYCLE_LOCK_HANDLE is not None:
        h._LIFECYCLE_LOCK_HANDLE.close()
        h._LIFECYCLE_LOCK_HANDLE = None
    h.run_job(job_id)
    job = json.loads((h.HISTORY_ROOT / f"{job_id}.json").read_text(encoding="utf-8"))
    job["log"] = (h.LOGS_ROOT / f"{job_id}.log").read_text(encoding="utf-8")
    return job


def config_source():
    return next(line.split("=", 1)[1] for line in CONF.read_text(encoding="utf-8").splitlines() if line.startswith("TEC_TAC_FRAMEWORK_SOURCE="))


def stage_left_empty():
    must(h.INSTALL_STAGE_ROOT.is_dir() and not any(h.INSTALL_STAGE_ROOT.iterdir()), "staging copies are removed after each run")
    info = os.lstat(h.INSTALL_STAGE_ROOT)
    must(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "the staging root is root:root 0700")


FW_REMOTE, FW_SEED, FWC = make_remote("framework", ["2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.0.5"])
UI_REMOTE, UI_SEED, UIC = make_remote("ui", ["0.5.1", "0.5.2"])
clone_at(FW_REMOTE, FW, FWC["2.0.1"])
clone_at(UI_REMOTE, UI, UIC["0.5.1"])
for rel in ("framework", "scripts", "templates"):
    (RUNTIME / rel).mkdir()
(RUNTIME / "VERSION").write_text("2.0.1\n", encoding="utf-8")
(RUNTIME / "tec_tac_package.json").write_text('{"version": "2.0.1"}\n', encoding="utf-8")
(DEPLOY / "VERSION").write_text("0.5.1\n", encoding="utf-8")
runtime_targets = h._runtime_targets_from_config(h.load_config())

# --- 1, 3, 7, 8: Framework update from a clean branch checkout --------------------------------------------------------------
before = owners(FW)
all_tactical(FW)
job = update("framework", "2.0.2", FWC["2.0.2"], FW_SEED)
must(job["status"] == "succeeded" and job["stage"] == "complete", (job["status"], job["stage"], job.get("error"), job["log"][-2000:]))
must(tgit("rev-parse", "HEAD", cwd=FW) == FWC["2.0.2"] and tgit("symbolic-ref", "--short", "HEAD", cwd=FW) == "dev", "exact commit on dev")
must(tgit("status", "--porcelain", cwd=FW) == "", "core source clean after update")
all_tactical(FW)
must(not h.verify_runtime_ownership(runtime_targets), h.verify_runtime_ownership(runtime_targets))
for rel, mode in (("framework", 0o755), ("scripts", 0o755), ("templates", 0o755), ("VERSION", 0o644), ("tec_tac_package.json", 0o644)):
    info = os.lstat(RUNTIME / rel)
    must((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, mode), (rel, info))
last = installs()[-1]
must(f"from={h.INSTALL_STAGE_ROOT}/" in last and f"staged_for={FW}" in last and "uid=0" in last, last)
must(config_source() == str(FW), f"config source path is {config_source()}")
stage_left_empty()
prov = json.loads((h.PROVENANCE_ROOT / "framework.json").read_text(encoding="utf-8"))
must(prov["commit"] == FWC["2.0.2"] and len(prov["commit"]) == 40 and prov["ref"] == "dev" and prov["repository"] == "jvz007/framework", prov)
must(job["installed_provenance"]["commit"] == FWC["2.0.2"], job["installed_provenance"])
must(set(owners(FW).values()) == set(before.values()) == {(UID, GID)}, "ownership unchanged across a successful run")
print("       1,3,7,8: framework update: exact commit, clean, Tactical-owned source, root-owned runtime, installer from staging, provenance")

# --- 2, 4, 5, 6: UI update; the build rewrites tracked files only in the staging copy -----------------------------------------
job = update("ui", "0.5.2", UIC["0.5.2"], UI_SEED)
must(job["status"] == "succeeded", (job.get("error"), job["log"][-2000:]))
must(tgit("status", "--porcelain", cwd=UI) == "", "ui source clean after update")
for rel in ("vite.config.js", "scripts/sync-modules.sh"):
    must((UI / rel).read_text(encoding="utf-8") == tgit("show", f"{UIC['0.5.2']}:{rel}", cwd=UI) + "\n", f"{rel} changed in the checkout")
must(not (UI / "node_modules").exists() and not (UI / "dist").exists(), "the UI build ran in the checkout")
must((DEPLOY / "VERSION").read_text(encoding="utf-8").strip() == "0.5.2", "deployed UI version")
all_tactical(UI)
stage_left_empty()
published = h.UI_SYNC_TOOLS_ROOT / "scripts" / "sync-modules.sh"
info = os.lstat(published)
must((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o755), info)
must(published.read_text(encoding="utf-8") == tgit("show", f"{UIC['0.5.2']}:scripts/sync-modules.sh", cwd=UI) + "\n", "published sync script is not the signed one")
must((h.UI_SYNC_TOOLS_ROOT / "scripts" / "tec-tac-config.sh").is_file(), "the config reader the sync script sources")
must(f"UI_SYNC_SCRIPT={published}" in CONF.read_text(encoding="utf-8").splitlines(), "UI_SYNC_SCRIPT not pointed at the root-owned copy")
must(h.publish_ui_sync_from_checkout(io.StringIO()) == published, "install.sh path (--publish-ui-sync) from the verified UI checkout")
try:
    h.capture_ui_sync_tools(UI)
except RuntimeError as exc:
    must("not staged and verified" in str(exc), exc)
else:
    raise AssertionError("UI sync tools were published from the unverified checkout")
print("       UI module sync script: root-owned copy from the verified tree, UI_SYNC_SCRIPT points at it, never from the checkout")
print("       2,4,5,6: UI update: clean source, vite.config.js and sync-modules.sh unchanged, build output only in staging")

# --- 9: repeating an update changes no ownership --------------------------------------------------------------------------------
fw_before, rt_before = owners(FW), owners(RUNTIME)
job = update("framework", "2.0.2", FWC["2.0.2"], FW_SEED)
must(job["status"] == "succeeded", job.get("error"))
must(set(owners(FW).values()) == {(UID, GID)} and owners(RUNTIME) == rt_before, "a repeated update changed ownership")
print("       9: a repeated update leaves source and runtime ownership as they were")

# --- dirty source: tracked change logged and restored; generated bytecode removed -----------------------------------------------
run("bash", "-c", f"echo changed >> {FW}/install.sh && mkdir -p {FW}/framwork/tec_tac/__pycache__ && echo x > {FW}/framwork/tec_tac/__pycache__/m.pyc", user=True)
job = update("framework", "2.0.3", FWC["2.0.3"], FW_SEED)
must(job["status"] == "succeeded", job.get("error"))
must(any("install.sh" in line for line in job.get("source_restored_changes", [])), job.get("source_restored_changes"))
must("tracked change(s); restoring them to HEAD" in job["log"], job["log"][-1500:])
must(tgit("status", "--porcelain", "--untracked-files=all", cwd=FW) == "" and tgit("rev-parse", "HEAD", cwd=FW) == FWC["2.0.3"], "dirty source not restored")
print("       dirty source: tracked change logged and restored as the Tactical account, bytecode removed, update continues")

# --- mixed ownership left by an older update (root worktree, Tactical .git) is repaired, never handed to root ------------------
for current, dirs, names in os.walk(FW):
    if "/.git" in current + "/" or current.endswith("/.git"):
        continue
    for name in [".", *[d for d in dirs if d != ".git"], *names]:
        os.lchown(os.path.join(current, name), 0, 0)
job = update("framework", "2.0.3", FWC["2.0.3"], FW_SEED)
must(job["status"] == "succeeded", job.get("error"))
must("source checkout paths to the Tactical account" in job["log"], job["log"][-1500:])
all_tactical(FW)
print("       mixed root/Tactical checkout: repaired to one Tactical owner, Git never ran as root")

# --- 10, 11, 12: failed install, full rollback from the staged backup --------------------------------------------------------------
set_fail("2.0.4")
fw_before = owners(FW)
count = len(installs())
job = update("framework", "2.0.4", FWC["2.0.4"], FW_SEED)
must(job["status"] == "failed" and job["stage"] == "rolled-back" and job["rollback"]["status"] == "succeeded", (job["stage"], job.get("rollback"), job["log"][-2000:]))
ran = installs()[count:]
must(len(ran) == 2 and "v=2.0.4" in ran[0] and "v=2.0.3" in ran[1] and all(f"from={h.INSTALL_STAGE_ROOT}/" in line for line in ran), ran)
must(tgit("rev-parse", "HEAD", cwd=FW) == FWC["2.0.3"] and tgit("symbolic-ref", "--short", "HEAD", cwd=FW) == "dev", "source not back at the old HEAD")
must(tgit("status", "--porcelain", "--untracked-files=all", cwd=FW) == "", "failed update dirtied the source")
must(set(owners(FW).values()) == set(fw_before.values()) == {(UID, GID)}, "ownership changed across a failed run (mixed ownership)")
must((RUNTIME / "VERSION").read_text(encoding="utf-8").strip() == "2.0.3" and not h.verify_runtime_ownership(runtime_targets), "runtime not rolled back")
must(json.loads((h.PROVENANCE_ROOT / "framework.json").read_text(encoding="utf-8"))["commit"] == FWC["2.0.3"], "provenance not put back")
must(config_source() == str(FW), "config source path after rollback")
stage_left_empty()
print("       10,11,12: failed install: old installer from a verified staged backup, source back at the old HEAD, clean, one owner, provenance back")

# --- a failure before the installer (commit the remote does not have) touches nothing ----------------------------------------
count = len(installs())
job = update("framework", "2.0.5", "f" * 40, FW_SEED, package_commit=FWC["2.0.5"])
must(job["stage"] == "failed-pre-mutation" and job["rollback"].get("reason") == "before-install", (job["stage"], job.get("rollback"), job.get("error")))
must("does not have commit" in job["error"] and len(installs()) == count, job["error"])
must(tgit("rev-parse", "HEAD", cwd=FW) == FWC["2.0.3"] and tgit("status", "--porcelain", cwd=FW) == "", "source changed by a pre-install failure")
print("       pre-install failure: no installer, source unchanged and clean")

# --- fix note: a changed install.sh in the source checkout stops the update before any installer runs --------------------------
real_move = h.move_source_to_commit


def move_then_tamper(*args, **kwargs):
    result = real_move(*args, **kwargs)
    run("bash", "-c", f"echo 'touch {MARKERS}/evil' >> {FW}/install.sh", user=True)  # the web account changes install.sh
    return result


h.move_source_to_commit = move_then_tamper
count = len(installs())
job = update("framework", "2.0.5", FWC["2.0.5"], FW_SEED)
h.move_source_to_commit = real_move
must(job["stage"] == "failed-pre-mutation" and "install.sh differs from the signed release manifest" in job["error"], (job["stage"], job["error"]))
must(len(installs()) == count and not (MARKERS / "evil").exists(), "an installer ran from a changed checkout")
must(tgit("rev-parse", "HEAD", cwd=FW) == FWC["2.0.3"] and tgit("status", "--porcelain", cwd=FW) == "", "tampered source not restored")
print("       fix note (update): changed install.sh in the checkout -> refused before any installer, source restored")

# --- fix note: a changed install.sh in the rollback backup stops the rollback before its installer runs ----------------------
real_backup = h.backup_root


def backup_then_tamper(target, component, old_version, job_id):
    path = real_backup(target, component, old_version, job_id)
    with tarfile.open(path, "r:gz") as tf:
        members = [(m, tf.extractfile(m).read() if m.isfile() else None) for m in tf.getmembers()]
    with tarfile.open(path, "w:gz") as tf:
        for member, data in members:
            if member.name.endswith("/install.sh"):
                data = data + f"touch {MARKERS}/evil\n".encode()
                member.size = len(data)
            tf.addfile(member, io.BytesIO(data) if data is not None else None)
    return path


h.backup_root = backup_then_tamper
set_fail("2.0.5")
count = len(installs())
job = update("framework", "2.0.5", FWC["2.0.5"], FW_SEED)
h.backup_root = real_backup
must(job["stage"] == "rollback-failed" and "install.sh differs from the signed release manifest" in job["rollback"]["error"], (job["stage"], job.get("rollback")))
ran = installs()[count:]
must(len(ran) == 1 and "v=2.0.5" in ran[0] and not (MARKERS / "evil").exists(), f"the rollback installer ran from a changed backup: {ran}")
must(tgit("rev-parse", "HEAD", cwd=FW) == FWC["2.0.3"] and tgit("status", "--porcelain", cwd=FW) == "", "source not restored after a refused rollback")
print("       fix note (rollback): changed install.sh in the backup -> rollback refused before its installer, source still restored")
# Put the runtime back for the restore checks below (the refused rollback left 2.0.5 deployed).
set_fail()

# --- fix note: a restored checkout with a changed install.sh is refused before any installer runs ----------------------------
restore_log = tmp / "restore.log"
run("bash", "-c", f"echo 'touch {MARKERS}/evil' >> {FW}/install.sh", user=True)
count = len(installs())
with restore_log.open("w") as out:
    try:
        h.install_restored_component("framework", out)
    except RuntimeError as exc:
        must("install.sh differs from the signed release manifest" in str(exc), exc)
    else:
        raise AssertionError("a restored checkout with a changed install.sh was installed")
must(len(installs()) == count and not (MARKERS / "evil").exists(), "the restore ran an installer from a changed checkout")
tgit("checkout", "--", "install.sh", cwd=FW)
with restore_log.open("w") as out:
    must(h.install_restored_component("framework", out) == "2.0.3", "restore returns the restored version")
must(f"from={h.INSTALL_STAGE_ROOT}/" in installs()[-1] and "v=2.0.3" in installs()[-1], installs()[-1])
must(config_source() == str(FW) and not h.verify_runtime_ownership(runtime_targets), "restore left the config or the runtime wrong")
all_tactical(FW)
stage_left_empty()
print("       fix note (restore): changed install.sh refused before any installer; an unchanged one installs from the verified staging copy")

# --- 13: install.sh's rule and the updater's rule give the same runtime ----------------------------------------------------------
def runtime_copy(name):
    rt = tmp / name
    shutil.copytree(RUNTIME, rt, symlinks=True)
    for current, dirs, names in os.walk(rt):
        for item in [".", *dirs, *names]:
            os.lchown(os.path.join(current, item), UID, GID)
            if not os.path.islink(os.path.join(current, item)):
                os.chmod(os.path.join(current, item), 0o777 if os.path.isdir(os.path.join(current, item)) else 0o666)
    os.chmod(rt / "scripts" / "recovery" / "repair.sh", 0o775)
    return rt


cli_rt, updater_rt = runtime_copy("rt-cli"), runtime_copy("rt-updater")
subprocess.run([sys.executable, "-I", str(ROOT / "scripts/system-update-helper.py"), "--runtime-ownership", "apply",
                str(cli_rt), str(cli_rt / "framework"), str(cli_rt / "scripts")], check=True, capture_output=True, text=True)
h.apply_runtime_ownership(h.runtime_ownership_targets(updater_rt))


def modes(rt):
    return {os.path.relpath(os.path.join(c, n), rt): (os.lstat(os.path.join(c, n)).st_uid, os.lstat(os.path.join(c, n)).st_gid, stat.S_IMODE(os.lstat(os.path.join(c, n)).st_mode))
            for c, ds, ns in os.walk(rt) for n in [*ds, *ns] if os.path.relpath(c, rt).split(os.sep)[0] in {"framework", "scripts", "templates", "."}}


must(modes(cli_rt) == modes(updater_rt), "install.sh and the updater produce different runtime ownership")
must(modes(cli_rt)[os.path.join("scripts", "recovery", "repair.sh")][2] == 0o755 and modes(cli_rt)["VERSION"] == (0, 0, 0o644), modes(cli_rt))
bad = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/system-update-helper.py"), "--runtime-ownership", "verify",
                      str(tmp / "rt-missing"), str(tmp / "rt-missing" / "framework"), str(tmp / "rt-missing" / "scripts")], capture_output=True, text=True)
must(bad.returncode != 0 and "ownership verification failed" in bad.stderr, bad.stderr)
install_sh = (ROOT / "install.sh").read_text(encoding="utf-8")
must("runtime_ownership_rule apply" in install_sh and "runtime_ownership_rule verify" in install_sh, "install.sh does not use the shared rule")
must('cp -a "${SOURCE_FRAMEWORK_DIR}"' not in install_sh and "TEC_TAC_FRAMEWORK_SOURCE=${RECORDED_FRAMEWORK_SOURCE}" in install_sh, "install.sh ownership or source path")
print("       13: install.sh (--runtime-ownership) and the updater apply the same rule with the same result")

# --- review of f72e984, High: VERSION in the checkout is a link to a root-only secret ------------------------------------------
secret_text = "ROOT-ONLY-SECRET-" + uuid.uuid4().hex
secret = tmp / "root-secret-version"
secret.write_text(secret_text + "\n", encoding="utf-8")
os.chmod(secret, 0o600)
run("bash", "-c", f"rm -f {FW}/VERSION && ln -s {secret} {FW}/VERSION", user=True)
must(h._read_version_file(FW) == "", "a VERSION link must not be read")
job = update("framework", "2.0.3", FWC["2.0.3"], FW_SEED)
job_text = json.dumps(job)
must(secret_text not in job_text, "the root-only secret reached the job, history or log")
for folder in (h.JOBS_ROOT, h.HISTORY_ROOT, h.LOGS_ROOT, h.PROVENANCE_ROOT):
    for item in folder.iterdir():
        if item.is_file():
            must(secret_text not in item.read_text(encoding="utf-8", errors="replace"), f"secret in {item}")
must(job["installed_version"] == "2.0.3" and job["source_checkout_version"] == "2.0.3", (job["installed_version"], job.get("source_checkout_version")))
must(job["status"] == "succeeded" and tgit("status", "--porcelain", cwd=FW) == "", (job.get("error"), "the link is a tracked change that is restored"))
for bad in ("1.0; rm -rf /", "x" * 65, "1.0\nINJECT", "", "v 1"):
    (tmp / "vprobe").mkdir(exist_ok=True)
    (tmp / "vprobe" / "VERSION").write_text(bad, encoding="utf-8")
    must(h._read_version_file(tmp / "vprobe") == "", f"unvalidated VERSION accepted: {bad!r}")
(tmp / "vprobe" / "VERSION").write_text("2.0.3-2+build.1\n", encoding="utf-8")
must(h._read_version_file(tmp / "vprobe") == "2.0.3-2+build.1", "a plain version is read")
print("       VERSION link to a root-only file: never followed; the secret never reaches the job, history or log; the installed version comes from root-held state")

# --- lost coverage: verify_rollback_tree refusals ------------------------------------------------------------------------------
cfg_now = h.load_config()
with h.install_stage(str(uuid.uuid4()), "probe") as stage_dir:
    staged = h.stage_release_tree(FW, stage_dir / "tree", "framework")
    for wanted, why in (("2.0.9", "is version 2.0.3, expected 2.0.9"), ("unknown", "installed version is unknown"), ("", "installed version is unknown")):
        try:
            h.verify_rollback_tree(cfg_now, staged, "framework", wanted)
        except RuntimeError as exc:
            must("rollback verification failed" in str(exc) and why in str(exc), exc)
        else:
            raise AssertionError(f"rollback tree accepted for version {wanted!r}")
    unsigned_src = tmp / "unsigned-tree"
    shutil.copytree(FW, unsigned_src, ignore=shutil.ignore_patterns(".git", h.TREE_MANIFEST, h.TREE_SIGNATURE))
    try:
        h.stage_release_tree(unsigned_src, stage_dir / "unsigned", "framework")
    except RuntimeError as exc:
        must("has no signed release manifest" in str(exc), exc)
    else:
        raise AssertionError("an unsigned tree was staged for a rollback")
    unsigned = h.stage_release_tree(unsigned_src, stage_dir / "unsigned2", "framework", allow_unsigned=True)
    try:
        h.verify_rollback_tree(cfg_now, unsigned, "framework", "2.0.3")
    except RuntimeError as exc:
        must("rollback verification failed" in str(exc), exc)
    else:
        raise AssertionError("an unsigned rollback tree was accepted")
    must(str(unsigned.resolve()) not in h._VERIFIED_STAGES, "a refused tree was registered as verified")
print("       verify_rollback_tree refuses an unsigned tree, an unknown version and another version")

# --- lost coverage: links and swapped folders inside manifest paths are refused while staging ---------------------------------
scratch = tmp / "tactical-scratch"
scratch.mkdir()
os.chown(scratch, UID, GID)
for swap, expect in ((f"mv {FW}/framwork {scratch}/moved-framwork && ln -s {scratch}/moved-framwork {FW}/framwork", "framwork/tec_tac/__init__.py"),
                     (f"mv {FW}/install.sh {scratch}/moved-install.sh && ln -s {scratch}/moved-install.sh {FW}/install.sh", "install.sh")):
    run("bash", "-c", swap, user=True)
    with h.install_stage(str(uuid.uuid4()), "probe") as stage_dir:
        try:
            h.stage_release_tree(FW, stage_dir / "tree", "framework")
        except RuntimeError as exc:
            must(expect in str(exc) and "is a link or cannot be read" in str(exc), exc)
        else:
            raise AssertionError(f"a link inside a manifest path was staged: {expect}")
    tgit("checkout", "-f", "--", ".", cwd=FW)
    must(tgit("status", "--porcelain", cwd=FW) == "", "checkout restored after the probe")
print("       stage_release_tree refuses a linked folder and a linked file inside manifest paths")

# --- lost coverage: a checkout path owned by a third account is refused ---------------------------------------------------------
os.lchown(FW / "templates" / "plugin.txt", 4242, 4242)
try:
    h.normalise_source_owner(FW, "framework", h.load_config())
except RuntimeError as exc:
    must("must be owned by tactical" in str(exc) and "chown -R tactical" in str(exc), exc)
else:
    raise AssertionError("a third-party owned path was accepted")
must(os.lstat(FW / "templates" / "plugin.txt").st_uid == 4242, "the third-party file was changed")
os.lchown(FW / "templates" / "plugin.txt", UID, GID)
print("       a path owned by a third account is refused with the chown command")

# --- review round 6, High: the installed version comes from root-held state, never from the checkout -------------------------
# Installed 2.0.3 (runtime VERSION). The Tactical account commits VERSION=0.0.0 in its checkout; an older signed release with
# allow_downgrade false must still be refused as a downgrade, before anything changes and with no installer run.
must(h.installed_version("framework", h.load_config()) == "2.0.3", "root-held installed version")
run("bash", "-c", f"cd {FW} && echo 0.0.0 > VERSION && git -c user.name=t -c user.email=t@t commit -q -am lower", user=True)
lowered = tgit("rev-parse", "HEAD", cwd=FW)
count = len(installs())
job = update("framework", "2.0.2", FWC["2.0.2"], FW_SEED)
must(job["stage"] == "failed-pre-mutation" and "downgrade requires explicit allow_downgrade request" in job["error"], (job["stage"], job.get("error")))
must(job["installed_version"] == "2.0.3" and job["source_checkout_version"] == "0.0.0", (job["installed_version"], job.get("source_checkout_version")))
must(len(installs()) == count and (RUNTIME / "VERSION").read_text(encoding="utf-8").strip() == "2.0.3", "an installer ran or the runtime changed")
# A newer package with that checkout: refused before anything changes, because the rollback copy would not be the installed release.
job = update("framework", "2.0.5", FWC["2.0.5"], FW_SEED)
must(job["stage"] == "failed-pre-mutation" and "source checkout is at version 0.0.0, but the installed framework is 2.0.3" in job["error"], job.get("error"))
must(len(installs()) == count and tgit("rev-parse", "HEAD", cwd=FW) == lowered, "the checkout moved or an installer ran")
tgit("reset", "-q", "--hard", FWC["2.0.3"], cwd=FW)
# --publish-ui-sync takes the expected UI version from root-held state: a checkout at another version is refused.
must(h.installed_version("ui", h.load_config()) == "0.5.2", "deployed UI version")
tgit("checkout", "-q", "--detach", UIC["0.5.1"], cwd=UI)
try:
    h.publish_ui_sync_from_checkout(io.StringIO())
except RuntimeError as exc:
    must("expected 0.5.2" in str(exc), exc)
else:
    raise AssertionError("an older signed UI sync script was published from the checkout")
tgit("checkout", "-q", "dev", cwd=UI)
print("       round 6: a lowered VERSION in the checkout does not open the downgrade gate; a disagreeing checkout and UI sync publish are refused")

# --- review round 6, Medium: root never follows a link or a writable folder above a checkout -------------------------------------
os.chmod(SRC, 0o777)
try:
    h.normalise_source_owner(FW, "framework", h.load_config())
except RuntimeError as exc:
    must(f"the folder {SRC} is not root-owned or is group/world writable" in str(exc), exc)
else:
    raise AssertionError("a world-writable folder above the checkout was accepted")
os.chmod(SRC, 0o755)
outside = tmp / "outside-root"
outside.mkdir()
(outside / "root-file").write_text("root\n", encoding="utf-8")
os.lchown(outside / "root-file", 0, 0)
tparent = tmp / "tactical-parent"
tparent.mkdir()
os.chown(tparent, UID, GID)
(tparent / "framework").symlink_to(outside)
os.lchown(tparent / "framework", UID, GID)
for bad, expect in ((tparent / "framework", "is not root-owned or is group/world writable"),
                    (tmp / "link-to-src" / "framework", "is a symbolic link or not a folder")):
    if bad.parent.name == "link-to-src":
        (tmp / "link-to-src").symlink_to(SRC)
    try:
        h.normalise_source_owner(bad, "framework", h.load_config())
    except RuntimeError as exc:
        must(expect in str(exc), (expect, str(exc)))
    else:
        raise AssertionError(f"accepted: {bad}")
root_link = tmp / "rootdir"
root_link.mkdir()
(root_link / "framework").symlink_to(outside)
try:
    h.normalise_source_owner(root_link / "framework", "framework", h.load_config())
except RuntimeError as exc:
    must("is a symbolic link or not a folder" in str(exc), exc)
else:
    raise AssertionError("a checkout that is itself a link was accepted")
must(os.lstat(outside).st_uid == 0 and os.lstat(outside / "root-file").st_uid == 0, "something outside the checkout changed owner")
h._set_config_line("TEC_TAC_FRAMEWORK_SOURCE", tparent / "framework")
try:
    h._git(["status"], tparent / "framework")
except RuntimeError as exc:
    must("is not root-owned or is group/world writable" in str(exc), exc)
else:
    raise AssertionError("Git ran in a checkout below a Tactical-owned folder")
finally:
    h._set_config_line("TEC_TAC_FRAMEWORK_SOURCE", FW)
print("       round 6: a world-writable or Tactical-owned folder, a linked folder and a linked checkout are refused; nothing outside changes owner")

# --- guards ------------------------------------------------------------------------------------------------------------------------
try:
    h.run_install("framework", FW, io.StringIO())
except RuntimeError as exc:
    must("not staged and verified" in str(exc), exc)
else:
    raise AssertionError("an installer ran from the source checkout")
outside = tmp / "root-secret"
outside.write_text("secret\n", encoding="utf-8")
os.chmod(outside, 0o600)
os.lchown(FW / "VERSION", 0, 0)
os.link(outside, FW / "planted")
try:
    h.normalise_source_owner(FW, "framework", h.load_config())
except RuntimeError as exc:
    must("more than one hard link" in str(exc), exc)
else:
    raise AssertionError("a hard link to a root file was handed to the Tactical account")
must(os.lstat(outside).st_uid == 0, "a root file outside the checkout was given away")
(FW / "planted").unlink()
print("       guards: no installer from a checkout; a hard-linked root file is never handed over")

shutil.rmtree(tmp, ignore_errors=True)
print("[TEST] PASS system update linux staging 1.17.98")

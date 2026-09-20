#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

[[ -f "${ROOT}/framwork/tec_tac/server_backup.py" ]] || fail "Core server-backup provider missing"
[[ -f "${ROOT}/scripts/server-backup-helper.py" ]] || fail "privileged server-backup helper missing"
[[ -f "${ROOT}/docs/server-backup-capability.md" ]] || fail "server-backup developer contract missing"
grep -q 'CAPABILITY_VERSION = "1.5.2"' "${ROOT}/framwork/tec_tac/server_backup.py" || fail "server-backup capability is not 1.5.2"
grep -q 'core.server_backup' "${ROOT}/framwork/tec_tac/server_backup.py" || fail "core.server_backup capability id missing"
grep -q 'register_core_server_backup_capability' "${ROOT}/framwork/tec_tac/apps.py" || fail "Core server-backup capability is not registered by AppConfig"
grep -q 'module_id in {"tec-tac", "core"}' "${ROOT}/framwork/tec_tac/capabilities.py" || fail "capability registry does not recognize Core-owned providers"
grep -Fq '${SERVER_BACKUP_HELPER} --dispatch *' "${ROOT}/install.sh" || fail "narrow server-backup sudoers rule missing"
grep -Fq '${SERVER_BACKUP_HELPER} --tactical-privileged *' "${ROOT}/install.sh" || fail "Tactical backup privilege bridge sudoers rule missing"
[[ -f "${ROOT}/scripts/tactical-backup-sudo.py" ]] || fail "Tactical backup sudo shim missing"
! grep -Eq 'NOPASSWD:[[:space:]]*(ALL|/bin/(ba)?sh|/usr/bin/(ba)?sh)' "${ROOT}/install.sh" || fail "generic shell sudo permission detected"
grep -q 'ALLOWED_ACTIONS.*create_backup.*restore_backup' "${ROOT}/scripts/server-backup-helper.py" || fail "privileged operation allow-list missing"
grep -q 'systemd-run' "${ROOT}/scripts/server-backup-helper.py" || fail "server-backup helper must detach privileged work"
grep -q 'runuser' "${ROOT}/scripts/server-backup-helper.py" || fail "Tactical scripts must execute as Tactical owner"
grep -q 'backup.sh' "${ROOT}/scripts/server-backup-helper.py" || fail "Tactical backup.sh integration missing"
grep -q 'restore.sh' "${ROOT}/scripts/server-backup-helper.py" || fail "Tactical restore.sh integration missing"
grep -q 'tec-tac-backup-.*\\.tgz' "${ROOT}/scripts/server-backup-helper.py" || fail "recovery bundle naming missing"
grep -q 'tactical/' "${ROOT}/scripts/server-backup-helper.py" || fail "separate Tactical bundle component missing"
grep -q 'tec-tac/tec-tac-backup.tar.gz' "${ROOT}/scripts/server-backup-helper.py" || fail "separate Tec-Tac bundle component missing"
grep -q 'checksums.sha256' "${ROOT}/scripts/server-backup-helper.py" || fail "root checksum file missing"
grep -q 'restore_mode' "${ROOT}/framwork/tec_tac/server_backup.py" || fail "restore_mode contract missing"
grep -q 'ftplib' "${ROOT}/scripts/server-backup-helper.py" || fail "native FTP adapter missing"
! grep -A25 'def make_rclone_config' "${ROOT}/scripts/server-backup-helper.py" | grep -q 'dtype == "ftp"' || fail "FTP still configured through rclone"
grep -q 'validate_destination' "${ROOT}/framwork/tec_tac/server_backup.py" || fail "validate_destination provider operation missing"
grep -q '.tectac-validation-' "${ROOT}/scripts/server-backup-helper.py" || fail "job-unique validation object naming missing"
grep -q 'validate_restore' "${ROOT}/framwork/tec_tac/server_backup.py" || fail "validate_restore provider operation missing"
grep -q 'operation_validate_restore' "${ROOT}/scripts/server-backup-helper.py" || fail "validate_restore privileged operation missing"
grep -q 'artifact_valid' "${ROOT}/scripts/server-backup-helper.py" || fail "restore validation artifact/readiness split missing"

PYTHONPATH="${ROOT}/framwork" python3 - "${ROOT}" <<'PY'
import importlib.util, pathlib, tempfile, tarfile, io, hashlib, json, sys, gzip, shutil
root=pathlib.Path(sys.argv[1])
import tec_tac.capabilities as cap
from tec_tac.server_backup import register_core_server_backup_capability, get_server_backup_provider
cap._clear_capabilities_for_tests()
reg=register_core_server_backup_capability()
assert reg.id == "core.server_backup" and reg.module_id == "core" and reg.version == "1.5.2"
assert set(("create_backup","get_job_status","list_backups","restore_backup","apply_retention","validate_destination","validate_restore","store_secret","delete_secret")) <= set(reg.operations)
assert reg.metadata["format_version"] == 2
assert reg.metadata["overrideable_restore_checks"] == ["target.os"]
assert set(reg.metadata["recovery_modes"]) == {"full","tactical","tec_tac"}
provider=get_server_backup_provider()
# Read-only status lookup must not dispatch a privileged job and must sanitize logs.
import tec_tac.server_backup as sb
with tempfile.TemporaryDirectory() as sd:
    sd=pathlib.Path(sd); (sd/"jobs").mkdir(); (sd/"logs").mkdir()
    old_layout=sb.load_layout
    sb.load_layout=lambda:{"TEC_TAC_SERVER_BACKUP_ROOT":str(sd)}
    try:
        jid="11111111-1111-4111-8111-111111111111"
        job={"id":jid,"action":"create_backup","status":"running","stage":"tactical.collect.nginx","stage_label":"Collecting nginx configuration","created_at":"2026-09-20T10:00:00+00:00","started_at":"2026-09-20T10:00:01+00:00","finished_at":None,"error":None,"context":{"source_run_id":"backup-run-42"},"progress":{"current":3,"total":8},"request":{},"result":None}
        (sd/"jobs"/f"{jid}.json").write_text(json.dumps(job))
        (sd/"logs"/f"{jid}.log").write_text("normal line\npassword=hunter2\nhttps://alice:secret@example.invalid/path\nAuthorization: Bearer abc.def\n")
        status=provider.get_job_status(job_id=jid,context={})
        assert status["job_id"]==jid and status["stage"]=="tactical.collect.nginx"
        assert status["stage_label"]=="Collecting nginx configuration"
        assert status["progress"]=={"current":3,"total":8}
        assert all("hunter2" not in line and "alice:secret@" not in line and "abc.def" not in line for line in status["log_tail"])
        status2=provider.get_job_status(source_run_id="backup-run-42",context={})
        assert status2["job_id"]==jid
    finally:
        sb.load_layout=old_layout
# Legacy restore bool remains a compatibility bridge into the new mode contract.
try:
    provider.restore_backup(backup_ref="bad", destination=None, restore_tec_tac=True, context={})
except Exception as exc:
    assert "backup_ref" in str(exc).lower() or "helper" in str(exc).lower() or getattr(exc,"job_id",None)

spec=importlib.util.spec_from_file_location("server_backup_helper",root/"scripts/server-backup-helper.py")
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
assert h.ARCHIVE_RE.fullmatch("tec-tac-backup-2026_09_20__09_15_00.tgz")
assert h.LEGACY_ARCHIVE_RE.fullmatch("rmm-backup-2026_09_20__09_14_32.tar")

# TAR links are safe when both the member path and resolved link target remain
# inside the archive namespace.  Internal symlinks/hardlinks are accepted;
# absolute or escaping targets and special files remain blocked.
def _tar_with(entries, mode="w"):
    bio=io.BytesIO()
    with tarfile.open(fileobj=bio,mode=mode) as tf:
        for entry in entries:
            kind=entry[0]; name=entry[1]
            info=tarfile.TarInfo(name)
            if kind=="file":
                data=entry[2]; info.size=len(data); tf.addfile(info,io.BytesIO(data))
            elif kind=="dir":
                info.type=tarfile.DIRTYPE; tf.addfile(info)
            elif kind=="symlink":
                info.type=tarfile.SYMTYPE; info.linkname=entry[2]; tf.addfile(info)
            elif kind=="hardlink":
                info.type=tarfile.LNKTYPE; info.linkname=entry[2]; tf.addfile(info)
            elif kind=="fifo":
                info.type=tarfile.FIFOTYPE; tf.addfile(info)
    bio.seek(0); return bio

safe=_tar_with([
    ("dir","nginx/sites-available/"),
    ("file","nginx/sites-available/rmm.conf",b"server {}\n"),
    ("dir","nginx/sites-enabled/"),
    ("symlink","nginx/sites-enabled/rmm.conf","../sites-available/rmm.conf"),
    ("hardlink","nginx/rmm-copy.conf","nginx/sites-available/rmm.conf"),
])
with tarfile.open(fileobj=safe,mode="r:") as tf:
    assert len(h.safe_tar_members(tf))==5

for target in ("../../../../etc/passwd","/etc/passwd"):
    bad=_tar_with([("symlink","nginx/sites-enabled/rmm.conf",target)])
    with tarfile.open(fileobj=bad,mode="r:") as tf:
        try: h.safe_tar_members(tf)
        except RuntimeError: pass
        else: raise AssertionError(f"unsafe TAR symlink target accepted: {target}")

missing_hardlink=_tar_with([("hardlink","copy.conf","missing.conf")])
with tarfile.open(fileobj=missing_hardlink,mode="r:") as tf:
    try: h.safe_tar_members(tf)
    except RuntimeError: pass
    else: raise AssertionError("hardlink to missing archive member was accepted")

special=_tar_with([("fifo","pipe")])
with tarfile.open(fileobj=special,mode="r:") as tf:
    try: h.safe_tar_members(tf)
    except RuntimeError: pass
    else: raise AssertionError("TAR FIFO was accepted")

with tempfile.TemporaryDirectory() as xd:
    xd=pathlib.Path(xd)
    payload=xd/"payload.tar.gz"
    with tarfile.open(payload,"w:gz") as tf:
        data=b"server {}\n"
        info=tarfile.TarInfo("etc/tec-tac/sites-available/rmm.conf"); info.size=len(data); tf.addfile(info,io.BytesIO(data))
        link=tarfile.TarInfo("etc/tec-tac/sites-enabled/rmm.conf"); link.type=tarfile.SYMTYPE; link.linkname="../sites-available/rmm.conf"; tf.addfile(link)
    dest=xd/"extract"; dest.mkdir()
    h.safe_extract_payload_tar(payload,dest)
    link=dest/"etc/tec-tac/sites-enabled/rmm.conf"
    assert link.is_symlink() and link.resolve()==(dest/"etc/tec-tac/sites-available/rmm.conf").resolve()
    assert link.read_text()=="server {}\n"

# create_tactical_component must validate the exact native archive before hashing/finalising it.
import inspect
source=inspect.getsource(h.create_tactical_component)
assert source.index("validate_tactical_native_archive(archive)") < source.index("digest = sha256_file(archive)")
assert "TEC_TAC_BACKUP_JOB_ID" in source and "Core narrow privilege bridge" in source
helper_source=(root/"scripts/server-backup-helper.py").read_text()
for required_stage in ("prepare","tactical.backup","tactical.validate","tec_tac.backup","bundle.create","bundle.validate","destination.upload","destination.verify"):
    assert required_stage in helper_source

# Privileged collection output must be private but owned/readable by the
# Tactical account that later creates the native TAR.
import os, pwd, stat, subprocess
with tempfile.TemporaryDirectory() as wd:
    wd=pathlib.Path(wd)
    workspace=wd/"workspace"; (workspace/"nginx").mkdir(parents=True)
    os.chmod(wd,0o755); os.chmod(workspace,0o755); os.chmod(workspace/"nginx",0o755)
    src=wd/"source"; src.write_bytes(b"privileged-backup-material")
    try:
        acct=pwd.getpwnam("nobody")
    except KeyError:
        acct=pwd.getpwuid(os.getuid())
    h._write_workspace_file(workspace,"nginx","rmm.conf",src,acct.pw_uid,acct.pw_gid)
    out=workspace/"nginx"/"rmm.conf"
    st=out.stat()
    assert st.st_uid==acct.pw_uid and st.st_gid==acct.pw_gid
    assert stat.S_IMODE(st.st_mode)==0o600
    if os.geteuid()==0 and shutil.which("runuser"):
        subprocess.run(["runuser","-u",acct.pw_name,"--","test","-r",str(out)],check=True)

# Only the three fixed nginx sites-enabled sources may traverse a symlink, and
# the resolved file must stay beneath the allow-listed sites-available root.
with tempfile.TemporaryDirectory() as nd:
    nd=pathlib.Path(nd)
    available=nd/"sites-available"; enabled=nd/"sites-enabled"
    available.mkdir(); enabled.mkdir()
    real=available/"rmm.conf"; real.write_text("server {}\n")
    link=enabled/"rmm.conf"; link.symlink_to(real)
    assert h._resolve_fixed_nginx_site_source(link, available) == real.resolve()
    outside=nd/"outside.conf"; outside.write_text("server { listen 1; }\n")
    bad=enabled/"frontend.conf"; bad.symlink_to(outside)
    try: h._resolve_fixed_nginx_site_source(bad, available)
    except SystemExit: pass
    else: raise AssertionError("nginx privileged bridge followed a symlink outside sites-available")

with tempfile.TemporaryDirectory() as od:
    od=pathlib.Path(od)
    cfg={"TEC_TAC_SERVER_BACKUP_ROOT":str(od/"state"),"TACTICAL_USER":"root"}
    report=h._vr_new({"backup_ref":"destination:x:tec-tac-backup-test.tgz","restore_mode":"full"},"tec-tac-backup-test.tgz")
    report["sections"]["target"]["status"]="passed"
    h._vr_check(report,"target","target.os","Operating system","failed","ubuntu 24.04")
    h._vr_check(report,"target","target.memory","System memory","passed","ok")
    job={"id":"44444444-4444-4444-8444-444444444444","context":{"requested_by":"alice","source_module":"backups","source_action":"restore"}}
    accepted=h._accept_validation_overrides(cfg,job,report,["target.os"])
    audit_id=accepted["target.os"]
    audit=json.loads((od/"state"/"restore-overrides"/f"{audit_id}.json").read_text())
    assert audit["accepted_by"]=="alice" and audit["check_id"]=="target.os"
    assert audit["backup_ref"]==report["backup_ref"] and audit["restore_mode"]=="full"
    assert audit["original_status"]=="failed" and audit["original_detail"]=="ubuntu 24.04"
    assert h._target_effectively_ready(report) is True

    execution=h._vr_new({"backup_ref":report["backup_ref"],"restore_mode":"full"},"tec-tac-backup-test.tgz")
    execution["sections"]["target"]["status"]="passed"
    h._vr_check(execution,"target","target.os","Operating system","failed","ubuntu 24.04")
    h._authorize_restore_overrides(cfg,execution,{"target.os":audit_id})
    assert h._target_effectively_ready(execution) is True
    assert execution["sections"]["target"]["checks"][0]["overridden"] is True

    stale=h._vr_new({"backup_ref":report["backup_ref"],"restore_mode":"tactical"},"tec-tac-backup-test.tgz")
    stale["sections"]["target"]["status"]="passed"
    h._vr_check(stale,"target","target.os","Operating system","failed","ubuntu 24.04")
    try: h._authorize_restore_overrides(cfg,stale,{"target.os":audit_id})
    except RuntimeError: pass
    else: raise AssertionError("restore accepted an override bound to a different restore mode")

    artifact=h._vr_new({"backup_ref":report["backup_ref"],"restore_mode":"full"},"tec-tac-backup-test.tgz")
    artifact["sections"]["bundle"]["status"]="failed"
    h._vr_check(artifact,"bundle","bundle.structure","Recovery bundle structure","failed","bad checksum")
    try: h._accept_validation_overrides(cfg,job,artifact,["bundle.structure"])
    except RuntimeError: pass
    else: raise AssertionError("artifact-integrity check became overrideable")

    # Restore script override must be prepared before destructive work, must
    # preserve real OS/codename detection, and must fail closed on drift.
    restore_source=od/"restore.sh"
    baseline=(
        '#!/usr/bin/env bash\nSCRIPT_VERSION="67"\n'
        'osname=$(lsb_release -si)\n'
        'codename=$(lsb_release -sc)\n'
        + h.TACTICAL_RESTORE_OS_GATE +
        'echo "$osname $codename"\n'
    )
    restore_source.write_text(baseline)
    class L:
        def __init__(self): self.lines=[]
        def write(self,v): self.lines.append(str(v))
    log=L(); unchanged=od/"restore-original.sh"
    result=h._prepare_tactical_restore_script(restore_source,unchanged,os_override_audit_id=None,log=log)
    assert result["adjusted"] is False and unchanged.read_bytes()==restore_source.read_bytes()
    patched=od/"restore-overridden.sh"
    result=h._prepare_tactical_restore_script(restore_source,patched,os_override_audit_id=audit_id,log=log)
    patched_text=patched.read_text()
    assert result=={"adjusted":True,"baseline":"67","audit_id":audit_id}
    assert h.TACTICAL_RESTORE_OS_GATE not in patched_text
    assert 'osname=$(lsb_release -si)' in patched_text and 'codename=$(lsb_release -sc)' in patched_text
    assert any(audit_id in line for line in log.lines)
    drift=od/"restore-drift.sh"; drift.write_text(baseline.replace('if [[ "$fullrelno" != "22.04" ]]; then','if [[ "$fullrelno" != "22.04" ]];then'))
    try: h._prepare_tactical_restore_script(drift,od/"bad.sh",os_override_audit_id=audit_id,log=log)
    except RuntimeError: pass
    else: raise AssertionError("restore override patch did not fail closed on OS-gate drift")
    wrong=od/"restore-v68.sh"; wrong.write_text(baseline.replace('SCRIPT_VERSION="67"','SCRIPT_VERSION="68"'))
    try: h._prepare_tactical_restore_script(wrong,od/"bad2.sh",os_override_audit_id=audit_id,log=log)
    except RuntimeError: pass
    else: raise AssertionError("restore override patch accepted an uninspected restore.sh version")

with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td)
    # Tec-Tac component creation must exclude the entire mutable state root,
    # even when it contains large historical installers/backups.
    runtime=td/"runtime"; framework_src=td/"framework-src"; ui_src=td/"ui-src"; state=td/"state"
    for path in (runtime,framework_src,ui_src,state): path.mkdir(parents=True,exist_ok=True)
    (runtime/"VERSION").write_text("1.15.5\n"); (runtime/"etc").mkdir(); (runtime/"etc"/"tec-tac.conf").write_text("x")
    (framework_src/"VERSION").write_text("1.15.5\n"); (framework_src/"install.sh").write_text("#!/bin/sh\n")
    (ui_src/"VERSION").write_text("0.11.2\n"); (ui_src/"scripts").mkdir(); (ui_src/"scripts"/"install.sh").write_text("#!/bin/sh\n")
    (state/"system-updates"/"backups").mkdir(parents=True); (state/"system-updates"/"backups"/"old-installer.zip").write_bytes(b"z"*1024)
    (state/"server-backup"/"staging").mkdir(parents=True); (state/"server-backup"/"staging"/"old.tgz").write_bytes(b"b"*1024)
    component=td/"component.tar.gz"
    meta=h.create_tec_tac_component({
      "TEC_TAC_ROOT":str(runtime),"TEC_TAC_FRAMEWORK_SOURCE":str(framework_src),"TEC_TAC_UI_SOURCE":str(ui_src),
      "TEC_TAC_STATE_ROOT":str(state),"TEC_TAC_SERVER_BACKUP_ROOT":str(state/"server-backup"),
      "TEC_TAC_UI_DEPLOY_ROOT":str(state/"ui"/"tec-tac"),
    },component)
    assert meta["state_policy"]["included"] is False
    with tarfile.open(component,"r:gz") as tf:
      # Duplicate-member validation must remain enabled and accept the component.
      members=h.safe_tar_members(tf)
      names=[m.name.lstrip("./") for m in members]
    assert len(names)==len(set(names)), names
    runtime_rel=str(runtime.resolve()).lstrip("/")
    runtime_etc=runtime_rel+"/etc"
    assert names.count(runtime_etc)==1, names
    state_rel=str(state.resolve()).lstrip("/")
    assert not any(n==state_rel or n.startswith(state_rel+"/") for n in names), names

    # make_payload_tar() itself must canonicalize parent/child inputs so callers
    # cannot accidentally emit recursively duplicated archive members.
    redundant=td/"redundant.tar.gz"
    h.make_payload_tar(redundant,[runtime,runtime/"etc",runtime/"etc"/"tec-tac.conf",runtime])
    with tarfile.open(redundant,"r:gz") as tf:
      members=h.safe_tar_members(tf)
      redundant_names=[m.name.lstrip("./") for m in members]
    assert len(redundant_names)==len(set(redundant_names)), redundant_names
    assert redundant_names.count(runtime_etc)==1, redundant_names
    assert redundant_names.count(runtime_etc+"/tec-tac.conf")==1, redundant_names

with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td)
    # Build a valid native Tactical archive and prove byte identity after outer bundling/extraction.
    tactical=td/"rmm-backup-test.tar"
    def tgz_bytes(name="payload.txt", data=b"x", safe_link=False):
      bio=io.BytesIO()
      with tarfile.open(fileobj=bio,mode="w:gz") as nt:
        ti=tarfile.TarInfo(name); ti.size=len(data); nt.addfile(ti,io.BytesIO(data))
        if safe_link:
          link=tarfile.TarInfo("links/payload-link.txt"); link.type=tarfile.SYMTYPE; link.linkname="../payload.txt"; nt.addfile(link)
      return bio.getvalue()
    required={
      "rmm/local_settings.py":b"x",
      "systemd/rmm.service":b"[Service]\nUser=tactical\n",
      "systemd/celery.service":b"x",
      "systemd/celerybeat.service":b"x",
      "systemd/meshcentral.service":b"x",
      "systemd/nats.service":b"x",
      "systemd/nats-api.service":b"x",
      "systemd/daphne.service":b"x",
      "nginx/rmm.conf":b"x",
      "nginx/frontend.conf":b"x",
      "nginx/meshcentral.conf":b"x",
      "meshcentral/mesh.tar.gz":tgz_bytes(safe_link=True),
      "confd/etc-confd.tar.gz":tgz_bytes(),
      "postgres/db-test.psql.gz":gzip.compress(b"select 1;"),
      "postgres/mesh-db-test.psql.gz":gzip.compress(b"select 1;"),
    }
    with tarfile.open(tactical,"w") as tf:
      for name,data in required.items():
        ti=tarfile.TarInfo(name); ti.size=len(data); tf.addfile(ti,io.BytesIO(data))
    native_hash=hashlib.sha256(tactical.read_bytes()).hexdigest()
    h.validate_tactical_native_archive(tactical)

    tec=td/"tec-tac-backup.tar.gz"
    with tarfile.open(tec,"w:gz") as tf:
      for name,data in {
        "opt/tec-tac/VERSION":b"1.15.5\n",
        "etc/tec-tac/config":b"x",
      }.items():
        ti=tarfile.TarInfo(name); ti.size=len(data); tf.addfile(ti,io.BytesIO(data))
    tec_hash=h.sha256_file(tec)
    tmeta={"included":True,"archive":f"tactical/{tactical.name}","archive_name":tactical.name,"sha256":native_hash,"size_bytes":tactical.stat().st_size}
    cmeta={"included":True,"archive":"tec-tac/tec-tac-backup.tar.gz","archive_name":"tec-tac-backup.tar.gz","sha256":tec_hash,"size_bytes":tec.stat().st_size,"framework_version":"1.15.5","ui_version":"0.11.2","paths":{"framework_source":"/opt/tec-tac-src/framework","ui_source":"/opt/tec-tac-src/ui","state_root":"/var/lib/tec-tac"},"state_policy":{"state_root":"/var/lib/tec-tac","included":False,"reason":"mutable runtime/cache/history/staging state is rebuilt after restore"}}
    manifest={"format_version":2,"artifact_type":"tec-tac-recovery-bundle","created_at":h.now(),"backup_class":"manual","components":{"tactical":tmeta,"tec_tac":cmeta},"recovery_modes":["full","tactical","tec_tac"]}
    (td/"manifest.json").write_text(json.dumps(manifest))
    (td/"checksums.sha256").write_text(f"{native_hash}  tactical/{tactical.name}\n{tec_hash}  tec-tac/tec-tac-backup.tar.gz\n")
    bundle=td/"tec-tac-backup-test.tgz"
    with tarfile.open(bundle,"w:gz") as tf:
      tf.add(td/"manifest.json",arcname="manifest.json"); tf.add(td/"checksums.sha256",arcname="checksums.sha256")
      tf.add(tactical,arcname=f"tactical/{tactical.name}"); tf.add(tec,arcname="tec-tac/tec-tac-backup.tar.gz")
    stage=td/"stage"; stage.mkdir(); m,parts=h.validate_recovery_bundle(bundle,"full",stage)
    assert hashlib.sha256(parts["tactical"].read_bytes()).hexdigest()==native_hash
    assert set(m["recovery_modes"])=={"full","tactical","tec_tac"}

    # Tactical-only recovery must not be blocked by corrupt unused Tec-Tac bytes.
    badtec=td/"bad.bin"; badtec.write_bytes(b"corrupt")
    bad=td/"tec-tac-backup-bad.tgz"
    with tarfile.open(bad,"w:gz") as tf:
      tf.add(td/"manifest.json",arcname="manifest.json"); tf.add(td/"checksums.sha256",arcname="checksums.sha256")
      tf.add(tactical,arcname=f"tactical/{tactical.name}"); tf.add(badtec,arcname="tec-tac/tec-tac-backup.tar.gz")
    st2=td/"st2"; st2.mkdir(); h.validate_recovery_bundle(bad,"tactical",st2)
    st3=td/"st3"; st3.mkdir()
    try: h.validate_recovery_bundle(bad,"full",st3)
    except RuntimeError: pass
    else: raise AssertionError("full restore accepted corrupt Tec-Tac component")

    # Non-destructive restore validation: artifact validity is independent of
    # target readiness, and unused component corruption must remain isolated.
    class Log:
      def write(self, value): pass
    cfg={
      "TEC_TAC_SERVER_BACKUP_ROOT":str(td/"state"),
      "TEC_TAC_SERVER_BACKUP_LOCAL_ROOTS":str(td),
      "TACTICAL_ROOT":"/rmm",
      "TACTICAL_USER":"__tectac_missing_test_user__",
    }
    (td/"state"/"staging").mkdir(parents=True)
    job={"id":"11111111-1111-4111-8111-111111111111","request":{"backup_ref":f"destination:x:{bundle.name}","destination":{"id":"x","type":"local","path":str(td)},"restore_mode":"full"}}
    report=h.operation_validate_restore(cfg,job,Log())
    assert report["artifact_valid"] is True
    assert isinstance(report["target_ready"],bool) and report["ok"] == (report["artifact_valid"] and report["target_ready"])
    assert not (td/"state"/"staging"/f"validate-restore-{job['id']}").exists()
    tactical_job={"id":"22222222-2222-4222-8222-222222222222","request":{"backup_ref":f"destination:x:{bad.name}","destination":{"id":"x","type":"local","path":str(td)},"restore_mode":"tactical"}}
    tactical_report=h.operation_validate_restore(cfg,tactical_job,Log())
    assert tactical_report["artifact_valid"] is True, tactical_report
    full_job={"id":"33333333-3333-4333-8333-333333333333","request":{"backup_ref":f"destination:x:{bad.name}","destination":{"id":"x","type":"local","path":str(td)},"restore_mode":"full"}}
    full_report=h.operation_validate_restore(cfg,full_job,Log())
    assert full_report["artifact_valid"] is False

    # Listing semantics expose v2 component flags and mark native Tactical archives legacy/tactical-only.
    dest={"id":"x","type":"local","path":str(td)}
    item=h.backup_item(dest,bundle.name,str(bundle),bundle.stat().st_size,h.now(),{"format_version":2,"backup_class":"manual","components":{"tactical":{"included":True},"tec_tac":{"included":True}},"recovery_modes":["full","tactical","tec_tac"]})
    assert item["format_version"]==2 and not item["legacy"] and "full" in item["recovery_modes"]
    legacy=h.backup_item(dest,tactical.name,str(tactical),tactical.stat().st_size,h.now(),None)
    assert legacy["legacy"] and legacy["recovery_modes"]==["tactical"]

    # Native FTP adapter: fake the protocol object and prove validation is not an rclone path.
    class FakeFTP:
      def __init__(self): self.files={}; self.cwd_path="/"
      def cwd(self,p): self.cwd_path=p
      def mkd(self,p): return p
      def storbinary(self,cmd,fh,blocksize=8192): self.files[cmd.split(" ",1)[1]]=fh.read()
      def retrbinary(self,cmd,cb,blocksize=8192): cb(self.files[cmd.split(" ",1)[1]])
      def delete(self,n): self.files.pop(n,None)
      def nlst(self): return list(self.files)
      def size(self,n): return len(self.files[n])
      def quit(self): pass
      def close(self): pass
    fake=FakeFTP(); old=h.ftp_connect; h.ftp_connect=lambda config,destination,timeout=60: fake
    payload=td/"probe"; payload.write_bytes(b"abc"*100)
    result=h.validation_result({"id":"f","type":"ftp"})
    try:
      h.validate_ftp_roundtrip({}, {"id":"f","type":"ftp","host":"example","username":"u","port":21,"remote_path":"backups","tls_mode":"none"}, payload, h.sha256_file(payload), result, ".tectac-validation-test.bin")
    finally: h.ftp_connect=old
    assert result["checks"]["write"]=="passed" and result["checks"]["delete"]=="passed" and fake.files=={}

print("server backup recovery-bundle contract: PASS")
PY

python3 -m py_compile "${ROOT}/framwork/tec_tac/server_backup.py" "${ROOT}/scripts/server-backup-helper.py"
bash -n "${ROOT}/install.sh"
bash -n "${ROOT}/uninstall.sh"
echo "[TEST] PASS Core recovery-bundle server-backup capability"

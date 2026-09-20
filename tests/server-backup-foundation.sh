#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

[[ -f "${ROOT}/framwork/tec_tac/server_backup.py" ]] || fail "Core server-backup provider missing"
[[ -f "${ROOT}/scripts/server-backup-helper.py" ]] || fail "privileged server-backup helper missing"
[[ -f "${ROOT}/docs/server-backup-capability.md" ]] || fail "server-backup developer contract missing"
grep -q 'CAPABILITY_VERSION = "1.4.0"' "${ROOT}/framwork/tec_tac/server_backup.py" || fail "server-backup capability is not 1.4.0"
grep -q 'core.server_backup' "${ROOT}/framwork/tec_tac/server_backup.py" || fail "core.server_backup capability id missing"
grep -q 'register_core_server_backup_capability' "${ROOT}/framwork/tec_tac/apps.py" || fail "Core server-backup capability is not registered by AppConfig"
grep -q 'module_id in {"tec-tac", "core"}' "${ROOT}/framwork/tec_tac/capabilities.py" || fail "capability registry does not recognize Core-owned providers"
grep -Fq '${SERVER_BACKUP_HELPER} --dispatch *' "${ROOT}/install.sh" || fail "narrow server-backup sudoers rule missing"
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
import importlib.util, pathlib, tempfile, tarfile, io, hashlib, json, sys, gzip
root=pathlib.Path(sys.argv[1])
import tec_tac.capabilities as cap
from tec_tac.server_backup import register_core_server_backup_capability, get_server_backup_provider
cap._clear_capabilities_for_tests()
reg=register_core_server_backup_capability()
assert reg.id == "core.server_backup" and reg.module_id == "core" and reg.version == "1.4.0"
assert set(("create_backup","list_backups","restore_backup","apply_retention","validate_destination","validate_restore","store_secret","delete_secret")) <= set(reg.operations)
assert reg.metadata["format_version"] == 2
assert set(reg.metadata["recovery_modes"]) == {"full","tactical","tec_tac"}
provider=get_server_backup_provider()
# Legacy restore bool remains a compatibility bridge into the new mode contract.
try:
    provider.restore_backup(backup_ref="bad", destination=None, restore_tec_tac=True, context={})
except Exception as exc:
    assert "backup_ref" in str(exc).lower() or "helper" in str(exc).lower() or getattr(exc,"job_id",None)

spec=importlib.util.spec_from_file_location("server_backup_helper",root/"scripts/server-backup-helper.py")
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
assert h.ARCHIVE_RE.fullmatch("tec-tac-backup-2026_09_20__09_15_00.tgz")
assert h.LEGACY_ARCHIVE_RE.fullmatch("rmm-backup-2026_09_20__09_14_32.tar")

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
      names={m.name.lstrip("./") for m in tf.getmembers()}
    state_rel=str(state.resolve()).lstrip("/")
    assert not any(n==state_rel or n.startswith(state_rel+"/") for n in names), names

with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td)
    # Build a valid native Tactical archive and prove byte identity after outer bundling/extraction.
    tactical=td/"rmm-backup-test.tar"
    def tgz_bytes(name="payload.txt", data=b"x"):
      bio=io.BytesIO()
      with tarfile.open(fileobj=bio,mode="w:gz") as nt:
        ti=tarfile.TarInfo(name); ti.size=len(data); nt.addfile(ti,io.BytesIO(data))
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
      "meshcentral/mesh.tar.gz":tgz_bytes(),
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

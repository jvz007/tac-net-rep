#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

[[ -f "${ROOT}/framwork/tec_tac/server_backup.py" ]] || fail "server_backup provider missing"
[[ -f "${ROOT}/scripts/server-backup-helper.py" ]] || fail "privileged server-backup helper missing"
[[ -f "${ROOT}/docs/server-backup-capability.md" ]] || fail "server-backup developer contract missing"
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
grep -q 'rclone' "${ROOT}/scripts/server-backup-helper.py" || fail "rclone remote adapters missing"
grep -q 'store_scp' "${ROOT}/scripts/server-backup-helper.py" || fail "dedicated SCP adapter missing"
grep -q 'manifest.json' "${ROOT}/scripts/server-backup-helper.py" || fail "Tec-Tac payload manifest missing"
grep -q 'state.tar.gz' "${ROOT}/scripts/server-backup-helper.py" || fail "Tec-Tac state payload missing"
grep -q '0600' "${ROOT}/docs/server-backup-capability.md" || fail "root-only secret mode is undocumented"

PYTHONPATH="${ROOT}/framwork" python3 - "${ROOT}" <<'PY'
import importlib.util
import json
import pathlib
import tarfile
import tempfile
import sys

root=pathlib.Path(sys.argv[1])
import tec_tac.capabilities as cap
from tec_tac.server_backup import register_core_server_backup_capability

cap._clear_capabilities_for_tests()
reg=register_core_server_backup_capability()
assert reg.id == "core.server_backup"
assert reg.module_id == "core"
assert reg.version == "1.0.0"
assert set(("create_backup","list_backups","restore_backup","apply_retention","store_secret","delete_secret")) <= set(reg.operations)
status=cap.capability_status("core.server_backup", version=">=1,<2")
# A source-tree unit test does not have the installed root helper, therefore the
# health callback may correctly make the capability unhealthy. Ownership/version
# resolution itself must still treat Core as a framework provider, never missing.
assert status["state"] in {"available","unhealthy"}, status
assert status["module_id"] == "core"

spec=importlib.util.spec_from_file_location("server_backup_helper", root/"scripts/server-backup-helper.py")
helper=importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
assert helper.normalize_remote_path("a/b") == "a/b"
for bad in ("../x","a/../../x"):
    try: helper.normalize_remote_path(bad)
    except RuntimeError: pass
    else: raise AssertionError(f"unsafe remote path accepted: {bad}")
assert helper.validate_destination({"id":"local1","type":"local","path":"/rmmbackups/test"})["type"] == "local"
try: helper.validate_destination({"id":"x","type":"shell","path":"/rmmbackups"})
except RuntimeError: pass
else: raise AssertionError("unsupported arbitrary destination type accepted")

with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td)
    runtime=td/"runtime"; runtime.mkdir(); (runtime/"VERSION").write_text("1.15.0\n")
    source=td/"source"; source.mkdir(); (source/"VERSION").write_text("1.15.0\n"); (source/"install.sh").write_text("#!/bin/sh\n")
    ui=td/"ui"; (ui/"scripts").mkdir(parents=True); (ui/"VERSION").write_text("0.11.2\n"); (ui/"scripts"/"install.sh").write_text("#!/bin/sh\n")
    state=td/"state"; state.mkdir(); (state/"state.json").write_text("{}")
    deploy=td/"deploy"; deploy.mkdir(); (deploy/"VERSION").write_text("0.11.2\n")
    payload=td/"payload"; payload.mkdir()
    cfg={"TEC_TAC_ROOT":str(runtime),"TEC_TAC_FRAMEWORK_SOURCE":str(source),"TEC_TAC_UI_SOURCE":str(ui),"TEC_TAC_STATE_ROOT":str(state),"TEC_TAC_UI_DEPLOY_ROOT":str(deploy),"TEC_TAC_SERVER_BACKUP_ROOT":str(state/"server-backup")}
    files,manifest=helper.create_tec_tac_payload(cfg,payload)
    assert "backend.tar.gz" in files and "ui-source.tar.gz" in files and "state.tar.gz" in files and "manifest.json" in files
    assert manifest["framework_version"] == "1.15.0" and manifest["ui_version"] == "0.11.2"

    good=td/"rmm-backup-test.tar"
    with tarfile.open(good,"w") as tf:
        required={
            "rmm/local_settings.py": b"x",
            "systemd/rmm.service": b"[Service]\nUser=tactical\n",
            "meshcentral/mesh.tar.gz": b"x",
            "confd/etc-confd.tar.gz": b"x",
            "postgres/db-test.psql.gz": b"x",
        }
        for name,data in required.items():
            info=tarfile.TarInfo(name); info.size=len(data); tf.addfile(info, __import__('io').BytesIO(data))
    assert helper.validate_tactical_archive(good, restore_tec_tac=False) is None

print("server backup capability unit contract: PASS")
PY

python3 -m py_compile "${ROOT}/framwork/tec_tac/server_backup.py" "${ROOT}/scripts/server-backup-helper.py"
bash -n "${ROOT}/install.sh"
bash -n "${ROOT}/uninstall.sh"
echo "[TEST] PASS Core privileged server-backup capability"

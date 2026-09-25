#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

[[ -f "${ROOT}/framwork/tec_tac/server_maintenance.py" ]] || fail "server maintenance provider missing"
[[ -f "${ROOT}/framwork/tec_tac/server_maintenance_views.py" ]] || fail "server maintenance API views missing"
[[ -f "${ROOT}/scripts/server-maintenance-helper.py" ]] || fail "server maintenance privileged helper missing"
[[ -f "${ROOT}/docs/server-maintenance-capability.md" ]] || fail "server maintenance developer contract missing"
grep -q 'core.server_maintenance' "${ROOT}/framwork/tec_tac/server_maintenance.py" || fail "capability id missing"
grep -q 'register_core_server_maintenance_capability' "${ROOT}/framwork/tec_tac/apps.py" || fail "AppConfig registration missing"
grep -q 'system/maintenance/jobs/' "${ROOT}/framwork/tec_tac/urls.py" || fail "job API routes missing"
grep -q 'can_manage_privileged_operations' "${ROOT}/framwork/tec_tac/server_maintenance_views.py" || fail "server maintenance privileged RBAC guard missing"
grep -q 'systemd-run' "${ROOT}/scripts/server-maintenance-helper.py" || fail "durable systemd execution missing"
grep -q 'server-maintenance.lock' "${ROOT}/scripts/server-maintenance-helper.py" || fail "global maintenance lock missing"
grep -q 'flock.*LOCK_EX' "${ROOT}/scripts/server-maintenance-helper.py" || fail "exclusive maintenance lock missing"
grep -Fq '${SERVER_MAINTENANCE_HELPER} --dispatch *' "${ROOT}/install.sh" || fail "narrow dispatch sudo rule missing"
grep -Fq '${SERVER_MAINTENANCE_HELPER} --cancel *' "${ROOT}/install.sh" || fail "narrow cancel sudo rule missing"
! grep -Fq '${SERVER_MAINTENANCE_HELPER} --register *' "${ROOT}/install.sh" || fail "runtime account may register privileged actions"
! grep -Eq 'SERVER_MAINTENANCE_HELPER.*(/bin/(ba)?sh|/usr/bin/(ba)?sh|NOPASSWD:[[:space:]]*ALL)' "${ROOT}/install.sh" || fail "arbitrary root shell exposed"
grep -q 'action.registered' "${ROOT}/scripts/server-maintenance-helper.py" || fail "action registration audit missing"
grep -q 'job.finished' "${ROOT}/scripts/server-maintenance-helper.py" || fail "job completion audit missing"
grep -q 'execution_failed' "${ROOT}/scripts/server-maintenance-helper.py" || fail "structured execution failure missing"
grep -q 'timed_out' "${ROOT}/scripts/server-maintenance-helper.py" || fail "structured timeout exit result missing"

python3 -m py_compile \
  "${ROOT}/framwork/tec_tac/server_maintenance.py" \
  "${ROOT}/framwork/tec_tac/server_maintenance_views.py" \
  "${ROOT}/scripts/server-maintenance-helper.py"
bash -n "${ROOT}/install.sh"

PYTHONPATH="${ROOT}/framwork" python3 - "${ROOT}" <<'PY'
import importlib.util, json, os, pathlib, stat, tempfile, uuid, sys
root=pathlib.Path(sys.argv[1])

import tec_tac.capabilities as cap
import tec_tac.server_maintenance as sm
cap._clear_capabilities_for_tests()
reg=sm.register_core_server_maintenance_capability()
assert reg.id=="core.server_maintenance" and reg.version=="1.0.0"
assert {"start","get_job","cancel","list_jobs"} <= set(reg.operations)
assert reg.metadata["arbitrary_shell"] is False and reg.metadata["global_lock"] is True

ctx=cap.build_operation_context(source_module="test",source_action="test.run",requested_by="tester")
assert sm._validate_context(ctx)["requested_by"]=="tester"
for bad in ({}, {"source_module":"x","source_action":"y"}):
    try: sm._validate_context(bad)
    except sm.ServerMaintenanceValidationError: pass
    else: raise AssertionError("incomplete operation context accepted")

spec=importlib.util.spec_from_file_location("sm_helper",root/"scripts/server-maintenance-helper.py")
h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
with tempfile.TemporaryDirectory() as td:
    td=pathlib.Path(td)
    state=td/"state"; registry=td/"registry"; action_root=td/"actions"
    state.mkdir(); registry.mkdir(); action_root.mkdir()
    exe=action_root/"echo-action"
    exe.write_text('#!/usr/bin/env python3\nimport sys\nprint("OUT:"+sys.argv[1])\nprint("ERR",file=sys.stderr)\n')
    exe.chmod(0o755)
    if os.geteuid()==0: os.chown(exe,0,0)
    h.STATE_ROOT=state; h.JOBS_ROOT=state/"jobs"; h.CANCEL_ROOT=state/"cancel-requests"; h.LOGS_ROOT=state/"logs"; h.AUDIT_FILE=state/"audit.jsonl"; h.LOCK_FILE=state/"server-maintenance.lock"; h.REGISTRY_ROOT=registry; h.ACTION_ROOT=action_root
    (state/"jobs").mkdir(); (state/"cancel-requests").mkdir(); (state/"logs").mkdir()
    manifest={"id":"test.echo","revision":"1","executable":str(exe),"argv":[{"param":"value"}],"parameters":{"value":{"type":"string","required":True,"max_length":20}},"timeout_seconds":5,"success_exit_codes":[0],"enabled":True}
    validated=h.validate_manifest(manifest)
    assert validated["id"]=="test.echo"
    params, public=h.validate_parameters(validated,{"value":"hello"})
    assert h.render_argv(validated,params)==[str(exe),"hello"] and public["value"]=="hello"
    try: h.validate_parameters(validated,{"value":"hello","shell":"rm -rf /"})
    except RuntimeError: pass
    else: raise AssertionError("unknown parameter accepted")
    outside=td/"outside"; outside.write_text('#!/bin/sh\nexit 0\n'); outside.chmod(0o755)
    bad=dict(manifest,executable=str(outside))
    try: h.validate_manifest(bad)
    except RuntimeError: pass
    else: raise AssertionError("executable outside registered action root accepted")

    # Direct worker execution proves durable state/output/failure fields without
    # requiring systemd inside the test container. Dispatch itself is separately
    # guarded above by the required systemd-run contract.
    (registry/"test.echo.json").write_text(json.dumps(manifest))
    jid="55555555-5555-4555-8555-555555555555"
    job={"schema":1,"id":jid,"action":"test.echo","action_revision":"1","status":"dispatched","stage":"dispatched","created_at":"2026-09-21T00:00:00+00:00","started_at":None,"finished_at":None,"cancel_requested_at":None,"context":{"source_module":"test","source_action":"test.run","requested_by":"tester"},"parameters":{"value":"hello"},"public_parameters":{"value":"hello"},"lock":{"scope":"global","state":"pending","acquired_at":None},"exit_result":None,"failure":None}
    (state/"jobs"/f"{jid}.json").write_text(json.dumps(job))
    h.run_job(jid)
    finished=json.loads((state/"jobs"/f"{jid}.json").read_text())
    assert finished["status"]=="succeeded" and finished["exit_result"]["exit_code"]==0
    assert finished["lock"]["state"]=="released"
    assert "OUT:hello" in (state/"logs"/f"{jid}.stdout.log").read_text()
    assert "ERR" in (state/"logs"/f"{jid}.stderr.log").read_text()
    assert "job.finished" in (state/"audit.jsonl").read_text()

print("server maintenance capability foundation: PASS")
PY

echo "[TEST] PASS server maintenance foundation"

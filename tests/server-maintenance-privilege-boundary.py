#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import stat
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sm_helper_boundary", ROOT / "scripts/server-maintenance-helper.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def configure(td: pathlib.Path):
    state = td / "state"
    registry = td / "registry"
    actions = td / "actions"
    for p in (state, registry, actions):
        p.mkdir()
    h.STATE_ROOT = state
    h.JOBS_ROOT = state / "jobs"
    h.CANCEL_ROOT = state / "cancel-requests"
    h.LOGS_ROOT = state / "logs"
    h.RUNNING_ROOT = state / "running"
    h.AUDIT_FILE = state / "audit.jsonl"
    h.LOCK_FILE = state / "server-maintenance.lock"
    h.REGISTRY_ROOT = registry
    h.ACTION_ROOT = actions
    for p in (h.JOBS_ROOT, h.CANCEL_ROOT, h.LOGS_ROOT, h.RUNNING_ROOT):
        p.mkdir()
    return state, registry, actions


def action_manifest(exe: pathlib.Path):
    return {
        "id": "test.echo",
        "revision": "1",
        "executable": str(exe),
        "argv": [{"param": "value"}],
        "parameters": {"value": {"type": "string", "required": True, "max_length": 64}},
        "timeout_seconds": 5,
        "success_exit_codes": [0],
        "enabled": True,
    }


def job(jid: str, value: str):
    return {
        "schema": 1,
        "id": jid,
        "action": "test.echo",
        "action_revision": "1",
        "status": "queued",
        "stage": "queued",
        "created_at": "2026-09-25T00:00:00+00:00",
        "started_at": None,
        "finished_at": None,
        "cancel_requested_at": None,
        "context": {"source_module": "test", "source_action": "test.run", "requested_by": "tester"},
        "parameters": {"value": value},
        "public_parameters": {"value": value},
        "lock": {"scope": "global", "state": "pending", "acquired_at": None},
        "exit_result": None,
        "failure": None,
    }


with tempfile.TemporaryDirectory() as raw:
    td = pathlib.Path(raw)
    state, registry, actions = configure(td)
    exe = actions / "echo-action"
    exe.write_text('#!/usr/bin/env python3\nimport sys\nprint(sys.argv[1])\n', encoding="utf-8")
    exe.chmod(0o755)
    if os.geteuid() == 0:
        os.chown(exe, 0, 0)
    (registry / "test.echo.json").write_text(json.dumps(action_manifest(exe)), encoding="utf-8")

    jid = "66666666-6666-4666-8666-666666666666"
    public = h.JOBS_ROOT / f"{jid}.json"
    public.write_text(json.dumps(job(jid, "ORIGINAL")), encoding="utf-8")

    # Claim exactly what root validated, then simulate Tactical replacing its
    # public status/request file before the detached root worker starts.
    claimed_path, claimed = h.claim_job(jid)
    action = h.load_action(claimed["action"])
    params, public_params = h.validate_parameters(action, claimed["parameters"])
    h.write_claimed_job(claimed_path, claimed, parameters=params, public_parameters=public_params, status="dispatched", stage="dispatched", unit=h._systemd_unit(jid))
    public.write_text(json.dumps(job(jid, "ATTACKER_CHANGED")), encoding="utf-8")

    h.run_job(jid)
    out = (h.LOGS_ROOT / f"{jid}.stdout.log").read_text(encoding="utf-8")
    assert "ORIGINAL" in out, out
    assert "ATTACKER_CHANGED" not in out, out
    finished = h.load_claimed_job(jid)[1]
    assert finished["status"] == "succeeded"
    mirrored = json.loads(public.read_text(encoding="utf-8"))
    assert mirrored["parameters"]["value"] == "ORIGINAL"

    # The old predictable .tmp name must not be usable as a root write gadget.
    jid2 = "77777777-7777-4777-8777-777777777777"
    canary = td / "root-canary"
    canary.write_text("UNCHANGED", encoding="utf-8")
    canary.chmod(0o600)
    before = canary.stat()
    legacy_tmp = h.JOBS_ROOT / f"{jid2}.json.tmp"
    legacy_tmp.symlink_to(canary)
    h.mirror_job(job(jid2, "SAFE"))
    after = canary.stat()
    assert canary.read_text(encoding="utf-8") == "UNCHANGED"
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
    assert after.st_uid == before.st_uid and after.st_gid == before.st_gid
    mirror = h.JOBS_ROOT / f"{jid2}.json"
    assert mirror.is_file() and not mirror.is_symlink()

print("server maintenance privileged-boundary regression: PASS")

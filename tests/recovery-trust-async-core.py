#!/usr/bin/env python3
"""D3 regression: Core signer trust queues a privileged job without synchronous polling."""
from __future__ import annotations
import json
import pathlib
import tempfile

from tec_tac import server_backup as sb

with tempfile.TemporaryDirectory() as td:
    root = pathlib.Path(td)
    old_state = sb._state_root
    old_dispatch = sb._dispatch
    old_read = sb._read_job
    dispatched = []
    try:
        sb._state_root = lambda: root
        sb._dispatch = lambda job_id: dispatched.append(job_id)
        def should_not_read(_job_id):
            raise AssertionError("async trust start synchronously polled the job")
        sb._read_job = should_not_read
        result = sb.trust_recovery_signer_core(
            backup_ref="destination:remote-a:tec-tac-backup-d3.tgz",
            destination_id="remote-a",
            expected_key_id="source-a",
            expected_fingerprint="ab" * 32,
            expected_server_name="source-rmm",
            expected_installation_id="install-a",
            context={"source_module":"core","source_action":"recovery.trust_signer","requested_by":"admin"},
        )
        assert result["status"] == "queued" and result["action"] == "trust_recovery_signer"
        assert dispatched == [result["job_id"]]
        job = json.loads((root / "jobs" / f"{result['job_id']}.json").read_text())
        assert job["status"] == "queued"
        assert job["request"]["destination_id"] == "remote-a"
        assert "destination" not in job["request"]
        assert job["request"]["expected_fingerprint"] == "ab" * 32
    finally:
        sb._state_root = old_state
        sb._dispatch = old_dispatch
        sb._read_job = old_read

print("[TEST] PASS D3 recovery trust queues without synchronous web polling")

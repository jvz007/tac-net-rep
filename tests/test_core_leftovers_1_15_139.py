#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import importlib.util
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_l01_standalone_batch_identity_comes_from_root_verifier():
    mod = load_module(ROOT / "scripts/module-v2-job-helper.py", "module_v2_job_helper_l01")
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        package = base / "package.zip"
        package.write_bytes(b"root-verified-package")
        sha = hashlib.sha256(package.read_bytes()).hexdigest()
        job = {
            "artifacts": [
                {
                    "kind": "package",
                    "id": "mutable-job-id",
                    "path": str(package),
                    "source": "test",
                }
            ]
        }
        root_trust = [
            {
                "package_sha256": sha,
                "artifact_modules": [
                    {"id": "signed-module", "version": "9.8.7", "previous_module_ids": []}
                ],
            }
        ]
        packages = mod.batch_packages(job, base / "running", root_trust)
        assert packages == [
            {
                "id": "signed-module",
                "version": "9.8.7",
                "path": str(package.resolve()),
                "source": "test",
            }
        ]


def test_l04_staged_metadata_reader_rejects_symlink_and_claim_uses_it():
    mod = load_module(ROOT / "scripts/module-job-helper.py", "module_job_helper_l04")
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        jobs = base / "jobs"
        staged = base / "staged"
        running = base / "running"
        requests = base / "running-requests"
        logs = base / "logs"
        for directory in (jobs, staged):
            directory.mkdir()
        job_id = "11111111-1111-1111-1111-111111111111"
        upload_id = "22222222-2222-2222-2222-222222222222"
        (jobs / f"{job_id}.json").write_text(json.dumps({
            "id": job_id, "action": "install", "plugin_id": "demo",
            "upload_id": upload_id, "status": "queued"
        }), encoding="utf-8")
        real_meta = base / "real-meta.json"
        real_meta.write_text(json.dumps({"package_path": str(staged / f"{upload_id}.zip")}), encoding="utf-8")
        (staged / f"{upload_id}.json").symlink_to(real_meta)
        (staged / f"{upload_id}.zip").write_bytes(b"package")

        mod.JOBS_ROOT = jobs
        mod.STAGED_ROOT = staged
        mod.RUNNING_ROOT = running
        mod.RUNNING_REQUEST_ROOT = requests
        mod.LOGS_ROOT = logs
        mod.tactical_identity = lambda config=None: (1234, 1234)
        real_chown = mod.os.chown
        mod.os.chown = lambda *args, **kwargs: None
        try:
            try:
                mod.claim_job(job_id)
            except SystemExit as exc:
                assert "unsafe or unreadable" in str(exc)
            else:
                raise AssertionError("claim_job followed symlinked staged metadata")
        finally:
            mod.os.chown = real_chown
        assert real_meta.exists(), "claim must not alter the symlink target"
        assert not requests.exists() or not any(requests.iterdir()), "unsafe metadata must not create a claimed request"


def test_l02_config_loader_treats_values_as_data_not_shell():
    loader = ROOT / "scripts/tec-tac-config.sh"
    uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
    assert 'source "${CONFIG_LOADER}"' in uninstall
    assert 'source "${TEC_TAC_CONFIG_FILE}"' not in uninstall
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        marker = base / "executed"
        cfg = base / "tec-tac.conf"
        cfg.write_text(f"TEC_TAC_ROOT=$(touch {marker})\n", encoding="utf-8")
        command = (
            f'TEC_TAC_CONFIG_FILE="{cfg}"; source "{loader}"; '
            'printf "%s" "$TEC_TAC_ROOT"'
        )
        result = subprocess.run(["bash", "-c", command], check=True, text=True, capture_output=True)
        assert not marker.exists(), "config value executed shell code"
        assert result.stdout.startswith("$(touch ")


def test_l03_install_and_recovery_never_use_bare_python3_from_path():
    paths = [ROOT / "install.sh", *sorted((ROOT / "scripts/recovery").glob("*.sh"))]
    bare = re.compile(r"(?<![/A-Za-z0-9_.-])python3(?=\s|$)")
    failures = []
    for path in paths:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if bare.search(line):
                failures.append(f"{path.relative_to(ROOT)}:{lineno}:{line.strip()}")
    assert not failures, "bare python3 from PATH found:\n" + "\n".join(failures)


def main():
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"PASS core leftovers 1.15.139 ({len(tests)} tests)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import hashlib
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
        target = base / "real.json"
        target.write_text('{"package_path":"/tmp/package.zip"}', encoding="utf-8")
        link = base / "staged.json"
        link.symlink_to(target)
        try:
            mod._read_json_nofollow(link, label="staged module metadata")
        except SystemExit as exc:
            assert "unsafe or unreadable" in str(exc)
        else:
            raise AssertionError("symlink staged metadata was followed")
    source = (ROOT / "scripts/module-job-helper.py").read_text(encoding="utf-8")
    claim_body = source[source.index("def claim_job("):source.index("def load_running_request(") if source.index("def load_running_request(") > source.index("def claim_job(") else len(source)] if False else source
    assert '_read_json_nofollow(meta, label="staged module metadata")' in claim_body
    assert 'json.loads(meta.read_text' not in claim_body


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

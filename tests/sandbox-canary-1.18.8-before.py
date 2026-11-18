#!/usr/bin/python3
"""Core 1.18.8: the canary-first 'before' run. DEV SERVER ONLY, as root, against the INSTALLED Core 1.18.7. Nothing is installed or changed.

    sudo bash tests/sandbox-canary-1.18.8.sh before        (this file is started by that script)

Why: the new rootview rows and the stand-in folder marker must be seen to FAIL on the old Core before the fix goes in, or they prove nothing.

How: the unit is exactly a 1.18.7 run. This script imports the INSTALLED helper (/usr/local/lib/tec-tac/sandbox/sandbox-helper.py) only to take
its real ``canary_row``, ``build_properties`` and ``build_environment``, so the unit properties (the 12 hidden folders, the binds, the limits)
are 1.18.7's own. Everything new comes from the 1.18.8 source tree (the folder above tests/): ``view_plan``, the marker planting,
``parse_runner_rows``, ``group_table`` and ``format_table``. The 1.18.8 runner is handed to the unit as zlib+base64 text through
``python3 -I -c`` (no '$' and no '%' in the argument) and the plan on stdin, because the installed canary folder only holds the 1.18.7 runner.

It never touches the kill switch, never uses the helper's start path, writes no registry row and removes its markers in a finally block. The unit is started
with systemd-run as root through the same properties a 1.18.7 canary run gets; no credential is handed in.

Exit 0 when the ``view /`` row and the stand-in folder marker row show ATTACK SUCCEEDED (expected on 1.18.7) and no row is NOT RUN. Exit 1 when
they do not (the new rows prove nothing) or a row is NOT RUN. Exit 2 when the unit could not be started at all.
"""
from __future__ import annotations

import base64
import importlib.machinery
import importlib.util
import os
import secrets
import subprocess
import sys
import zlib
from pathlib import Path

INSTALLED_HELPER = "/usr/local/lib/tec-tac/sandbox/sandbox-helper.py"
UNIT_SECONDS = 60


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def runner_command(source_dir, group):
    """python3 -I -c '<decompress and run the 1.18.8 runner>' <group>: sys.argv[1:] is [group], __name__ is __main__ (no '$' or '%' in the text)."""
    blob = base64.b64encode(zlib.compress((Path(source_dir) / "scripts" / "sandbox-canary-runner.py").read_bytes(), 9)).decode("ascii")
    code = "import base64,zlib;exec(compile(zlib.decompress(base64.b64decode('" + blob + "')),'sandbox-canary-runner','exec'))"
    return ["/usr/bin/python3", "-I", "-c", code, group]


def resolv_file_for(installed):
    """Core's own resolv.conf as the installed helper builds it; written the way a start writes it when an earlier canary left none."""
    path = installed.core_resolv_file()
    if not os.path.exists(path):
        status = installed.read_status()
        resolvers = installed.usable_resolvers(status, installed.read_upstream_text(), installed.local_deny_now())
        if not resolvers:
            raise SystemExit("no usable upstream name server: run the selftest first (sudo /usr/local/sbin/tec-tac-sandbox --selftest)")
        installed._write_root_file(path, installed.resolv_conf_bytes(resolvers), 0o644)
    return path


def run_group(installed, new, group, plan, source_dir):
    row = installed.canary_row()
    local = installed.local_deny_now()
    status = installed.read_status()
    zswap = isinstance(status.get("systemd_version"), int) and status["systemd_version"] >= installed.ZSWAP_MIN_SYSTEMD
    run_id = secrets.token_hex(16)
    props = installed.build_properties(row, run_id, credential_names=[], deny_extra=local["extra"], resolv_file=resolv_file_for(installed), zswap=zswap)
    argv = [*installed.SYSTEMD_RUN, "--pipe", "--wait", "--collect", "--quiet", f"--unit={installed.unit_name(run_id)}", f"--slice={installed.SLICE}"]
    argv += [f"--property={item}" for item in props]
    argv += [f"--setenv={name}={value}" for name, value in installed.build_environment(row).items()]
    argv += ["--", *runner_command(source_dir, group)]
    import json

    try:
        done = subprocess.run(argv, input=json.dumps(plan).encode("utf-8"), capture_output=True, timeout=UNIT_SECONDS, env=dict(installed.CHILD_ENV), check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"the unit for group {group} could not be started: {type(exc).__name__}")
        raise SystemExit(2) from exc
    finally:
        installed.handoff_path(run_id).unlink(missing_ok=True)  # the installed unit's ExecStopPost wrote one; nothing reads it here
    rows = new.parse_runner_rows(done.stdout)
    if not rows:
        err = done.stderr.decode("utf-8", "replace").strip()[:300]
        print(f"group {group}: the unit printed no result rows (exit {done.returncode}). {err}")
    return rows


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    source_dir = Path(argv[0]) if argv else Path(__file__).resolve().parents[1]
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    installed = load("tectac_sandbox_installed_1_18_7", INSTALLED_HELPER)
    new = load("tectac_sandbox_source_1_18_8", source_dir / "scripts" / "sandbox-helper.py")
    if not hasattr(new, "view_plan") or not hasattr(new, "rootview_plan"):
        raise SystemExit("the helper in the source folder is not the 1.18.8 one")
    table = []
    markers = []
    try:
        markers = new._plant_markers()
        rows = run_group(installed, new, "files", {"markers": markers}, source_dir)
        table.extend(new.group_table("Files", "files", "not found or other content", rows, ["read " + m["path"] for m in markers]))
        rows = run_group(installed, new, "rootview", new.rootview_plan(), source_dir)
        table.extend(new.group_table("Files", "rootview", "only the allowed names are visible", rows))
    finally:
        new.remove_markers()
    print(new.format_table(table))
    attacks = [entry for entry in table if entry["verdict"] == "ATTACK SUCCEEDED"]
    not_run = [entry for entry in table if entry["verdict"] == "NOT RUN"]
    root_row = any(entry["attack"] == "view /" and entry["verdict"] == "ATTACK SUCCEEDED" for entry in table)
    standin_row = any(entry["attack"].startswith("read /tectac-canary-") and entry["verdict"] == "ATTACK SUCCEEDED" for entry in table)
    print(f"\nthe view / row shows ATTACK SUCCEEDED: {'yes' if root_row else 'NO'}; the stand-in folder marker row shows ATTACK SUCCEEDED: {'yes' if standin_row else 'NO'}")
    print(f"BEFORE RUN: {len(attacks)} ATTACK SUCCEEDED, {len(not_run)} NOT RUN (expected on 1.18.7: the view / row, the view /usr/local row and the stand-in folder marker row)")
    return 0 if root_row and standin_row and not not_run else 1


if __name__ == "__main__":
    sys.exit(main())

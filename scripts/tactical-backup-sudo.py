#!/usr/bin/env python3
"""Narrow sudo compatibility shim for Tactical backup.sh.

Tactical backup.sh v34 invokes sudo for a fixed set of root-owned backup
sources. This shim recognizes only those exact command shapes and delegates to
Core's root-owned server-backup helper, which independently validates the
active job and workspace before collecting anything.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

HELPER = "/usr/local/sbin/tec-tac-server-backup"
REAL_SUDO = "/usr/bin/sudo"


def fail(message):
    print(f"tec-tac backup sudo shim: {message}", file=sys.stderr)
    raise SystemExit(2)


def workspace_from_output(value, expected_leaf):
    path = Path(value)
    if path.name != expected_leaf:
        fail("unexpected privileged output filename")
    if len(path.parents) < 2:
        fail("unexpected privileged output path")
    return str(path.parents[1])


def delegate(job_id, operation, workspace):
    result = subprocess.run(
        [REAL_SUDO, "-n", HELPER, "--tactical-privileged", job_id, operation, workspace],
        check=False,
    )
    raise SystemExit(result.returncode)


def main(argv):
    job_id = os.environ.get("TEC_TAC_BACKUP_JOB_ID", "").strip()
    if not job_id:
        fail("missing active Core backup job")
    args = argv[1:]

    # sudo tar -czvf <tmp>/certs/etc-letsencrypt.tar.gz -C /etc/letsencrypt .
    # sudo tar -czvf <tmp>/opt/opt-tactical.tar.gz -C /opt/tactical .
    if len(args) == 6 and args[0] == "tar" and args[1] == "-czvf" and args[3] == "-C" and args[5] == ".":
        output, source = args[2], args[4]
        if source == "/etc/letsencrypt":
            delegate(job_id, "letsencrypt", workspace_from_output(output, "etc-letsencrypt.tar.gz"))
        if source == "/opt/tactical":
            delegate(job_id, "opt-tactical", workspace_from_output(output, "opt-tactical.tar.gz"))
        if source == "/etc/conf.d":
            delegate(job_id, "confd", workspace_from_output(output, "etc-confd.tar.gz"))
        fail("tar source is not allow-listed")

    # sudo cp /etc/nginx/sites-enabled/{rmm,frontend,meshcentral}.conf <tmp>/nginx/
    if len(args) == 3 and args[0] == "cp" and args[1].startswith("/etc/nginx/sites-enabled/"):
        source = Path(args[1])
        op = {
            "rmm.conf": "nginx-rmm",
            "frontend.conf": "nginx-frontend",
            "meshcentral.conf": "nginx-meshcentral",
        }.get(source.name)
        dest = Path(args[2])
        if not op or dest.name != "nginx":
            fail("nginx copy is not allow-listed")
        delegate(job_id, op, str(dest.parent))

    # sudo cp <fixed systemd unit list> <tmp>/systemd/
    if len(args) >= 4 and args[0] == "cp" and Path(args[-1]).name == "systemd":
        allowed = {
            "/etc/systemd/system/rmm.service",
            "/etc/systemd/system/celery.service",
            "/etc/systemd/system/celerybeat.service",
            "/etc/systemd/system/meshcentral.service",
            "/etc/systemd/system/nats.service",
            "/etc/systemd/system/daphne.service",
            "/etc/systemd/system/uvicorn.service",
            "/etc/systemd/system/nats-api.service",
        }
        sources = set(args[1:-1])
        if not sources or not sources.issubset(allowed):
            fail("systemd copy contains a non-allow-listed source")
        delegate(job_id, "systemd", str(Path(args[-1]).parent))

    # Core pre-creates /rmmbackups and refuses package installation during a
    # backup, so mkdir/chown/apt-get should never be needed on the Core path.
    fail("command is not allowed during Core-managed Tactical backup")


if __name__ == "__main__":
    main(sys.argv)

"""Runtime check for Core 1.17.17 module-registered server-maintenance actions. It did NOT run on the development PC (it needs a Linux
server, the root helpers, systemd and a signed module package). DEV SERVER ONLY.

What you need first (Core cannot make these):

* Core 1.17.17 installed on the dev server (so ``/usr/local/sbin/tec-tac-server-maintenance`` knows ``--register-module``).
* A small SIGNED test module, id ``smprobe``, signed by a trusted publisher that holds ``server_maintenance.register``. Its manifest:

      {"id": "smprobe", "type": "extension", "version": "0.1.0", "category": "server",
       "publisher_permissions": ["server_maintenance.register"],
       "permission_groups": {"Probe": ["smprobe.run"]},
       "server_maintenance_actions": [{"id": "smprobe.echo", "permission": "smprobe.run",
                                       "executable": "server_maintenance/actions/echo.sh",
                                       "argv": [{"param": "text"}],
                                       "parameters": {"text": {"type": "string", "required": true, "max_length": 40}},
                                       "timeout_seconds": 30}]}

  with ``server_maintenance/actions/echo.sh`` (``#!/bin/sh`` then ``echo "probe:$1"``). The module validator under pipeline/ must know the
  ``server_maintenance_actions`` key before it accepts this package.
* Install it through the normal module install route (browser or API). Do not register anything by hand. A signed 0.1.1 that drops the
  action is needed only for step 6.

Run it as root on the dev server, from the Tactical backend folder, through manage.py shell:

    cd /rmm/api/tacticalrmm && sudo ../env/bin/python manage.py shell < /path/to/tests/server-maintenance-module-actions-runtime-1.17.17.py

Steps 1 to 5 are read-only apart from the probe job. It prints PASS or FAIL for each step and exits with status 1 when any step fails.
"""
import hashlib
import json
import os
import stat
import sys
import time
import uuid
from pathlib import Path

from accounts.models import Role, User
from tec_tac import rbac
from tec_tac.capabilities import build_operation_context
from tec_tac.server_maintenance import ServerMaintenancePermissionDenied, get_server_maintenance_provider

RESULTS = []
REGISTRY = Path("/etc/tec-tac/server-maintenance/actions.d")
ACTIONS = Path("/usr/local/lib/tec-tac/server-maintenance/actions")
MODULE = "smprobe"
ACTION = "smprobe.echo"
CONTEXT = build_operation_context(source_module=MODULE, source_action="smprobe.runtime-check", requested_by="runtime-check")


def step(name, fn):
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - a runtime probe reports every failure
        RESULTS.append(False)
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        RESULTS.append(True)
        print(f"PASS {name}")


def check(cond, message=""):
    if not cond:
        raise AssertionError(message)


def registered():
    return json.loads((REGISTRY / f"{ACTION}.json").read_text(encoding="utf-8"))


def registration_from_the_install():
    check(os.geteuid() == 0, "run this as root")
    entry = registered()
    check(entry["owner_module"] == MODULE and entry["permission"] == "smprobe.run" and entry["registered_by"] == "module-manifest", entry)
    executable = Path(entry["executable"])
    check(ACTIONS in executable.parents and MODULE in executable.parts, f"the executable is copied into the Core action root: {executable}")
    info = executable.stat()
    check(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o755, (info.st_uid, oct(info.st_mode)))
    check(hashlib.sha256(executable.read_bytes()).hexdigest() == entry["executable_sha256"], "the recorded SHA-256 matches the copy")
    source = Path("/opt/tec-tac/extensions") / MODULE / "server_maintenance" / "actions" / "echo.sh"
    check(source.read_bytes() == executable.read_bytes() and str(executable) != str(source), "an action does not run from the module folder")
    info = (REGISTRY / f"{ACTION}.json").stat()
    check(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o644, "the registry file is root-owned 0644")
    audit = Path("/var/lib/tec-tac/server-maintenance/audit.jsonl").read_text(encoding="utf-8")
    check('"action.registered"' in audit and ACTION in audit, "the helper's audit log names the registration")


def permission_is_enforced():
    provider = get_server_maintenance_provider()
    marker = uuid.uuid4().hex[:8]
    role = Role.objects.create(name=f"smprobe-{marker}")
    user = User(username=f"smprobe-{marker}", role=role)
    user.set_password(uuid.uuid4().hex)
    user.save()
    try:
        before = len(provider.list_jobs(context=CONTEXT, limit=500))
        try:
            provider.start(action=ACTION, parameters={"text": "no"}, context=CONTEXT, user=user)
            raise AssertionError("a user without smprobe.run started the action")
        except ServerMaintenancePermissionDenied as exc:
            check(exc.permission == "smprobe.run", exc.permission)
        check(len(provider.list_jobs(context=CONTEXT, limit=500)) == before, "a refusal creates no job")
        rbac.grant_extension_permission(role, "smprobe.run")
        job = provider.start(action=ACTION, parameters={"text": "hello"}, context=CONTEXT, user=user)
        for _ in range(60):
            job = provider.get_job(job_id=job["id"], context=CONTEXT)
            if job["status"] in ("succeeded", "failed", "cancelled", "dispatch_failed"):
                break
            time.sleep(1)
        check(job["status"] == "succeeded" and "probe:hello" in job["stdout"]["text"] and job["permission"] == "smprobe.run", job)
        rows = {row["id"]: row for row in provider.list_actions(context=CONTEXT)}
        check(rows[ACTION]["permission"] == "smprobe.run" and rows[ACTION]["owner_module"] == MODULE, rows.get(ACTION))
    finally:
        user.delete()
        role.delete()


def a_tampered_executable_stops():
    entry = registered()
    executable = Path(entry["executable"])
    original = executable.read_bytes()
    provider = get_server_maintenance_provider()
    admin = User.objects.filter(is_superuser=True).first()
    check(admin is not None, "a superuser is needed")
    try:
        executable.write_bytes(original + b"\n# tampered\n")
        try:
            job = provider.start(action=ACTION, parameters={"text": "x"}, context=CONTEXT, user=admin)
            check(job["status"] in ("failed", "dispatch_failed"), job["status"])
        except Exception as exc:  # the helper refuses at dispatch; the provider keeps the durable classification
            check("SHA-256" in str(exc) or "validation_failed" in str(getattr(exc, "classification", "")), str(exc))
    finally:
        executable.write_bytes(original)
        os.chmod(executable, 0o755)


def the_sudoers_rule_does_not_reach_the_new_modes():
    text = Path("/etc/sudoers.d/tec-tac-server-maintenance").read_text(encoding="utf-8")
    check("--dispatch" in text and "--cancel" in text and "register" not in text, text)


def disabling_does_not_unregister():
    check((REGISTRY / f"{ACTION}.json").is_file(), "disable the module in the browser, then run this step: the registration is still there")


def an_upgrade_that_drops_the_action_removes_it():
    check(not (REGISTRY / f"{ACTION}.json").exists() and not (ACTIONS / MODULE).exists(),
          "install the signed smprobe 0.1.1 that drops the action first, then run this step; uninstalling smprobe must also leave nothing behind")


for name, fn in (
    ("1. the install registered the action: root-owned copy, SHA-256, owner and permission, audit row", registration_from_the_install),
    ("2. the permission is enforced, a refusal makes no job, a holder runs the action", permission_is_enforced),
    ("3. a tampered executable stops at dispatch and is restored afterwards", a_tampered_executable_stops),
    ("4. the sudoers rule does not name --register-module or --unregister-module", the_sudoers_rule_does_not_reach_the_new_modes),
):
    step(name, fn)
if os.environ.get("SMPROBE_STEP") == "5":
    step("5. disabling the module leaves the registration in place", disabling_does_not_unregister)
if os.environ.get("SMPROBE_STEP") == "6":
    step("6. an upgrade that drops the action, or an uninstall, removes the registry file and the executable", an_upgrade_that_drops_the_action_removes_it)

print(f"{sum(RESULTS)} of {len(RESULTS)} steps passed")
if not all(RESULTS):
    sys.exit(1)

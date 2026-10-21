"""Runtime check for Core 1.17.68 patch lockdown (Johan, 21 October 2026; the former R-36). It did NOT run on the development PC (Django, Celery and Tactical are not installed there).

It shows, on the dev server with Advanced Patch Management installed AND honoured as the replacement of Windows Patching, that Tactical's own patch policy is switched off:
an update set to Ignore stays Ignore after Tactical's own `agent.approve_updates()` with a policy that approves its severity. Use dev02. The only data it touches is the
`action` of ONE existing update row of the test endpoint, and it puts the old value back at the end (also on a failure).

Environment (set on the command line):
    TECTAC_PROBE_AGENT   the Tactical agent number (the database id) of a test endpoint that has at least one not-yet-installed Windows update row

One command:
    cd /rmm/api/tacticalrmm && TECTAC_PROBE_AGENT=12 ../env/bin/python manage.py shell < /path/to/tests/patch-lockdown-runtime-1.17.68.py

What it checks (each line prints PASS or FAIL; the script ends with PASS only when every line passed):
    1 the lockdown is active and names the honoured module (patch_lockdown.status())
    2 both Tactical switches are True in this process (TRMM_DISABLE_APPROVE_UPDATES_TASK and TRMM_DISABLE_WINUPDATES_INSTALL_TASK)
    3 Agent.approve_updates is the guarded method and the guard is installed (approve_guard_installed)
    4 the test endpoint's patch policy approves at least one severity (otherwise this proves nothing: the line says so and FAILs)
    5 an update set to Ignore stays Ignore after agent.approve_updates()
    6 the capability core.patch_lockdown answers the same status
    7 the audit tick step writes at most one row and a second call writes none (the newest row is 'on' for the honoured module once the lockdown is in effect, 'held' only when applying failed in this process or the switch is off)
    8 no Tactical row other than the one update's action was changed (the policy rows are the same before and after)

Not checked here: switching the replacement off again (the switches go back with the restart a module disable already causes). To see the other direction, disable
Advanced Patch Management on dev02, restart, and run this script again: line 1 must then FAIL with active False and approve_updates must approve (nothing is restored by Core).
"""
import os
import sys

from django.conf import settings

from agents.models import Agent
from tec_tac import audit, capabilities, patch_lockdown
from winupdate.models import WinUpdate, WinUpdatePolicy

AGENT = os.environ.get("TECTAC_PROBE_AGENT", "")
if not AGENT.isdigit():
    print("FAIL set TECTAC_PROBE_AGENT to the Tactical agent number of a test endpoint")
    sys.exit(1)

results = []


def step(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))


status = patch_lockdown.status()
print(f"status: {status}")
step("1 the lockdown is active and names the honoured module", status["active"] is True and bool(status["honoured_module"]), str(status))
step("2 both Tactical switches are True", getattr(settings, "TRMM_DISABLE_APPROVE_UPDATES_TASK", False) is True and getattr(settings, "TRMM_DISABLE_WINUPDATES_INSTALL_TASK", False) is True and status["tasks_off"] is True)
step("3 approve_updates is the guarded method", bool(getattr(Agent.approve_updates, patch_lockdown.GUARD_MARKER, False)) and status["approve_guard_installed"] is True)

agent = Agent.objects.get(pk=int(AGENT))
policies_before = sorted(WinUpdatePolicy.objects.values_list("pk", "critical", "important", "moderate", "low", "other", "run_time_hour", "run_time_frequency", "reboot_after_install"))
policy = agent.get_patch_policy()
approving = [name for name in ("critical", "important", "moderate", "low", "other") if getattr(policy, name, None) == "approve"]
severity_of = {"critical": "Critical", "important": "Important", "moderate": "Moderate", "low": "Low", "other": ""}
step("4 the test endpoint's patch policy approves at least one severity", bool(approving), f"approving: {approving}; set one of this endpoint's policy severities to approve first")

row = None
original = None
try:
    if approving:
        wanted = [severity_of[name] for name in approving]
        row = agent.winupdates.filter(installed=False, severity__in=wanted).exclude(action="approve").first()
    if row is None:
        step("5 an update set to Ignore stays Ignore after approve_updates()", False, "no not-yet-installed update of an approved severity on this endpoint; wait for a scan or pick another endpoint")
    else:
        original = row.action
        row.action = "ignore"
        row.save(update_fields=["action"])
        agent.approve_updates()
        row.refresh_from_db()
        step("5 an update set to Ignore stays Ignore after approve_updates()", row.action == "ignore", f"kb {row.kb}, action now {row.action}")
finally:
    if row is not None and original is not None:
        WinUpdate.objects.filter(pk=row.pk).update(action=original)

wired = capabilities.capability_status("core.patch_lockdown")
print(f"capability: {wired}")
step("6 the capability core.patch_lockdown answers", isinstance(wired, dict) and wired.get("available") is True and capabilities.get_capability("core.patch_lockdown").status() == status, str(wired)[:200])

model = audit._auditlog_model()
before = model.objects.filter(action=patch_lockdown.AUDIT_ACTION).count()
first = patch_lockdown.audit_transition()
second = patch_lockdown.audit_transition()
after = model.objects.filter(action=patch_lockdown.AUDIT_ACTION).count()
newest = model.objects.filter(action=patch_lockdown.AUDIT_ACTION).order_by("-entry_time", "-id").first()
meta = ((newest.debug_info or {}).get("metadata") or {}) if newest else {}
step("7 the tick step writes at most one row and none the second time", second is None and after - before in (0, 1) and (first in (None, "on", "held")) and meta.get("state") == ("on" if patch_lockdown.in_effect() else "held"), f"first {first!r}, rows {before} -> {after}, newest {meta}")

policies_after = sorted(WinUpdatePolicy.objects.values_list("pk", "critical", "important", "moderate", "low", "other", "run_time_hour", "run_time_frequency", "reboot_after_install"))
step("8 no policy row was changed", policies_before == policies_after)

ok = bool(results) and all(results) and len(results) == 8
print(("PASS" if ok else "FAIL") + " Core 1.17.68 patch lockdown runtime")
if not ok:
    sys.exit(1)

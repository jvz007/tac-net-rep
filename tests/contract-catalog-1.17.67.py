#!/usr/bin/env python3
# ruff: noqa: F821, E402
"""1.17.67 regression: the contract catalog (framwork/tec_tac/contracts.py) carries every new public route and every changed behaviour.

contracts.py needs Django, so it is read as source (ast.literal_eval). Covered: a row for each of the four new routes (the system update list and
log, the maintenance log, and the history fallback note of the detail route) with query, response, errors, audit and notes; the rows name the
same four headers as the module log route and the shared helper; the run_system_action row carries the plan rule and the limit 105; the
SystemActionCreationRefused and SystemActionRefused rows name declaration_unreadable; the reconcile_schedule and start_one_off_run rows are
untouched in their signatures; the earlier module log row is unchanged; the docs name the new routes and wording; held Lows of the 1.17.66
review (Access-Control-Expose-Headers, the kit props rows) are still pinned as shipped.
"""
from __future__ import annotations

import ast
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "scheduler-completion-harness-1.17.61.py"
exec(compile(HARNESS.read_text(encoding="utf-8"), str(HARNESS), "exec"), globals())  # noqa: S102 - the shared test harness, not user input

tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
values = {}
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ("CORE_CONTRACTS", "RULES", "HTTP_CONTRACT_DETAILS"):
        values[node.targets[0].id] = ast.literal_eval(node.value)
rows, http = values["CORE_CONTRACTS"], values["HTTP_CONTRACT_DETAILS"]
index = {(r["import_path"], r["name"]): r for r in rows}
HEADERS = ("X-Content-Type-Options: nosniff", "Cache-Control: no-store", "X-Tec-Tac-Log-Truncated", "X-Tec-Tac-Log-Bytes", "X-Tec-Tac-Log-Kept", "Access-Control-Expose-Headers")

# ---- the new routes
listing = http["/api/tfd/system/updates/jobs/"]["GET"]
must(set(listing["query"]) == {"page", "page_size", "component", "status"}, listing["query"])
must({"jobs", "count", "total", "page", "page_size", "pages", "next_page", "previous_page"} == set(listing["response"]), listing["response"])
must({"log_bytes", "has_log", "installed_version", "id", "status", "component", "version"} <= set(listing["row"]) and "log_tail" not in listing["row"] and "backup_path" not in listing["row"], sorted(listing["row"]))
text = " ".join(listing["notes"])
must("1.17.67" in text and "history" in text and "500" in text and "no log text" in text and "backup_path is left out" in text, text)
must("Update installed successfully 1.17.16 -> 1.17.17" in text and "custom:system-update-failed" in text and "Update installed successfully to 1.17.17" in text, "the audit wording is in the contract")

detail = http["/api/tfd/system/updates/jobs/<uuid:job_id>/"]["GET"]
must("log_tail" in detail["response"] and "history" in " ".join(detail["notes"]) and "log_bytes" in " ".join(detail["notes"]) and "has_log" in " ".join(detail["notes"]), detail)

for route, kind in (("/api/tfd/system/updates/jobs/<uuid:job_id>/log/", "system_update_job_log"), ("/api/tfd/system/maintenance/jobs/<uuid:job_id>/log/", "server_maintenance_job_log")):
    entry = http[route]["GET"]
    must("core.privileged_operations" in entry["authorization"] and "download" in entry["query"], entry)
    for header in HEADERS:
        must(header in entry["response"] or "same headers as" in entry["response"], (route, header))
    must(set(entry["errors"]) >= {"400", "403", "404", "503"} and kind in entry["audit"] and "No log text" in entry["audit"] and "1.17.67" in " ".join(entry["notes"]), entry)
maint = http["/api/tfd/system/maintenance/jobs/<uuid:job_id>/log/"]["GET"]
must("part" in maint["query"] and "== log ==" in maint["query"]["part"] and "same 404" in maint["authorization"] and "1.1.0" in " ".join(maint["notes"]), maint)
update_log = http["/api/tfd/system/updates/jobs/<uuid:job_id>/log/"]["GET"]
must("system-update-<component>-<YYYY-MM-DD>.log" in update_log["query"]["download"], update_log)
print("       the system update list, detail and log routes and the maintenance log route have rows with query, response, errors, audit and notes")

module_log = http["/api/tfd/modules/v2/jobs/<uuid:job_id>/log/"]["GET"]
for header in HEADERS:
    must(header in module_log["response"], f"the module log row still names {header}")
must("since 1.17.66 on a 200 Access-Control-Expose-Headers" in module_log["response"], "the 1.17.66 text stays")
print("       the module log row is unchanged and still names the four headers (the held Low 'expose the log headers' stays closed)")

# ---- the changed behaviour of the system action rows
run_row = index[("tec_tac.system_actions", "run_system_action")]["purpose"]
for needle in ("Since 1.17.67", "plan mark", "kind plan", "full sorted id set", "OutcomeUnknown", "MAX_MARKS_PER_RUN is 105", "never sent twice", "No module calls run_system_action"):
    must(needle in run_row.replace("an endpoint is never sent twice", "never sent twice"), f"run_system_action row lacks {needle!r}")
must("Since 1.17.66 (module-facing, framework >=1.17.66; Johan CQ178" in run_row and "Since 1.17.65 (module-facing, framework >=1.17.65" in run_row, "the earlier text stays")
for key in (("tec_tac.system_action_confirmation", "SystemActionCreationRefused"), ("tec_tac.system_actions", "SystemActionRefused")):
    must("declaration_unreadable" in index[key]["purpose"], key)
must("1.17.67" in index[("tec_tac.system_action_confirmation", "SystemActionCreationRefused")]["purpose"], "the row says which release added the reason")
for reason in sa.REASONS:
    must(reason in index[("tec_tac.system_actions", "SystemActionRefused")]["purpose"], f"reason {reason} is not described")
meta = sa.system_actions_contract_metadata()
must(meta["version"] == "1.1.0" and "declaration_unreadable" in meta["refusal_reasons"] and meta["delivery"] == "at most once per group", meta)
print("       the run_system_action row carries the plan rule and the limit; both refusal rows name declaration_unreadable; the capability stays 1.1.0")

# ---- the held Low 'kit props rows' stays closed
src = (APP / "contracts.py").read_text(encoding="utf-8")
for needle in ("EditorWindow", "floating", "readOnly", "stacked", "inputId", "describedBy"):
    must(needle in src, f"the browser contract no longer names {needle}")
print("       the kit props rows of 1.17.66 are still in the catalog")

# ---- docs and notes
doc = (ROOT / "docs" / "system-update-logs.md").read_text(encoding="utf-8")
for needle in ("/api/tfd/system/updates/jobs/", "/log/", "download=1", "part=all", "Access-Control-Expose-Headers", "5 MB", "has_log", "log_bytes", "1.1.0", "Update installed successfully"):
    must(needle in doc, f"docs/system-update-logs.md lacks {needle!r}")
audit_doc = (ROOT / "docs" / "module-audit.md").read_text(encoding="utf-8")
for needle in ("system_update_job_log", "server_maintenance_job_log", "Update installed successfully 1.17.16 -> 1.17.17", "custom:system-update-failed", "system-update:<installed|failed>:<job id>"):
    must(needle in audit_doc, f"docs/module-audit.md lacks {needle!r}")
sys_doc = (ROOT / "docs" / "system-actions.md").read_text(encoding="utf-8")
for needle in ("declaration_unreadable", "105", "plan mark", "OutcomeUnknown"):
    must(needle in sys_doc, f"docs/system-actions.md lacks {needle!r}")
notes = (ROOT / "RELEASE_NOTES_1.17.67.md")
must(notes.is_file(), "RELEASE_NOTES_1.17.67.md exists")
body = notes.read_text(encoding="utf-8")
for needle in ("Module-facing", "declaration_unreadable", "plan mark", "105", "Update installed successfully", "Dev-server checklist", "PASS", "FAIL", "tec_tac_check_contract_export", "system-update-logs-runtime-1.17.67.py", "Not run here"):
    must(needle in body, f"the release notes lack {needle!r}")
must((ROOT / "VERSION").read_text(encoding="utf-8").strip() == "1.17.67" and '"version": "1.17.67"' in (ROOT / "tec_tac_package.json").read_text(encoding="utf-8"), "version 1.17.67")
print("       the docs and the release notes name the new routes, wording, reason and limit; VERSION and the package say 1.17.67")
print("PASS contract catalog 1.17.67")

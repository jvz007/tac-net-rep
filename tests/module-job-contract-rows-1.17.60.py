#!/usr/bin/env python3
"""1.17.60 regression: the contract rows, docs, release notes and version of the job history and full log release.

Django is not installed on this PC, so contracts.py is read as text and urls.py as a syntax tree. Checked: both new routes have a contract
entry with the query, headers and notes named in the plan; every path() added in urls.py for them has a contract entry and a mention in
docs/module-job-logs.md; the release notes exist and name MODULE_JOB_RETENTION_DAYS, the module-facing heading and eight PASS/FAIL checklist
steps; VERSION and tec_tac_package.json agree on 1.17.60 (a -N retry suffix is ignored); the docs name every header and the 180 days.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def read(*parts):
    return ROOT.joinpath(*parts).read_text(encoding="utf-8").replace("\r\n", "\n")


# ---- version
version = read("VERSION").strip()
package = json.loads(read("tec_tac_package.json"))["version"]
base = re.sub(r"-\d+$", "", version)
must(base == re.sub(r"-\d+$", "", package) and base in ("1.17.60", "1.17.61", "1.17.62"), f"VERSION {version} and package {package} must be 1.17.60, 1.17.61 or 1.17.62")  # 1.17.61 and 1.17.62 follow
must(not (ROOT / "RELEASE_NOTES_1.17.59.md").exists() and (ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.59.md").is_file(), "1.17.59 notes moved to docs/releases")

# ---- the routes in urls.py
urls = read("framwork", "tec_tac", "urls.py")
paths = [node.args[0].value for node in ast.walk(ast.parse(urls)) if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "path"
         and node.args and isinstance(node.args[0], ast.Constant)]
new_paths = [p for p in paths if p in ("modules/v2/jobs/history/", "modules/v2/jobs/<uuid:job_id>/log/")]
must(len(new_paths) == 2, f"both new path() lines exist: {new_paths}")
must(paths.index("modules/v2/jobs/history/") < paths.index("modules/v2/jobs/<uuid:job_id>/"), "history is listed before the uuid route")

contracts = read("framwork", "tec_tac", "contracts.py")
docs = read("docs", "module-job-logs.md")
for path in new_paths:
    key = f'"/api/tfd/{path}"'
    must(contracts.count(key) == 1, f"one contract entry for {path}")
    must(f"/api/tfd/{path}" in docs, f"docs/module-job-logs.md mentions {path}")

history = contracts[contracts.index('"/api/tfd/modules/v2/jobs/history/"'):contracts.index('"/api/tfd/modules/v2/jobs/<uuid:job_id>/log/"')]
log = contracts[contracts.index('"/api/tfd/modules/v2/jobs/<uuid:job_id>/log/"'):contracts.index('"/api/tfd/session/audit/"')]
for token in ("page_size", "module", "action", "status", "kind", "next_page", "previous_page", "log_bytes", "has_log", "renamed_from", "versions",
              "No row carries log text", "MODULE_JOB_RETENTION_DAYS (180)", "core.privileged_operations"):
    must(token in history, f"history contract names {token}")
for token in ("X-Tec-Tac-Log-Truncated", "X-Tec-Tac-Log-Bytes", "X-Tec-Tac-Log-Kept", "head-and-tail", "download", "5 MB", "403", "404", "503", "module_job_log",
              "core.privileged_operations", "nosniff", "no-store", "text/plain"):
    must(token in log, f"log contract names {token}")
must('"/api/tfd/modules/v2/jobs/": {' in contracts, "the old entry is still there")

for header in ("X-Tec-Tac-Log-Truncated", "X-Tec-Tac-Log-Bytes", "X-Tec-Tac-Log-Kept", "download=1", "nosniff", "no-store"):
    must(header in docs, f"docs name {header}")
must("180" in docs and "MODULE_JOB_RETENTION_DAYS" in docs and "sweep_orphan_logs" in docs and "core.privileged_operations" in docs and "module_job_log" in docs, "docs name the 180 days, the constant, the sweep, the permission and the audit row")
must("docs/module-job-logs.md" in read("docs", "module-replacement.md"), "module-replacement.md points to the new doc")

# ---- release notes
notes = read("RELEASE_NOTES_1.17.60.md") if version == "1.17.60" else read("docs", "releases", "RELEASE_NOTES_1.17.60.md")  # moved to docs/releases by 1.17.61
must("MODULE_JOB_RETENTION_DAYS" in notes and "## Module-facing" in notes, "notes name the constant and carry the module-facing heading")
must(len(re.findall(r"^\d\. \*\*", notes, flags=re.M)) == 8 and notes.count("PASS:") >= 8 and notes.count("FAIL:") >= 8, "eight checklist steps, each with PASS and FAIL")
must("From Core 1.17.60: Module Manager History tab and full logs" in notes and "CQ170" in notes and "CQ171" in notes, "notes name the UI request and the two questions")
for header in ("X-Tec-Tac-Log-Truncated", "X-Tec-Tac-Log-Bytes", "X-Tec-Tac-Log-Kept"):
    must(header in notes, f"notes name {header}")

# ---- requests and questions written for this release
reviews = ROOT.parents[1] / "reviews"
if reviews.is_dir():
    ui = (reviews / "requests" / "ui.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    must("### From Core 1.17.60: Module Manager History tab and full logs (UI 0.12.118, requires Core >=1.17.60)" in ui and "docs/ui-brand-board" in ui, "the UI request is written")
    questions = (reviews / "questions" / "core.md").read_text(encoding="utf-8")
    must("CQ170" in questions and "CQ171" in questions, "both questions are written")

print("PASS module-job-contract-rows-1.17.60")

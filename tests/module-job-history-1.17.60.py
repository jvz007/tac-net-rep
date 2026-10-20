#!/usr/bin/env python3
"""1.17.60 regression: the module job history list, GET /api/tfd/modules/v2/jobs/history/.

Rows come from a stub jobs folder holding every kind of job: install, replace plus rename, batch, bundle, enable that disables, disable
that hands back, remove, visibility, a hotfix apply and a hotfix rollback. Checked: newest first; every whitelist field on every row;
no log text, path, package hash or publisher trust anywhere; the error is one short scrubbed line; has_log and log_bytes are right and
a symlinked log counts as no log; the filters and their combinations; paging (page 2, the 100 cap, a page past the end, 400 for page=0
and page=x); a corrupt record is skipped; a non-manager is refused; the old /modules/v2/jobs/ answer is unchanged and still has log_tail.

Django is not installed on this PC: the view runs through the stub harness of the 1.17.58 licensing tests.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "framwork"))

from tec_tac import module_job_logs as m  # noqa: E402


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


TMP = Path(tempfile.mkdtemp(prefix="tectac-history-"))
m.JOBS_ROOT, m.LOGS_ROOT = TMP / "jobs", TMP / "logs"
m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT = TMP / "hf" / "jobs", TMP / "hf" / "logs"
for folder in (m.JOBS_ROOT, m.LOGS_ROOT, m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT):
    folder.mkdir(parents=True)

N = [0]
LEAKS = ("/var/lib/tec-tac", "/opt/tec-tac", "SECRET-PACKAGE-HASH", "PUBLISHER-TRUST-BLOB", "LOGTAIL-TEXT", "FAKEPASSWORD", "/srv/stage")


def put(day, *, hotfix=False, log=None, **record):
    N[0] += 1
    job_id = f"11111111-1111-4111-8111-{N[0]:012d}"
    base = {"id": job_id, "status": "succeeded", "stage": "done", "requested_by": "alice",
            "created_at": f"2026-10-{day:02d}T10:00:00+00:00", "started_at": f"2026-10-{day:02d}T10:00:05+00:00",
            "finished_at": f"2026-10-{day:02d}T10:01:00+00:00", "error": None,
            "package_sha256": "SECRET-PACKAGE-HASH", "publisher_trust": {"blob": "PUBLISHER-TRUST-BLOB"},
            "package_path": "/srv/stage/pkg.zip", "bundle_path": "/srv/stage/b.zip"}
    base.update(record)
    jobs, logs = (m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT) if hotfix else (m.JOBS_ROOT, m.LOGS_ROOT)
    (jobs / f"{job_id}.json").write_text(json.dumps(base), encoding="utf-8")
    if log is not None:
        (logs / f"{job_id}.log").write_bytes(log.encode("utf-8"))
    return job_id


install = put(1, action="install", plugin_id="reportmanager", plan={"actions": [{"id": "reportmanager", "version": "1.2.0", "action": "install"}]}, log="LOGTAIL-TEXT\n" * 3)
replace_rename = put(2, action="batch_install", plugin_id="newname", plan={"actions": [
    {"id": "newname", "version": "2.0.0", "action": "rename", "previous_module_id": "oldname"}]}, log="x\n")
replace = put(3, action="install", plugin_id="winpatch", plan={"actions": [{"id": "winpatch", "version": "1.1.0", "action": "replace"}]})
batch = put(4, action="batch_install", plugin_id="batch", plan={"actions": [
    {"id": "alpha", "version": "1.0.0", "action": "install"}, {"id": "beta", "version": "0.3.1", "action": "install"}]}, log="batch log\n")
bundle = put(5, action="bundle_install", plugin_id="suite", plan={"actions": [{"id": "suite", "version": "3.0.0"}, {"id": "dep", "version": "1.0.0"}]})
enable = put(6, action="enable", plugin_id="apm", affected_modules=["apm"], disabled_modules=["winpatch"], disable_modules=["winpatch"])
disable = put(7, action="disable", plugin_id="apm", affected_modules=["apm"], enabled_modules=["winpatch"], hand_back_skipped=["other"],
              reconciled_modules=["apm"])
conflict = put(8, action="disable", plugin_id="apm", reason="replacement_conflict", requested_by="system")
remove = put(9, action="remove", plugin_id="oldthing")
visibility = put(10, action="visibility", plugin_id="reportmanager")
failed = put(11, action="install", plugin_id="reportmanager", status="failed", stage="verify",
             error="Install failed: could not read /var/lib/tec-tac/module-manager/jobs/x.json with password=FAKEPASSWORD1\nTraceback second line /opt/tec-tac/x",
             log="a log\n")
hf_apply = put(12, hotfix=True, action="apply", module_id="reportmanager", hotfix_id="hf-1", base_version="1.2.0", log="hotfix log\n")
hf_rollback = put(13, hotfix=True, action="rollback", module_id="reportmanager", hotfix_id="hf-1", status="failed", error="no")
(m.JOBS_ROOT / "22222222-2222-4222-8222-222222222222.json").write_text("{not json", encoding="utf-8")
(m.JOBS_ROOT / "33333333-3333-4333-8333-333333333333.json").write_text("[1, 2]", encoding="utf-8")
(m.JOBS_ROOT / "README.json").write_text("{}", encoding="utf-8")

rows = m.history_rows()
by_id = {row["id"]: row for row in rows}
must(len(rows) == 13, f"13 readable jobs expected (corrupt, non-dict and oddly named files skipped), got {len(rows)}")
must([row["created_at"] for row in rows] == sorted((row["created_at"] for row in rows), reverse=True), "newest first")
must(rows[0]["id"] == hf_rollback and rows[-1]["id"] == install, "the newest row is the hotfix rollback and the oldest the install")
FIELDS = {"id", "kind", "action", "switch", "renamed_from", "module_ids", "versions", "requested_by", "created_at", "started_at", "finished_at",
          "status", "stage", "error", "has_log", "log_bytes", "disabled_modules", "enabled_modules", "reconciled_modules", "hand_back_skipped"}
for row in rows:
    must(set(row) == FIELDS, f"a row has exactly the whitelist fields: {set(row) ^ FIELDS}")
blob = json.dumps(rows)
must("log_tail" not in blob and not any(leak in blob for leak in LEAKS), "no log text, path, package hash or publisher trust in any row")
for forbidden in ("package_sha256", "publisher_trust", "package_path", "bundle_path", "plan", "log_tail"):
    must(all(forbidden not in row for row in rows), f"{forbidden} is not a row field")
print("PASS 13 rows, newest first, exactly the whitelist, nothing from the leak list")

must(by_id[install]["module_ids"] == ["reportmanager"] and by_id[install]["versions"] == {"reportmanager": "1.2.0"} and by_id[install]["kind"] == "module", "install row")
must(by_id[replace_rename]["renamed_from"] == "oldname" and by_id[replace_rename]["versions"] == {"newname": "2.0.0"}, "rename carries renamed_from")
must(by_id[batch]["module_ids"] == ["alpha", "beta"] and "batch" not in by_id[batch]["module_ids"] and by_id[batch]["versions"] == {"alpha": "1.0.0", "beta": "0.3.1"}, "batch lists its modules, not 'batch'")
must(by_id[bundle]["module_ids"] == ["suite", "dep"], "bundle row")
must(by_id[enable]["switch"] is True and by_id[enable]["disabled_modules"] == ["winpatch"], "an enable that disables is a switch")
must(by_id[disable]["switch"] is True and by_id[disable]["enabled_modules"] == ["winpatch"] and by_id[disable]["hand_back_skipped"] == ["other"]
     and by_id[disable]["reconciled_modules"] == ["apm"], "a disable that hands back is a switch with its lists")
must(by_id[conflict]["switch"] is True, "reason replacement_conflict is a switch")
must(by_id[remove]["switch"] is False and by_id[visibility]["action"] == "visibility" and by_id[remove]["versions"] is None, "remove and visibility rows; versions null when the job has none")
must(by_id[hf_apply]["kind"] == "hotfix" and by_id[hf_apply]["versions"] == {"reportmanager": "1.2.0"} and by_id[hf_apply]["module_ids"] == ["reportmanager"], "hotfix apply")
must(by_id[hf_rollback]["action"] == "rollback" and by_id[hf_rollback]["status"] == "failed", "hotfix rollback")
print("PASS install, replace+rename, batch, bundle, switch, remove, visibility and hotfix rows")

err = by_id[failed]["error"]
must(err and "\n" not in err and len(err) <= 200 and err.isascii(), f"error is one short ASCII line: {err!r}")
must("FAKEPASSWORD" not in err and "/var/lib" not in err and "tec-tac" not in err and "Traceback" not in err, f"error is scrubbed and path-free: {err!r}")
long = put(14, action="install", plugin_id="longerr", status="failed", error="é" * 10 + " " + "word " * 100)
must(len(m.history_rows()[0]["error"]) <= 200, "a long error is cut to 200 characters")
must(by_id[install]["error"] is None, "no error is null")
print("PASS error is one short, scrubbed, path-free line")

must(by_id[install]["has_log"] is True and by_id[install]["log_bytes"] == len("LOGTAIL-TEXT\n" * 3), "has_log and log_bytes")
must(by_id[replace]["has_log"] is False and by_id[replace]["log_bytes"] == 0, "no log")
must(by_id[hf_apply]["has_log"] is True and by_id[hf_apply]["log_bytes"] == len("hotfix log\n"), "a hotfix log is counted")
linked = put(15, action="install", plugin_id="linked")
target = TMP / "elsewhere.log"
target.write_text("elsewhere text that is not a job log\n")
try:
    os.symlink(target, m.LOGS_ROOT / f"{linked}.log")
    linked_row = next(row for row in m.history_rows() if row["id"] == linked)
except (OSError, NotImplementedError):
    (m.LOGS_ROOT / f"{linked}.log").write_text("placeholder\n")
    real = os.lstat

    def lstat(path, *a, **k):
        info = real(path, *a, **k)
        if str(path).endswith(f"{linked}.log"):
            values = list(info)
            values[0] = stat.S_IFLNK | 0o777
            return os.stat_result(values)
        return info

    os.lstat = lstat
    try:
        linked_row = next(row for row in m.history_rows() if row["id"] == linked)
    finally:
        os.lstat = real
must(linked_row["has_log"] is False and linked_row["log_bytes"] == 0, "a symlinked log counts as no log")
print("PASS has_log and log_bytes are right; a symlinked log counts as no log")

# ---- filters and paging
page = m.page_history
must({row["id"] for row in page(module="reportmanager")["items"]} == {install, visibility, failed, hf_apply, hf_rollback}, "module filter matches any module_ids and hotfix module")
must({row["id"] for row in page(module="beta")["items"]} == {batch}, "module filter matches inside a batch")
must(page(module="batch")["count"] == 0, "'batch' is not a module")
must({row["id"] for row in page(action="enable")["items"]} == {enable}, "action filter")
must(all(row["status"] == "failed" for row in page(status="failed")["items"]) and page(status="failed")["count"] == 3, "status filter: failed, the hotfix rollback, the long-error job")
must(page(kind="hotfix")["count"] == 2 and page(kind="module")["count"] == 13, "kind filter")
must({row["id"] for row in page(module="reportmanager", status="failed", kind="module")["items"]} == {failed}, "combined filters")
must(page(module="reportmanager", action="rollback")["count"] == 1 and page(module="nobody")["count"] == 0, "combined and empty")
rows_total = len(m.history_rows())
first = page(page_size=5)
must(first["page"] == 1 and first["count"] == rows_total and first["pages"] == (rows_total + 4) // 5 and first["next_page"] == 2 and first["previous_page"] is None and len(first["items"]) == 5, "page 1")
second = page(page=2, page_size=5)
must(second["previous_page"] == 1 and second["items"][0]["id"] == m.history_rows()[5]["id"], "page 2 starts at row 6")
must(page(page_size=1000)["page_size"] == 100 and page(page_size=1000)["pages"] == 1, "page_size is capped at 100")
must(page()["page_size"] == 50, "default page size 50")
beyond = page(page=99, page_size=5)
must(beyond["items"] == [] and beyond["pages"] == first["pages"] and beyond["next_page"] is None and beyond["previous_page"] == 98, "a page past the end is empty with the right pages")
for bad in ({"page": 0}, {"page": "x"}, {"page": -1}, {"page_size": 0}, {"page_size": "x"}, {"page": "1.5"}):
    try:
        page(**bad)
        raise AssertionError(f"{bad} must be refused")
    except m.HistoryParameterError:
        pass
print("PASS filters, combinations, paging, page cap, page past the end, bad values")

# ---- the view and the old route
import licensing_harness_1_17_58 as harness  # noqa: E402

H = harness.install()
v2views = H.v2views
from tec_tac import module_manager as mm  # noqa: E402

mm.JOBS_ROOT, mm.LOGS_ROOT = m.JOBS_ROOT, m.LOGS_ROOT


def get(view, **params):
    request = SimpleNamespace(user=H.User("manager"), query_params=params)
    return view().get(request)


v2views._require_module_manager = lambda user: None
resp = get(v2views.ModuleV2JobHistoryListView, page_size="2", status="failed")
must(resp.status_code == 200 and set(resp.data) == {"jobs", "count", "total", "page", "page_size", "pages", "next_page", "previous_page"}, "the envelope")
must(resp.data["count"] == 2 and resp.data["total"] == 3 and resp.data["pages"] == 2 and resp.data["next_page"] == 2, "the envelope numbers")
must(get(v2views.ModuleV2JobHistoryListView, page="0").status_code == 400 and get(v2views.ModuleV2JobHistoryListView, page="x").status_code == 400, "a bad page is a 400")
must(get(v2views.ModuleV2JobHistoryListView, page_size="nope").status_code == 400, "a bad page_size is a 400")


def refuse(user):
    raise H.PermissionDenied("no")


v2views._require_module_manager = refuse
for view in (v2views.ModuleV2JobHistoryListView, v2views.ModuleV2JobHistoryView):
    try:
        get(view)
        raise AssertionError("a non-manager must be refused")
    except H.PermissionDenied:
        pass
v2views._require_module_manager = lambda user: None

old = get(v2views.ModuleV2JobHistoryView)
must(old.status_code == 200 and set(old.data) == {"jobs", "count"}, "the old route keeps its legacy shape")
must(all("log_tail" in row for row in old.data["jobs"]), "the old route still puts log_tail on every row")
must(any(row["log_tail"] == ["LOGTAIL-TEXT"] * 3 for row in old.data["jobs"]), "the old route still carries the raw log tail")
old_paged = get(v2views.ModuleV2JobHistoryView, page="1", page_size="2")
must(set(old_paged.data) >= {"jobs", "count", "total", "page", "page_size", "pages", "next_page", "previous_page"} and all("log_tail" in row for row in old_paged.data["jobs"]), "the old paged shape")
print("PASS the view: envelope, 400s, 403 for a non-manager, and the old /modules/v2/jobs/ answer unchanged with log_tail")

print("PASS module-job-history-1.17.60")

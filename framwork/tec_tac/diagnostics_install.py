"""Install-state checks for the diagnostics report (1.18.9, request R2 from Welcome).

Django-free on purpose: the stat calls, the config reader and the systemctl runner are passed in, so the rules run in tests
on any PC. Everything here is read-only: os.lstat on a few paths and one injected ``systemctl is-enabled`` call. No root,
no helper, no privilege rule. A fact that cannot be read is "unknown" with the reason, never "pass".
"""
from __future__ import annotations

import os
import posixpath
import stat as stat_module
from collections.abc import Callable
from typing import Any

SOURCE_OWNERSHIP_ID = "core.install.source-ownership"
UI_SYNC_ID = "core.ui.module-sync"
KEY_ACCESS_ID = "core.secret_store.service-access"
KEY_ACCESS_SERVICES = ("rmm", "daphne", "celery", "celerybeat")
DEFAULT_MASTER_KEY_PATH = "/etc/tec-tac/secrets/master.key"
HELP_ID = "core.troubleshooting-diagnostics"
DEFAULT_UI_SYNC_SCRIPT = "/usr/local/lib/tec-tac-ui-sync/scripts/sync-modules.sh"
DEFAULT_UI_DEPLOY_ROOT = "/var/lib/tec-tac/ui/tec-tac"
UI_SYNC_UNIT = "tec-tac-ui-sync-publish.path"
_DISABLED_STATES = {"disabled", "masked", "masked-runtime", "not-found", "linked", "linked-runtime", "static", "indirect", "generated", "transient", "bad"}


def _check(check_id: str, label: str, status: str, summary: str, *, details: Any = None, metadata: dict | None = None) -> dict:
    return {"id": check_id, "label": label, "status": status, "summary": str(summary or ""), "details": details, "help_id": HELP_ID, "metadata": dict(metadata or {})}


def _read_layout(layout_reader: Callable[[], dict]) -> tuple[dict | None, str | None]:
    try:
        return dict(layout_reader()), None
    except (OSError, ValueError) as exc:  # the config file can be unreadable or malformed
        return None, f"{exc.__class__.__name__}: {exc}"


def _parents(path: str) -> list[str]:
    """Every folder from / down to the parent of path, in order."""
    parts = [p for p in posixpath.normpath(path).split("/") if p]
    folders = ["/"]
    for index in range(1, len(parts)):
        folders.append("/" + "/".join(parts[:index]))
    return folders


def _folder_problem(info: Any) -> str | None:
    """The rule open_source_checkout applies in system-update-helper.py: a real folder, root-owned, not group/world writable."""
    if stat_module.S_ISLNK(info.st_mode):
        return "a symbolic link"
    if not stat_module.S_ISDIR(info.st_mode):
        return "not a folder"
    if info.st_uid != 0 or info.st_mode & 0o022:
        return "not root-owned" if info.st_uid != 0 else "group or world writable"
    return None


def _owner_fix(folder: str) -> str:
    return f"Run: sudo chown root:root {folder} && sudo chmod 0755 {folder}"


def _reason(exc: OSError) -> str:
    return f"{exc.__class__.__name__}: {exc.strerror or exc}"


def source_ownership_check(layout_reader: Callable[[], dict], lstat: Callable[[str], Any] = os.lstat) -> dict:
    label = "Source folder ownership"
    layout, error = _read_layout(layout_reader)
    if layout is None:
        return _check(SOURCE_OWNERSHIP_ID, label, "unknown", f"The Tec-Tac layout could not be read ({error}).")
    checkouts = [posixpath.normpath(layout.get(key) or default) for key, default in
                 (("TEC_TAC_FRAMEWORK_SOURCE", "/opt/tec-tac-src/framework"), ("TEC_TAC_UI_SOURCE", "/opt/tec-tac-src/ui"))]
    folders: list[str] = []
    for checkout in checkouts:
        for folder in _parents(checkout):
            if folder not in folders:
                folders.append(folder)
    rows: list[dict] = []
    first_fail: str | None = None
    first_unknown: str | None = None
    for folder in folders:
        try:
            problem = _folder_problem(lstat(folder))
        except FileNotFoundError:
            rows.append({"path": folder, "status": "missing"})
            continue
        except OSError as exc:
            rows.append({"path": folder, "status": "unknown", "reason": _reason(exc)})
            first_unknown = first_unknown or f"{folder} could not be read ({_reason(exc)})."
            continue
        if not problem:
            rows.append({"path": folder, "status": "pass"})
            continue
        rows.append({"path": folder, "status": "fail", "problem": problem})
        if first_fail is None:
            if problem in {"a symbolic link", "not a folder"}:
                first_fail = f"{folder} is {problem}. Replace it with a real folder owned by root. {_owner_fix(folder)}"
            else:
                first_fail = f"{folder} is {problem}. {_owner_fix(folder)}"
    notes: list[str] = []
    for checkout in checkouts:
        try:
            info = lstat(checkout)
        except FileNotFoundError:
            notes.append(f"{checkout} does not exist yet; only the folders above it were checked.")
            continue
        except OSError as exc:
            notes.append(f"{checkout} could not be read ({exc.__class__.__name__}).")
            continue
        # The checkout itself belongs to the Tactical account by design (1.17.98): only a real folder is required.
        if stat_module.S_ISLNK(info.st_mode) or not stat_module.S_ISDIR(info.st_mode):
            problem = "a symbolic link" if stat_module.S_ISLNK(info.st_mode) else "not a folder"
            rows.append({"path": checkout, "status": "fail", "problem": problem})
            first_fail = first_fail or f"{checkout} is {problem}. Replace it with a real folder owned by the Tactical account."
    details = {"folders": rows, "checkouts": checkouts, "notes": notes}
    metadata = {"checkouts": checkouts, "folders_checked": folders}
    if first_fail:
        return _check(SOURCE_OWNERSHIP_ID, label, "fail", first_fail, details=details, metadata=metadata)
    if first_unknown:
        return _check(SOURCE_OWNERSHIP_ID, label, "unknown", first_unknown, details=details, metadata=metadata)
    return _check(SOURCE_OWNERSHIP_ID, label, "pass", "Every folder above the source checkouts is root-owned and not writable by others.", details=details, metadata=metadata)


def _file_part(path: str, lstat: Callable[[str], Any], *, executable: bool) -> dict:
    try:
        info = lstat(path)
    except FileNotFoundError:
        return {"path": path, "status": "fail", "reason": "missing"}
    except OSError as exc:
        return {"path": path, "status": "unknown", "reason": _reason(exc)}
    if stat_module.S_ISLNK(info.st_mode):
        return {"path": path, "status": "fail", "reason": "a symbolic link"}
    if not stat_module.S_ISREG(info.st_mode):
        return {"path": path, "status": "fail", "reason": "not a regular file"}
    if info.st_uid != 0:
        return {"path": path, "status": "fail", "reason": "not root-owned"}
    if info.st_mode & 0o022:
        return {"path": path, "status": "fail", "reason": "group or world writable"}
    if executable and not info.st_mode & 0o111:
        return {"path": path, "status": "fail", "reason": "not executable"}
    return {"path": path, "status": "pass", "mtime": info.st_mtime}


def _published_part(script: str, lstat: Callable[[str], Any]) -> dict:
    reader = posixpath.join(posixpath.dirname(script), "tec-tac-config.sh")
    files = [_file_part(script, lstat, executable=True), _file_part(reader, lstat, executable=False)]
    folders = []
    for folder in _parents(script):
        try:
            problem = _folder_problem(lstat(folder))
        except FileNotFoundError:
            folders.append({"path": folder, "status": "fail", "reason": "missing"})
            continue
        except OSError as exc:
            folders.append({"path": folder, "status": "unknown", "reason": _reason(exc)})
            continue
        folders.append({"path": folder, "status": "fail", "reason": problem} if problem else {"path": folder, "status": "pass"})
    rows = files + folders
    failed = [row for row in rows if row["status"] == "fail"]
    unknown = [row for row in rows if row["status"] == "unknown"]
    if failed:
        first = failed[0]
        if first["path"] == script and first["reason"] == "missing":
            fix = "The UI sync script is not published. Install Core or run a UI System Update to publish it."
        else:
            fix = f"{first['path']} is {first['reason']}. Run a UI System Update, or reinstall Core, to publish a root-owned copy."
        return {"part": "published", "status": "fail", "fix": fix, "rows": rows}
    if unknown:
        return {"part": "published", "status": "unknown", "fix": f"{unknown[0]['path']} could not be read ({unknown[0]['reason']}).", "rows": rows}
    return {"part": "published", "status": "pass", "rows": rows, "mtime": files[0]["mtime"]}


def _current_part(script_mtime: float, version_path: str, stat: Callable[[str], Any]) -> dict:
    try:
        deployed = stat(version_path).st_mtime
    except OSError as exc:
        return {"part": "current", "status": "unknown", "fix": f"The installed UI VERSION file could not be read ({exc.__class__.__name__}).", "path": version_path}
    if script_mtime < deployed:
        return {"part": "current", "status": "fail", "fix": "The UI sync script is older than the installed UI. Run a UI System Update, or wait for the path unit to publish it.", "path": version_path}
    return {"part": "current", "status": "pass", "path": version_path}


def _unit_part(runner: Callable[[str], Any]) -> dict:
    try:
        result = runner(UI_SYNC_UNIT)
    except (OSError, TimeoutError) as exc:  # missing systemctl, no bus, or the runner's 3 second limit
        return {"part": "path-unit", "status": "unknown", "fix": f"systemctl could not be run ({exc.__class__.__name__}).", "unit": UI_SYNC_UNIT}
    state = str((result.get("state") if isinstance(result, dict) else result) or "").strip().lower()
    if state in {"enabled", "enabled-runtime"}:
        return {"part": "path-unit", "status": "pass", "state": state, "unit": UI_SYNC_UNIT}
    if state in _DISABLED_STATES:
        return {"part": "path-unit", "status": "fail", "state": state, "unit": UI_SYNC_UNIT,
                "fix": f"The path unit {UI_SYNC_UNIT} is not enabled ({state}). Reinstall Core to re-create it."}
    return {"part": "path-unit", "status": "unknown", "state": state or "unknown", "unit": UI_SYNC_UNIT, "fix": f"systemctl gave no clear answer for {UI_SYNC_UNIT}."}


def ui_module_sync_check(layout_reader: Callable[[], dict], lstat: Callable[[str], Any] = os.lstat,
                         systemctl_runner: Callable[[str], Any] | None = None, stat: Callable[[str], Any] = os.stat) -> dict:
    label = "UI module sync"
    layout, error = _read_layout(layout_reader)
    if layout is None:
        return _check(UI_SYNC_ID, label, "unknown", f"The Tec-Tac layout could not be read ({error}).")
    script = posixpath.normpath(layout.get("UI_SYNC_SCRIPT") or DEFAULT_UI_SYNC_SCRIPT)
    version_path = posixpath.join(layout.get("TEC_TAC_UI_DEPLOY_ROOT") or DEFAULT_UI_DEPLOY_ROOT, "VERSION")
    published = _published_part(script, lstat)
    if published["status"] == "pass":
        current = _current_part(published["mtime"], version_path, stat)
    else:
        current = {"part": "current", "status": "skipped", "path": version_path}
    if systemctl_runner is None:
        unit = {"part": "path-unit", "status": "unknown", "unit": UI_SYNC_UNIT, "fix": "No systemctl runner was available."}
    else:
        unit = _unit_part(systemctl_runner)
    parts = [published, current, unit]
    failed = [p for p in parts if p["status"] == "fail"]
    unknown = [p for p in parts if p["status"] == "unknown"]
    details = {"script": script, "parts": parts,
               "limit": "Cannot prove the published bytes match the signed UI release (that needs root). Proves published, root-owned, not writable by others and not older than the installed UI."}
    metadata = {"script": script, "version_file": version_path, "unit": UI_SYNC_UNIT, "parts": {p["part"]: p["status"] for p in parts}}
    if failed:
        return _check(UI_SYNC_ID, label, "fail", " ".join(p["fix"] for p in failed), details=details, metadata=metadata)
    if unknown:
        return _check(UI_SYNC_ID, label, "unknown", " ".join(p["fix"] for p in unknown), details=details, metadata=metadata)
    return _check(UI_SYNC_ID, label, "pass", "The UI sync program is published, root-owned, not older than the installed UI, and its path unit is enabled.", details=details, metadata=metadata)


def _service_row(service: str, pid_reader: Callable[[str], Any], status_reader: Callable[[int], str], key_gid: int) -> dict:
    """One service's answer: ok, missing_group, not_running or unknown. Only the Groups line of /proc/<pid>/status is read."""
    try:
        raw = pid_reader(f"{service}.service")
        pid = int(str(raw).strip() or 0)
    except (OSError, TimeoutError, ValueError) as exc:
        return {"service": service, "state": "unknown", "reason": f"The service's process id could not be read ({exc.__class__.__name__})."}
    if pid <= 1:
        return {"service": service, "state": "not_running", "reason": "The service has no running process."}
    try:
        text = status_reader(pid)
    except OSError as exc:
        return {"service": service, "state": "unknown", "reason": f"The process's group list could not be read ({exc.__class__.__name__})."}
    groups = None
    for line in str(text).splitlines():
        if line.startswith("Groups:"):
            groups = line[len("Groups:"):].split()
            break
    if groups is None:
        return {"service": service, "state": "unknown", "reason": "The process status has no Groups line."}
    if str(key_gid) in groups:
        return {"service": service, "state": "ok"}
    return {"service": service, "state": "missing_group", "reason": f"The live process does not carry group id {key_gid}."}


def secret_key_service_access_check(key_stat: Callable[[str], Any] = os.stat, pid_reader: Callable[[str], Any] | None = None,
                                    status_reader: Callable[[int], str] | None = None, key_path: str = DEFAULT_MASTER_KEY_PATH,
                                    services: tuple = KEY_ACCESS_SERVICES) -> dict:
    """1.18.54: does each running Core service carry the group that owns the secret store master key? Read-only and Django-free. The
    key file is only stat-ed (its group id); its content is never opened. The answer holds service names, group numbers and states."""
    label = "Services can read the secret store key"
    try:
        key_gid = int(key_stat(key_path).st_gid)
    except OSError as exc:
        return _check(KEY_ACCESS_ID, label, "unknown", f"The master key file could not be inspected ({_reason(exc)}), so no service was compared with it.")
    if pid_reader is None or status_reader is None:
        return _check(KEY_ACCESS_ID, label, "unknown", "No process reader was available, so no service was compared with the key's group.")
    rows = [_service_row(service, pid_reader, status_reader, key_gid) for service in services]
    details = {"key_group_id": key_gid, "services": rows}
    metadata = {"key_group_id": key_gid, "services": {r["service"]: r["state"] for r in rows}}
    missing = [r["service"] for r in rows if r["state"] == "missing_group"]
    unknown = [r["service"] for r in rows if r["state"] == "unknown"]
    if missing:
        names = ", ".join(f"{n}.service" for n in missing)
        return _check(KEY_ACCESS_ID, label, "fail",
                      f"{names} runs without the group that owns the secret store key (gid {key_gid}), so it cannot read the key. Run the installer again, "
                      "or check the tec-tac.conf drop-in for that service, then restart it. The key file stays as it is.", details=details, metadata=metadata)
    if unknown:
        return _check(KEY_ACCESS_ID, label, "unknown", f"Could not tell for {', '.join(unknown)}. Nothing was assumed.", details=details, metadata=metadata)
    running = [r for r in rows if r["state"] == "ok"]
    if not running:
        return _check(KEY_ACCESS_ID, label, "unknown", "No Core service was running, so nothing could be compared with the key's group.", details=details, metadata=metadata)
    return _check(KEY_ACCESS_ID, label, "pass", f"{len(running)} running service(s) carry the key's group; services that are stopped were not checked.", details=details, metadata=metadata)

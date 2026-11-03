"""Module update detection and notices (Core 1.17.104, phase 1 of docs/planning/module-auto-update/SPEC-MODULE-AUTO-UPDATE.md).

Phase 1 is "notify and highlight" only (Johan, 3 November 2026). Core installs nothing by itself here: there is no policy, no window,
no queue and no automatic install. A person still updates a module through the existing Online catalog and install path.

What this file does:

* ``list_updates`` reads the Online catalog exactly as the Modules page sees it (``module_repository.online_catalog``: the cached
  repository indexes, the installed modules and their compatibility) and returns every installed module with a newer release. Each row
  carries the level (patch, minor or major from plain semantic versioning; anything else, such as a pre-release or a ``-N`` rebuild,
  is ``other``), whether it can be installed now and, when it cannot, why (a newer Core, a missing or older dependency, a source
  change). It makes no network call. Licensed repositories list only entitled releases, and a refused licence empties that list, so
  nothing beyond what the cached catalogue shows is ever reported.
* ``detect_and_notify`` runs in a Celery worker: after a manual repository sync (queued by the sync routes, never run in the request
  thread) and after the daily scheduled sync. It raises one Core notice per new module version for the active effective superusers
  only, and writes one audit row when a version is first detected. A version is announced once and never again, even after the
  notice is read or cleared: the dedupe record is a small file beside the repository caches, one entry per module. A release whose
  repository's last sync did not succeed (offline, a refused licence, refused credentials, a retired repository) is never announced.
* The read-only contract ``core.module_updates`` 1.0.0 (``tec_tac.module_updates.updates_for_module``): the same list for a verified
  calling module whose catalog category is ``server`` (for example Notifications, later). Every other caller is refused and audited;
  a wider read waits for Johan (fail closed: a read for every module would be a new global read).

No email is sent in this release (assumption recorded in reviews/questions/core.md, 3 November 2026). Nothing here depends on a module.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("tec_tac.module_updates")

CAPABILITY_ID = "core.module_updates"
CAPABILITY_VERSION = "1.0.0"
OPERATIONS = ("updates_for_module",)

# The dedupe record lives beside the repository caches: that directory is root:tactical-group 2770, so both the web and the Celery
# processes may write it (module_repository writes its caches there).
STATE_ROOT = Path("/var/lib/tec-tac/module-manager/repositories")
STATE_FILE = STATE_ROOT / "update-notices.json"
STATE_LOCK = STATE_ROOT / "update-notices.lock"
STATE_LOCK_WAIT_SECONDS = 5.0
STATE_LOCK_POLL_SECONDS = 0.1
MAX_STATE_RECORDS = 1000

NOTICE_PREFIX = "module-update:"
NOTICE_SOURCE = "core"
NOTICE_LEVEL = "info"
NOTICE_TITLE = "Module update available"
NOTICE_ACTION_LABEL = "Open Modules"
NOTICE_ACTION_ROUTE = "/modules"
MESSAGE_MAX = 600

AUDIT_ACTION = "custom:update-detected"
AUDIT_OBJECT_TYPE = "module_update"
AUDIT_SERVICE = "module-updates"
AUDIT_IDENTITY = "system (module update detection)"

LEVELS = ("major", "minor", "patch", "other")
ALLOWED_CALLER_CATEGORIES = frozenset({"server"})
DENY_AUDIT_INTERVAL_SECONDS = 300
_DENY_AUDITED: dict[tuple[str, str], float] = {}
_DENY_LOCK = threading.Lock()
TRIGGERS = frozenset({"manual-sync", "daily-sync"})
LIST_CACHE_SECONDS = 30
BROKER_TIMEOUT_SECONDS = 2
TASK_EXPIRES_SECONDS = 3600
TEXT_MAX = 120

_PLAIN_SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_LIST_CACHE: dict[str, Any] = {"at": 0.0, "value": None}
_LIST_CACHE_LOCK = threading.Lock()


class ModuleUpdatesError(RuntimeError):
    """A contract refusal. ``code`` is a stable word and ``status`` the HTTP status a route would give."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _plain(value: Any, limit: int = TEXT_MAX) -> str:
    """Untrusted text from a repository index: control characters removed, one line, length capped."""
    return " ".join(_CONTROL.sub("", str(value or "")).split())[:limit]


# ---------------------------------------------------------------------------------------------------------------- level and reasons


def update_level(installed: Any, available: Any) -> str:
    """patch, minor or major when both versions are plain X.Y.Z and the new one is higher; otherwise other.

    A pre-release, build metadata, a Tec-Tac ``-N`` rebuild, a two-part version, a leading zero or anything unreadable is other, so a
    later phase can treat it as "a person decides"."""
    old = _PLAIN_SEMVER.fullmatch(str(installed or "").strip())
    new = _PLAIN_SEMVER.fullmatch(str(available or "").strip())
    if not old or not new:
        return "other"
    before = tuple(int(part) for part in old.groups())
    after = tuple(int(part) for part in new.groups())
    if after <= before:
        return "other"
    if after[0] != before[0]:
        return "major"
    if after[1] != before[1]:
        return "minor"
    return "patch"


def blocked_reasons(item: dict) -> list[dict]:
    """Why the newer release cannot be installed now, from what the Online catalog already computed. Empty when it can.

    Each reason is {code, message}. Codes: core_required, ui_required, runtime_unknown, dependency_missing, dependency_update,
    source_changed. New permissions are not known before the package is staged (a repository index does not list them), so the
    install preview stays the place that shows them."""
    reasons: list[dict] = []
    compatibility = item.get("compatibility") if isinstance(item.get("compatibility"), dict) else {}
    for problem in compatibility.get("problems") or []:
        if not isinstance(problem, dict):
            continue
        if problem.get("type") == "runtime":
            component = problem.get("component")
            constraint = _plain(problem.get("constraint"), 40) or "a newer version"
            current = _plain(problem.get("current"), 40) or "an unknown version"
            if component == "framework":
                reasons.append({"code": "core_required", "message": f"Needs Tec-Tac Core {constraint}. This server runs {current}."})
            elif component == "ui":
                reasons.append({"code": "ui_required", "message": f"Needs the Tec-Tac UI {constraint}. This server runs {current}."})
            else:
                reasons.append({"code": "runtime_unknown", "message": f"Needs {_plain(component, 40) or 'a component'} {constraint}, which Core cannot check."})
        elif problem.get("type") == "dependency":
            dependency = _plain(problem.get("dependency"), 64) or "another module"
            constraint = _plain(problem.get("constraint"), 40) or "any version"
            installed_version = _plain(problem.get("installed_version"), 40)
            if installed_version:
                reasons.append({
                    "code": "dependency_update",
                    "message": f"Needs module {dependency} {constraint}. Version {installed_version} is installed.",
                })
            else:
                reasons.append({"code": "dependency_missing", "message": f"Needs module {dependency} ({constraint}), which is not installed."})
    if item.get("source_conflict"):
        reasons.append({
            "code": "source_changed",
            "message": "The installed copy came from another repository. Changing the source needs a person to confirm it.",
        })
    return reasons


def _current_sources(catalog: dict) -> set[str]:
    """The repositories whose last sync succeeded and that may offer releases now. Only their releases are ever announced."""
    current = set()
    for repo in catalog.get("repositories") or []:
        if not isinstance(repo, dict):
            continue
        sync = repo.get("sync") if isinstance(repo.get("sync"), dict) else {}
        if sync.get("status") != "ok" or sync.get("retired") or sync.get("credentials_rejected"):
            continue
        if sync.get("licensing_state") not in (None, "ok"):
            continue
        if repo.get("enabled", True) is False:
            continue
        current.add(str(repo.get("id") or ""))
    current.discard("")
    return current


def _release_notes_url(item: dict, repository_id: Any, version: Any) -> str | None:
    for release in item.get("releases") or []:
        if isinstance(release, dict) and release.get("repository_id") == repository_id and release.get("version") == version:
            link = release.get("release_notes_url")
            return link if isinstance(link, str) and link.startswith("https://") else None
    return None


def updates_from_catalog(catalog: dict, current_sources: set[str] | None = None) -> list[dict]:
    """The update rows for every installed module the Online catalog marks update_available. Pure: no files, no database."""
    rows = []
    for item in catalog.get("modules") or []:
        if not isinstance(item, dict) or not item.get("installed") or not item.get("update_available"):
            continue
        installed_version = str(item.get("installed_version") or "")
        available_version = str(item.get("latest_version") or "")
        if not installed_version or not available_version:
            continue
        repository_id = item.get("selected_repository_id")
        reasons = blocked_reasons(item)
        rows.append({
            "module_id": str(item.get("id") or ""),
            "name": _plain(item.get("name") or item.get("id")),
            "installed_version": installed_version,
            "available_version": available_version,
            "level": update_level(installed_version, available_version),
            "repository_id": repository_id,
            "repository_name": _plain(item.get("selected_repository_name")) or None,
            "channel": item.get("channel"),
            "release_notes_url": _release_notes_url(item, repository_id, available_version),
            "installable": not reasons,
            "blocked_reasons": reasons,
            "blocked_reason": reasons[0]["message"] if reasons else None,
            "source_current": None if current_sources is None else repository_id in current_sources,
        })
    rows.sort(key=lambda row: row["module_id"])
    return rows


def summarize(rows: list[dict]) -> dict:
    levels = {level: 0 for level in LEVELS}
    for row in rows:
        levels[row["level"] if row.get("level") in levels else "other"] += 1
    return {"count": len(rows), "installable_count": sum(1 for row in rows if row.get("installable")), "levels": levels}


# ------------------------------------------------------------------------------------------------------------------------ read model


def _load_catalog() -> dict:
    from .module_repository import online_catalog

    return online_catalog()


def _invalidate_list_cache() -> None:
    with _LIST_CACHE_LOCK:
        _LIST_CACHE["at"] = 0.0
        _LIST_CACHE["value"] = None


def _build_list() -> dict:
    catalog = _load_catalog()
    rows = updates_from_catalog(catalog, _current_sources(catalog))
    availability = catalog.get("availability") if isinstance(catalog.get("availability"), dict) else {}
    state = load_state()
    return {
        "schema": 1,
        "contract": f"{CAPABILITY_ID} {CAPABILITY_VERSION}",
        "updates": rows,
        **summarize(rows),
        "availability": {"state": availability.get("state"), "message": availability.get("message") or ""},
        "last_detection": state.get("last_run"),
        "generated_at": _utcnow(),
    }


def list_updates(*, fresh: bool = False) -> dict:
    """Every available update as the read route and the contract return it. Kept for LIST_CACHE_SECONDS in this process, so a badge
    that many browsers load stays cheap. A detection run clears the cache. Raises when the catalogue cannot be read."""
    now = time.monotonic()
    with _LIST_CACHE_LOCK:
        cached = _LIST_CACHE["value"]
        if not fresh and cached is not None and now - float(_LIST_CACHE["at"]) < LIST_CACHE_SECONDS:
            return cached
    value = _build_list()
    with _LIST_CACHE_LOCK:
        _LIST_CACHE["at"] = time.monotonic()
        _LIST_CACHE["value"] = value
    return value


def update_count() -> dict:
    """The badge: count, installable_count and the count per level."""
    payload = list_updates()
    return {"schema": 1, "count": payload["count"], "installable_count": payload["installable_count"], "levels": payload["levels"]}


# ------------------------------------------------------------------------------------------------------------- the dedupe record


def _empty_state() -> dict:
    return {"schema": 1, "notified": {}, "last_run": None}


def load_state() -> dict:
    """The dedupe record. A missing or unreadable file reads as empty for display; detection refuses to run on an unreadable one."""
    try:
        return _read_state()
    except (OSError, ValueError):
        return _empty_state()


def _read_state() -> dict:
    if not STATE_FILE.is_file():
        return _empty_state()
    payload = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("notified", {}), dict):
        raise ValueError("The module update record has an invalid structure.")
    payload.setdefault("schema", 1)
    payload.setdefault("notified", {})
    payload.setdefault("last_run", None)
    return payload


def _save_state(payload: dict) -> None:
    from .safe_files import atomic_json

    atomic_json(STATE_FILE, payload, mode=0o660)


@contextlib.contextmanager
def _state_lock():
    """An exclusive lock around one detection run, bounded by STATE_LOCK_WAIT_SECONDS. fcntl is POSIX only, so it is imported here."""
    import fcntl

    STATE_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = STATE_LOCK.open("a")
    try:
        deadline = time.monotonic() + STATE_LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ModuleUpdatesError("busy", "Another module update check is running.", 409) from None
                time.sleep(STATE_LOCK_POLL_SECONDS)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def is_new_version(record: Any, version: str) -> bool:
    """True when ``version`` has not been announced for the module. Only a version higher than the announced one is new, so a
    release that is withdrawn and offered again, or an older release, is never announced twice."""
    if not isinstance(record, dict) or not record.get("version"):
        return True
    announced = str(record["version"])
    if announced == version:
        return False
    try:
        from .module_state import version_satisfies

        return bool(version_satisfies(version, f">{announced}"))
    except (RuntimeError, ValueError, TypeError):  # ModuleStateError is a RuntimeError
        return False


def _prune(notified: dict) -> dict:
    if len(notified) <= MAX_STATE_RECORDS:
        return notified
    newest = sorted(notified.items(), key=lambda pair: str((pair[1] or {}).get("detected_at") or ""), reverse=True)
    return dict(newest[:MAX_STATE_RECORDS])


# ---------------------------------------------------------------------------------------------------------- detection and notices


def notice_client_id(module_id: str, version: str) -> str:
    """The notice's dedupe key: one per module version, inside the 64-character client id limit and its character set."""
    digest = hashlib.sha256(f"{module_id}\x00{version}".encode()).hexdigest()[:40]
    return f"{NOTICE_PREFIX}{digest}"


def notice_for(row: dict) -> dict:
    level_text = "" if row["level"] == "other" else f" ({row['level']})"
    text = f"Module {row['name'] or row['module_id']} can be updated from {row['installed_version']} to {row['available_version']}{level_text}."
    if row.get("blocked_reason"):
        text += f" It cannot be installed yet: {row['blocked_reason']}"
    return {
        "client_id": notice_client_id(row["module_id"], row["available_version"]),
        "title": NOTICE_TITLE,
        "message": text[:MESSAGE_MAX],
        "level": NOTICE_LEVEL,
        "action_label": NOTICE_ACTION_LABEL,
        "action_route": NOTICE_ACTION_ROUTE,
    }


def _recipients() -> list:
    from . import notices

    # No usernames: the active effective superusers only (a Django superuser or a role that is a superuser).
    return notices.system_notice_recipients(())


def _publish(recipients: list, notice: dict) -> int:
    from . import notices

    return notices.publish_system_notice(
        recipients, client_id=notice["client_id"], message=notice["message"], title=notice["title"], level=notice["level"],
        source=NOTICE_SOURCE, action_label=notice["action_label"], action_route=notice["action_route"],
    )


def _audit_detected(row: dict, trigger: str, recipients: int) -> None:
    from .audit import record, service_audit_actor

    record(
        actor=service_audit_actor(module_id="core", service=AUDIT_SERVICE, identity=AUDIT_IDENTITY),
        module_id="core",
        action=AUDIT_ACTION,
        object_type=AUDIT_OBJECT_TYPE,
        object_id=row["module_id"],
        message=f"Module update detected: {row['module_id']} {row['installed_version']} to {row['available_version']} ({row['level']}).",
        after={
            "module_id": row["module_id"],
            "installed_version": row["installed_version"],
            "available_version": row["available_version"],
            "level": row["level"],
            "installable": row["installable"],
            "blocked_codes": [reason["code"] for reason in row["blocked_reasons"]],
            "repository_id": row["repository_id"],
            "trigger": trigger,
            "notified_users": recipients,
        },
    )


def detect_and_notify(trigger: str = "manual-sync") -> dict:
    """Announce each new module version once (Celery only: the sync routes queue it, the daily sync calls it). Never raises.

    Returns counts: updates (all rows), current (rows whose repository's last sync succeeded), new (versions announced in this run),
    notified_users (notices created), failed (versions whose notice could not be stored; they are tried again next run) and error
    (a word, when the run stopped early)."""
    trigger = trigger if trigger in TRIGGERS else "manual-sync"
    report: dict[str, Any] = {"trigger": trigger, "updates": 0, "current": 0, "new": 0, "notified_users": 0, "failed": 0, "error": None}
    try:
        catalog = _load_catalog()
        rows = updates_from_catalog(catalog, _current_sources(catalog))
    except Exception:
        logger.warning("Module update detection could not read the catalogue; the next sync tries again.", exc_info=True)
        report["error"] = "catalogue_unavailable"
        return report
    _invalidate_list_cache()
    current = [row for row in rows if row["source_current"]]
    report["updates"] = len(rows)
    report["current"] = len(current)
    try:
        with _state_lock():
            try:
                state = _read_state()
            except (OSError, ValueError):
                # An unreadable record is rebuilt from what is offered now, with no notice: re-announcing every version would be a
                # flood, and a record that never recovers would silence detection for good. One warning; the next new version notifies.
                logger.warning("The module update record was unreadable; it is rebuilt without notices.", exc_info=True)
                state = _empty_state()
                state["notified"] = {
                    row["module_id"]: {"version": row["available_version"], "level": row["level"], "detected_at": _utcnow(), "rebuilt": True}
                    for row in current
                }
                report["error"] = "record_rebuilt"
            notified = dict(state.get("notified") or {})
            fresh = [row for row in current if is_new_version(notified.get(row["module_id"]), row["available_version"])]
            recipients = _recipients() if fresh else []
            now = _utcnow()
            for row in fresh:
                try:
                    created = _publish(recipients, notice_for(row))
                except Exception:
                    logger.warning("The notice for module update %s %s was not stored; the next run tries again.",
                                   row["module_id"], row["available_version"], exc_info=True)
                    report["failed"] += 1
                    continue
                notified[row["module_id"]] = {"version": row["available_version"], "level": row["level"], "detected_at": now}
                report["new"] += 1
                report["notified_users"] += int(created or 0)
                try:
                    _audit_detected(row, trigger, len(recipients))
                except Exception:
                    logger.warning("The audit row for module update %s %s was not written.", row["module_id"], row["available_version"], exc_info=True)
            state["notified"] = _prune(notified)
            state["last_run"] = {"at": now, "trigger": trigger, "updates": len(rows), "current": len(current), "new": report["new"]}
            _save_state(state)
    except ModuleUpdatesError as exc:
        report["error"] = exc.code
    except Exception:
        logger.warning("Module update detection stopped; the next sync tries again.", exc_info=True)
        report["error"] = "detection_failed"
    _invalidate_list_cache()
    return report


def queue_detection(trigger: str = "manual-sync") -> bool:
    """Hand one detection run to Celery from a request thread. One bounded broker attempt, no retry. Never raises. False when not sent;
    the daily sync then catches up."""
    try:
        from .tasks import detect_module_updates

        options = {"socket_timeout": BROKER_TIMEOUT_SECONDS, "socket_connect_timeout": BROKER_TIMEOUT_SECONDS}
        with detect_module_updates.app.connection_for_write(transport_options=options, connect_timeout=BROKER_TIMEOUT_SECONDS) as broker:
            detect_module_updates.apply_async(
                kwargs={"trigger": trigger if trigger in TRIGGERS else "manual-sync"}, connection=broker, retry=False,
                expires=TASK_EXPIRES_SECONDS, ignore_result=True,
            )
        return True
    except Exception:
        logger.warning("The module update check was not queued; the daily sync runs it.", exc_info=True)
        return False


# ------------------------------------------------------------------------------------------------- the contract core.module_updates


_REFUSAL_TEXT = "Only an installed, enabled server module may read module updates."


def _caller_category(module_id: str) -> str | None:
    """The effective catalog category of an installed extension module, from its manifest, or None when it cannot be read."""
    from . import module_category, registry

    plugin = next((p for p in registry.discover_plugins() if getattr(p, "plugin_id", None) == module_id), None)
    if plugin is None or getattr(plugin, "plugin_type", None) != "extension" or getattr(plugin, "legacy", False):
        return None
    return module_category.effective_category(getattr(plugin, "category", ""))


def _audit_refusal(caller_id: str, category: str | None, reason: str) -> None:
    """One non-strict deny row per caller and reason per DENY_AUDIT_INTERVAL_SECONDS in this process, so a loop cannot flood the log."""
    key = (caller_id, reason)
    now = time.monotonic()
    with _DENY_LOCK:
        last = _DENY_AUDITED.get(key)
        if last is not None and now - last < DENY_AUDIT_INTERVAL_SECONDS:
            return
        _DENY_AUDITED[key] = now
    try:
        from .audit import record, service_audit_actor

        record(
            actor=service_audit_actor(module_id="core", service=AUDIT_SERVICE, identity="system (module update contract)"),
            module_id="core",
            action="deny",
            object_type=AUDIT_OBJECT_TYPE,
            object_id=caller_id,
            message=f"Module updates read refused: {reason}.",
            metadata={"caller": caller_id, "category": category, "reason": reason, "contract": f"{CAPABILITY_ID} {CAPABILITY_VERSION}"},
        )
    except Exception:  # a failed deny row never turns the refusal into another error
        logger.warning("The module updates refusal could not be audited.", exc_info=True)


def updates_for_module() -> dict:
    """core.module_updates 1.0.0: the available updates, read-only. Returns the same payload as GET /api/tfd/modules/updates/.

    The caller must be the code of an installed, enabled module, verified by Core from the call stack (AD-26), whose catalog category is
    server. Core code, a library, a disabled or legacy module, a core, premium or test module and any other caller get ModuleUpdatesError
    caller_not_allowed (403) and one deny audit row (rate limited). Nothing else is written."""
    from .caller_identity import calling_module_for_core_provider

    caller = calling_module_for_core_provider(provider_file=__file__)
    if caller is None:
        _audit_refusal("(unverified)", None, "unverified_caller")
        raise ModuleUpdatesError("caller_not_allowed", _REFUSAL_TEXT, 403)
    try:
        category = _caller_category(caller.module_id)
    except Exception:  # an unreadable registry refuses (fail closed)
        logger.warning("The module updates caller's category could not be read.", exc_info=True)
        category = None
    if category not in ALLOWED_CALLER_CATEGORIES:
        _audit_refusal(caller.module_id, category, "category_not_allowed" if category else "category_unknown")
        raise ModuleUpdatesError("caller_not_allowed", _REFUSAL_TEXT, 403)
    return list_updates()


class _CoreModuleUpdatesProvider:
    updates_for_module = staticmethod(updates_for_module)


_PROVIDER = _CoreModuleUpdatesProvider()


def module_updates_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "namespace": "tec_tac.module_updates",
        "operations": list(OPERATIONS),
        "caller": "verified (AD-26): an installed, enabled module of catalog category server, its own server-side code. Any other caller (core, premium or test module, Core, a library) gets 403 caller_not_allowed and one deny audit row.",
        "access": "read-only. The same list as GET /api/tfd/modules/updates/ (module-manage permission for a person).",
        "levels": list(LEVELS),
        "blocked_codes": ["core_required", "ui_required", "runtime_unknown", "dependency_missing", "dependency_update", "source_changed"],
    }


def register_core_module_updates_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Read-only list of installed modules with a newer release in an enabled repository, with level and blocked reason.",
        operations=OPERATIONS,
        metadata=module_updates_contract_metadata(),
    )

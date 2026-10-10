"""Notices for failed module jobs (Core 1.17.14, Johan CQ36 and CQ41).

A module job runs as root, minutes after the browser that queued it has moved on. When it fails, nobody is looking. The
scheduler tick calls ``sweep_failed_jobs`` once a minute. It raises one notice per failed module job (enable, disable,
install, bundle install and batch install) for the people who can act on it, through
``tec_tac.notices.publish_system_notice``.

* One notice per job and recipient. The dedupe key is the notice's ``client_id``, ``module-job-failed:<job id>``, so the
  next tick never stores it again and never resets a notice the person has read.
* Recipients (CQ41, assumption (a), the smallest audience): every active effective superuser, plus the user named in the
  job's ``requested_by`` when that user is active.
* The text is plain English, printable ASCII, cut short, and holds no paths. A failed switch says whether the flags were put
  back, from ``rolled_back`` and ``rollback_error`` as the root helper recorded them.
* It looks only at jobs finished in the last seven days, and at most 200 of them per tick, newest first: the same bounds
  as the replacement audit sweep.
* It never raises. A failure is logged and the next tick tries again. Tactical is not affected.

The browser toast for a new notice is UI work. Core only stores the notice.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from . import module_replacement as _replacement

logger = logging.getLogger("tec_tac.module_failure_notices")

CLIENT_ID_PREFIX = "module-job-failed:"
SOURCE = "core"
TITLE = "Module job failed"
ACTION_LABEL = "Open Modules"
ACTION_ROUTE = "/modules"
WINDOW_DAYS = _replacement.AUDIT_WINDOW_DAYS
MAX_JOBS_PER_TICK = _replacement.AUDIT_MAX_JOBS_PER_TICK
ERROR_MAX = 200
MESSAGE_MAX = 600

# What each job action did, in the words of the sentence "Module X could not be ...".
_VERBS = {"enable": "enabled", "disable": "disabled", "install": "installed", "bundle_install": "installed", "batch_install": "installed"}
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")
_PATH_TOKEN_RE = re.compile(r"\S*[/\\]\S*")


def client_id_for(job_id: Any) -> str | None:
    """The dedupe key of a job's notice, or None when the job has no usable id."""
    text = str(job_id or "")
    return f"{CLIENT_ID_PREFIX}{text}" if _JOB_ID_RE.fullmatch(text) else None


def _error_text(value: Any) -> str:
    """The job's error as one short line of printable ASCII with every path-like word replaced."""
    cleaned = _replacement._plain(value, ERROR_MAX * 3)
    cleaned = _PATH_TOKEN_RE.sub("[path]", cleaned)
    return " ".join(cleaned.split())[:ERROR_MAX]


def _subject(job: Mapping[str, Any]) -> str:
    action = job.get("action")
    plugin = _PATH_TOKEN_RE.sub("[path]", _replacement._plain(job.get("plugin_id"), 80))
    if action == "batch_install":
        return "The batch install"
    if action == "bundle_install":
        return f"The bundle install of module {plugin}" if plugin else "The bundle install"
    return f"Module {plugin}" if plugin else "A module"


def notice_for_job(job: Mapping[str, Any]) -> dict | None:
    """The notice a failed module job owes, or None. Pure: no database, no clock, no files.

    Returns {client_id, level, title, message, action_label, action_route, requested_by}."""
    if not isinstance(job, Mapping) or job.get("status") != "failed" or job.get("action") not in _VERBS:
        return None
    client_id = client_id_for(job.get("id"))
    if client_id is None:
        return None
    action = str(job["action"])
    verb = _VERBS[action]
    if action == "install" and job.get("replace"):
        verb = "updated"
    text = f"{_subject(job)} could not be {verb}."
    if action in ("enable", "disable"):
        # A switch records what happened to the flags. The stage alone is never taken as proof.
        outcome, _ = _replacement._failed_outcome(job, _replacement._plain(job.get("stage"), 40))
        text += f" {outcome}"
    error = _error_text(job.get("error")) or "no error was recorded"
    text += f" Error: {error}"
    return {
        "client_id": client_id, "level": "error", "title": TITLE, "message": text[:MESSAGE_MAX],
        "action_label": ACTION_LABEL, "action_route": ACTION_ROUTE,
        "requested_by": str(job.get("requested_by") or ""),
    }


def _bounded_failed_jobs(jobs: Iterable[Any], now: datetime) -> list[Mapping[str, Any]]:
    """Failed jobs finished inside the window, newest first, at most ``MAX_JOBS_PER_TICK``."""
    horizon = now.timestamp() - WINDOW_DAYS * 86400
    found = []
    for job in jobs:
        if not isinstance(job, Mapping) or job.get("status") != "failed":
            continue
        when = _replacement._parse_when(job.get("finished_at"))
        if when is not None and when.timestamp() >= horizon:
            found.append((when, job))
    found.sort(key=lambda item: item[0], reverse=True)
    return [job for _, job in found[:MAX_JOBS_PER_TICK]]


def _default_recipients(requested_by: str) -> list:
    from . import notices

    return notices.system_notice_recipients([requested_by] if requested_by else [])


def _default_publish(recipients, notice: dict) -> int:
    from . import notices

    return notices.publish_system_notice(
        recipients, client_id=notice["client_id"], message=notice["message"], title=notice["title"], level=notice["level"],
        source=SOURCE, action_label=notice["action_label"], action_route=notice["action_route"],
    )


def _default_existing(client_ids: list[str]) -> set[tuple[str, Any]]:
    from .models import TecTacUserNotice

    return set(TecTacUserNotice.objects.filter(client_id__in=client_ids).values_list("client_id", "user_id"))


def sweep_failed_jobs(*, now: datetime | None = None, jobs: Iterable[Any] | None = None,
                      recipients_for: Callable[[str], list] | None = None,
                      publish: Callable[[list, dict], int] | None = None,
                      existing: Callable[[list[str]], set] | None = None) -> int:
    """Raise one notice per failed module job that has none yet. Returns how many notices it stored. Never raises.

    The three callables are the database seams (recipients, the store, and which notices already exist); the defaults use
    ``tec_tac.notices``. A job whose recipients all hold its notice already costs one read and no write."""
    stored = 0
    try:
        if jobs is None:
            from . import module_manager_v2 as v2

            jobs = v2._iter_jobs()
        now = now or datetime.now(timezone.utc)
        notices = []
        for job in _bounded_failed_jobs(jobs, now):
            notice = notice_for_job(job)
            if notice is not None:
                notices.append(notice)
        if not notices:
            return 0
        have = (existing or _default_existing)([item["client_id"] for item in notices])
        recipients_for = recipients_for or _default_recipients
        publish = publish or _default_publish
        cache: dict[str, list] = {}
        for notice in notices:
            try:
                if notice["requested_by"] not in cache:
                    cache[notice["requested_by"]] = list(recipients_for(notice["requested_by"]))
                recipients = cache[notice["requested_by"]]
                missing = [user for user in recipients if (notice["client_id"], getattr(user, "pk", user)) not in have]
                if missing:
                    stored += int(publish(missing, notice) or 0)
            except Exception:
                logger.exception("Could not raise the failure notice %s.", notice["client_id"])
    except Exception:
        logger.exception("Module failure notice sweep failed; Tactical is not affected.")
    return stored

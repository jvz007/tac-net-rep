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

Priority 1 email (1.17.15, Johan CQ41): a failed module job is a system failure, so the same people also get an email, once
per job. ``send_p1_email`` is the one place that sends it, so a later Priority 1 type (server storage) calls the same
function. Outbound email has no contract yet: ``_mail_settings`` returns None, so nothing is sent until one exists (see
reviews/requests/core-modules.md). Core does not read Tactical's CoreSettings.
"""
from __future__ import annotations

import logging
import re
import socket
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from . import module_replacement as _replacement

logger = logging.getLogger("tec_tac.module_failure_notices")

CLIENT_ID_PREFIX = "module-job-failed:"
EMAIL_CLIENT_ID_PREFIX = "module-job-failed-email:"
SMTP_TIMEOUT_SECONDS = 20
EMAIL_SERVER_MAX = 120
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


def _module_label(job: Mapping[str, Any]) -> str:
    """What the job is about, in words for a subject line: a module id, or the batch and bundle installs (1.17.15)."""
    action = job.get("action")
    plugin = _PATH_TOKEN_RE.sub("[path]", _replacement._plain(job.get("plugin_id"), 80))
    if action == "batch_install":
        return "batch install"
    if action == "bundle_install":
        return f"bundle {plugin}" if plugin else "bundle install"
    return plugin or "module job"


def notice_for_job(job: Mapping[str, Any]) -> dict | None:
    """The notice a failed module job owes, or None. Pure: no database, no clock, no files.

    Returns {client_id, level, title, message, action_label, action_route, requested_by, module}. ``module`` is the label
    the Priority 1 email uses (1.17.15)."""
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
        "requested_by": str(job.get("requested_by") or ""), "module": _module_label(job),
    }


def email_client_id_for(notice: Mapping[str, Any]) -> str | None:
    """The dedupe key of a notice's Priority 1 email, ``module-job-failed-email:<job id>``, or None (1.17.15)."""
    client_id = str(notice.get("client_id") or "")
    if not client_id.startswith(CLIENT_ID_PREFIX):
        return None
    job_id = client_id[len(CLIENT_ID_PREFIX):]
    return f"{EMAIL_CLIENT_ID_PREFIX}{job_id}" if _JOB_ID_RE.fullmatch(job_id) else None


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


def _mail_settings() -> dict | None:
    """The outbound email settings Core may use, or None (1.17.15, CQ41).

    The keys are Tactical's own names (smtp_host, smtp_port, smtp_from_email, smtp_requires_auth, smtp_host_user,
    smtp_host_password), so the contract can mirror them. There is no contract yet. Tactical keeps these in its CoreSettings
    model, and Core may not read Tactical's models, so the Priority 1 email stays off until the Global Settings core module
    publishes one (reviews/requests/core-modules.md)."""
    return None


def _server_name() -> str:
    """The name the email gives for this server: the first Django ALLOWED_HOSTS entry, else the machine's host name."""
    try:
        from django.conf import settings as django_settings

        for host in django_settings.ALLOWED_HOSTS:
            name = str(host).strip().lstrip(".")
            if name and name != "*":
                return _replacement._plain(name, EMAIL_SERVER_MAX) or "this server"
    except Exception:
        logger.debug("No Django host name for the Priority 1 email; using the machine name.")
    try:
        return _replacement._plain(socket.gethostname(), EMAIL_SERVER_MAX) or "this server"
    except OSError:
        return "this server"


def _p1_message(notice: Mapping[str, Any], server: str, settings: Mapping[str, Any], address: str):
    """The email for one notice and one address. Plain English; the body repeats the notice text, which holds no paths."""
    from email.message import EmailMessage

    module = str(notice.get("module") or "module job")
    message = EmailMessage()
    message["Subject"] = f"[Tec-Tac] Priority 1: module job failed for {module} on {server}"
    message["From"] = str(settings["smtp_from_email"]).strip()
    message["To"] = address
    message.set_content(
        f"A module job did not finish on {server}.\n\n"
        f"{notice['message']}\n\n"
        f"Server: {server}\n"
        f"Module: {module}\n\n"
        "Open Modules in Tec-Tac to see the job log.\n\n"
        "Tec-Tac by Tech Flow Dynamics - techxflow.co.za\n"
    )
    return message


def _smtp_send(settings: Mapping[str, Any], message) -> None:
    """Send one message the way Tactical sends its own email (1.17.15): implicit TLS on port 465, otherwise a plain
    connection, upgraded with STARTTLS when the server needs a login. The socket waits SMTP_TIMEOUT_SECONDS at most."""
    import smtplib
    import ssl

    host = str(settings["smtp_host"]).strip()
    port = int(settings.get("smtp_port") or 25)
    use_ssl = port == 465
    if use_ssl:
        client = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT_SECONDS, context=ssl.create_default_context())
    else:
        client = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECONDS)
    with client:
        if settings.get("smtp_requires_auth"):
            client.ehlo()
            if not use_ssl:
                client.starttls()
            client.login(str(settings.get("smtp_host_user") or ""), str(settings.get("smtp_host_password") or ""))
        client.send_message(message)


def _default_mark_sent(user: Any, client_id: str) -> None:
    """Record that the email was tried for this user. The row is read already, so it raises no toast."""
    from django.utils import timezone

    from .models import TecTacUserNotice

    TecTacUserNotice.objects.get_or_create(user=user, client_id=client_id, defaults={
        "source": SOURCE, "level": "info", "title": "Email notice sent",
        "message": "An email about a failed module job was sent to you.", "read_at": timezone.now(),
    })


def send_p1_email(notice: Mapping[str, Any], recipients: Iterable[Any], *, settings: Mapping[str, Any] | None = None,
                  server: str | None = None, have: Callable[[list[str]], set] | None = None,
                  send: Callable[[Mapping[str, Any], Any], None] | None = None,
                  mark: Callable[[Any, str], None] | None = None) -> int:
    """Email one Priority 1 notice to each recipient who has not had it yet (1.17.15, CQ41). Returns how many emails it
    tried. Never raises.

    ``recipients`` is the audience of the toast. ``settings`` None means ``_mail_settings()``; a missing sender or host
    skips everything, logged at DEBUG. One try per recipient and job: the try is marked with a row whose client id is
    ``module-job-failed-email:<job id>``, whether the send worked or not, so the next tick never sends it again. A send
    that fails is logged, and the tick goes on. A recipient with no email address is skipped and not marked."""
    try:
        cfg = _mail_settings() if settings is None else settings
        if not cfg or not str(cfg.get("smtp_from_email") or "").strip() or not str(cfg.get("smtp_host") or "").strip():
            logger.debug("Priority 1 email skipped: outbound email is not configured.")
            return 0
        client_id = email_client_id_for(notice)
        users = list(recipients)
        if client_id is None or not users:
            return 0
        done = (have or _default_existing)([client_id])
        server_label = server or _server_name()
        tried = 0
        for user in users:
            if (client_id, getattr(user, "pk", user)) in done:
                continue
            address = str(getattr(user, "email", "") or "").strip()
            if not address:
                continue
            tried += 1
            try:
                (send or _smtp_send)(cfg, _p1_message(notice, server_label, cfg, address))
            except Exception:
                logger.exception("Could not send the Priority 1 email %s.", client_id)
            try:
                (mark or _default_mark_sent)(user, client_id)
            except Exception:
                logger.exception("Could not record the Priority 1 email %s.", client_id)
        return tried
    except Exception:
        logger.exception("Priority 1 email failed; Tactical is not affected.")
        return 0


def sweep_failed_jobs(*, now: datetime | None = None, jobs: Iterable[Any] | None = None,
                      recipients_for: Callable[[str], list] | None = None,
                      publish: Callable[[list, dict], int] | None = None,
                      existing: Callable[[list[str]], set] | None = None,
                      mail_settings: Callable[[], Mapping[str, Any] | None] | None = None,
                      email_have: Callable[[list[str]], set] | None = None,
                      send_mail: Callable[[Mapping[str, Any], Any], None] | None = None,
                      mark_sent: Callable[[Any, str], None] | None = None) -> int:
    """Raise one notice per failed module job that has none yet, and the Priority 1 email for it (1.17.15). Returns how many
    notices it stored. Never raises.

    The callables are the seams: recipients, the store, which notices already exist, the email settings, which emails were
    already tried, the sender and the marker. The defaults use ``tec_tac.notices``, ``send_p1_email`` and the
    ``TecTacUserNotice`` table. A job whose recipients all hold its notice already costs one read and no write."""
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
        try:
            mail = dict((mail_settings or _mail_settings)() or {})
        except Exception:
            logger.exception("Could not read the outbound email settings; no Priority 1 email this tick.")
            mail = {}
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
            # 1.17.15 (CQ41): the Priority 1 email goes to the same people, after the toast notice is stored.
            send_p1_email(notice, cache.get(notice["requested_by"]) or [], settings=mail, have=email_have,
                          send=send_mail, mark=mark_sent)
    except Exception:
        logger.exception("Module failure notice sweep failed; Tactical is not affected.")
    return stored

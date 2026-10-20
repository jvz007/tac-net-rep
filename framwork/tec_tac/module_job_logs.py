"""Module job history, full job logs and retention (Core 1.17.60).

Three jobs, one file, standard library only (nothing here imports Django at load time):

* ``read_job_log``: the whole log of one module job or hotfix job, capped and scrubbed, for
  ``GET /api/tfd/modules/v2/jobs/<id>/log/``.
* ``history_rows`` and ``page_history``: the whitelisted job list for ``GET /api/tfd/modules/v2/jobs/history/``. No row
  carries log text, a path, a hash or publisher trust.
* ``prune_expired``: the retention sweep for finished job records. The scheduler tick calls it. The root helpers remove a
  log only after its record is gone (``sweep_orphan_logs`` in the two helper scripts).

The log folders are root-owned and read-only for the Tactical group, so the Django side can read a log but never delete one.
The folder paths below are the same literals ``module_manager`` and ``module_hotfix`` use; a test pins that they agree.
"""
from __future__ import annotations

import json
import logging
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

STATE_ROOT = Path("/var/lib/tec-tac/module-manager")
JOBS_ROOT = STATE_ROOT / "jobs"
LOGS_ROOT = STATE_ROOT / "logs"
HOTFIX_JOBS_ROOT = STATE_ROOT / "hotfixes" / "jobs"
HOTFIX_LOGS_ROOT = STATE_ROOT / "hotfixes" / "logs"

# The one number that sets how long a finished job record is kept. Change it here and restart the scheduler tick or Core.
MODULE_JOB_RETENTION_DAYS = 180
MAX_PRUNE_PER_RUN = 200
PRUNE_GATE_KEY = "tec-tac:module-job-retention:gate"
PRUNE_GATE_SECONDS = 3600

MAX_LOG_BYTES = 5 * 1024 * 1024
HALF_LOG_BYTES = MAX_LOG_BYTES // 2
MAX_JOB_RECORD_BYTES = 4 * 1024 * 1024
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
ACTIVE_STATUSES = frozenset({"queued", "dispatched", "running"})

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_JOB_FILE_RE = re.compile(r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.json$")
_MODULE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z.+_-]{1,40}$")


class JobLogError(Exception):
    """A refusal with the HTTP status the view answers and a plain sentence."""

    def __init__(self, status: int, message: str, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code


class HistoryParameterError(ValueError):
    """A bad page or page_size value: the view answers 400."""


# ------------------------------------------------------------------------------------------------ scrubbing

NEWLINE = "\n"
_MARK = "<redacted>"
MAX_SCRUB_LINE = 20000  # a longer line is cut before the patterns run: a second guard next to the unambiguous patterns
_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----")
_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_HEADER = re.compile(r"(?i)\b((?:proxy-)?authorization|x-api-key|x-auth-token|set-cookie|cookie)\b([ \t]*[:=][ \t]*)[^\r\n]*")
_BEARER = re.compile(r"(?i)\b(bearer|basic|token)([ \t]+)([A-Za-z0-9._~+/=-]{8,})")
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15}://)[^/\s:@]+:[^/\s@]*@")
_KEYWORDS = (
    r"password|passwd|pass|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|licen[cs]e[ _-]?key|private[_-]?key|"
    r"knox|authorization|cookie|csrf|session"
)
_KEY_VALUE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])((?:[A-Za-z0-9]+[_-])*(?:" + _KEYWORDS + r")(?:[_-]+[A-Za-z0-9]+)*)(?![A-Za-z0-9])"
    r"([\"']?[ \t]*)([:=])([ \t]*)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\r\n]*)"
)
_CLI_FLAG = re.compile(r"(?i)(--?(?:password|passwd|secret|token|api-key|apikey|license-key|licence-key)[ \t]+)(\S+)")
_PATH = re.compile(r"(?<![A-Za-z0-9_/:.\-])/[^\s\"'<>|;,()\[\]]+")
_SENSITIVE_PATH = re.compile(r"secret|token|key|pem|password|credential|\.env|id_rsa|tec-tac-trust|github-token", re.IGNORECASE)


def _redact_key_blocks(text: str, tail_segment: bool) -> str:
    """Redact whole private-key blocks, BEGIN line to END line, across lines.

    A segment can start or end inside a block when the log was cut: an unterminated BEGIN is redacted to the end of the
    segment, and in a tail segment everything before the first END (a block that began in the omitted middle) is redacted.
    """
    out = []
    pos = 0
    if tail_segment:
        end = _KEY_END.search(text)
        begin = _KEY_BEGIN.search(text)
        if end and (not begin or end.start() < begin.start()):
            out.append(_MARK + "\n")
            pos = end.end()
    while True:
        begin = _KEY_BEGIN.search(text, pos)
        if not begin:
            break
        out.append(text[pos:begin.start()])
        out.append("<redacted private key>")
        end = _KEY_END.search(text, begin.end())
        if not end:
            pos = len(text)
            break
        pos = end.end()
    out.append(text[pos:])
    return _KEY_END.sub("<redacted private key>", "".join(out))


def _key_value(match: re.Match) -> str:
    key, quote, sep, space, value = match.groups()
    if not value:
        return match.group(0)
    if value[0] in "\"'" and len(value) >= 2 and value[-1] == value[0]:
        return f"{key}{quote}{sep}{space}{value[0]}{_MARK}{value[0]}"
    if sep == "=":
        parts = re.split(r"(?=[\s&])", value, maxsplit=1)
        return f"{key}{quote}{sep}{space}{_MARK}{parts[1] if len(parts) > 1 else ''}"
    return f"{key}{quote}{sep}{space}{_MARK}"


def _bearer(match: re.Match) -> str:
    word, space, value = match.groups()
    if word.lower() != "bearer" and value.isalpha() and value.islower():
        return match.group(0)  # an ordinary word after "Token " or "Basic ", not a credential
    return f"{word}{space}{_MARK}"


def _path(match: re.Match) -> str:
    return "<redacted path>" if _SENSITIVE_PATH.search(match.group(0)) else match.group(0)


def clean_text(raw: bytes) -> str:
    """Decode as UTF-8 (bad bytes replaced) and strip NUL, ANSI colour codes and other non-text control characters."""
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    return _CONTROL.sub("", _ANSI.sub("", text))


def scrub_text(text: str, *, tail_segment: bool = False) -> str:
    """Redact secrets from already-cleaned log text. Pattern-based, so it cannot be perfect: the audit row exists for that."""
    lines = text.split(NEWLINE)
    if any(len(line) > MAX_SCRUB_LINE for line in lines):
        text = NEWLINE.join(line[:MAX_SCRUB_LINE] + " <line cut>" if len(line) > MAX_SCRUB_LINE else line for line in lines)
    text = _redact_key_blocks(text, tail_segment)
    text = _HEADER.sub(lambda m: f"{m.group(1)}{m.group(2)}{_MARK}", text)
    text = _BEARER.sub(_bearer, text)
    text = _URL_CREDENTIALS.sub(lambda m: f"{m.group(1)}{_MARK}@", text)
    text = _KEY_VALUE.sub(_key_value, text)
    text = _CLI_FLAG.sub(lambda m: f"{m.group(1)}{_MARK}", text)
    return _PATH.sub(_path, text)


def scrub_bytes(raw: bytes, *, tail_segment: bool = False) -> str:
    return scrub_text(clean_text(raw), tail_segment=tail_segment)


# ------------------------------------------------------------------------------------------------ safe file access


def parse_job_id(value) -> str:
    """The canonical lowercase form of a job id, or a 400. Only this string may ever reach a path."""
    if not isinstance(value, str) or not _UUID_RE.match(value):
        raise JobLogError(400, "That is not a valid job id.", "invalid_job_id")
    try:
        canonical = str(uuid.UUID(value))
    except ValueError as exc:
        raise JobLogError(400, "That is not a valid job id.", "invalid_job_id") from exc
    if canonical != value:
        raise JobLogError(400, "That is not a valid job id.", "invalid_job_id")
    return canonical


def _read_json_file(path: Path):
    """The parsed dict of a job record that is a regular, non-symlink file of sane size. None for anything else."""
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JOB_RECORD_BYTES:
            return None
        with open(path, "rb") as handle:
            payload = json.loads(handle.read(MAX_JOB_RECORD_BYTES + 1).decode("utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _folder_is_plain(folder: Path) -> bool:
    """True when the folder is a real directory (not a symlink) whose real path is the expected one."""
    try:
        info = os.lstat(folder)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return False
    expected = os.path.join(os.path.realpath(folder.parent), folder.name)
    return os.path.realpath(folder) == expected


def _log_size(logs_root: Path, job_id: str):
    """Size of the regular, non-symlink log file of a job, or None when there is none. Reads no content."""
    if not _folder_is_plain(Path(logs_root)):
        return None
    try:
        info = os.lstat(Path(logs_root) / f"{job_id}.log")
    except OSError:
        return None
    return info.st_size if stat.S_ISREG(info.st_mode) else None


def _read_range(fd: int, offset: int, length: int) -> bytes:
    os.lseek(fd, offset, os.SEEK_SET)
    chunks = []
    remaining = length
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 1024 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _open_log(logs_root: Path, job_id: str):
    """Open ``<logs folder>/<canonical uuid>.log`` for reading and return ``(fd, size)``.

    No symlink is followed, the folder must be the expected plain directory, and the opened file must be a regular file.
    """
    missing = JobLogError(404, "No log was kept for this job.", "no_log")
    logs_root = Path(logs_root)
    if not _folder_is_plain(logs_root):
        if os.path.lexists(logs_root):
            logger.warning("Module job log folder refused: it is not a plain directory.")
        raise missing
    path = logs_root / f"{job_id}.log"
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise missing from exc
    if not stat.S_ISREG(before.st_mode):
        logger.warning("Module job log refused: not a regular file.")
        raise missing
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise missing from exc
    try:
        after = os.fstat(fd)
        same = (not before.st_ino or not after.st_ino) or (before.st_ino, before.st_dev) == (after.st_ino, after.st_dev)
        if not stat.S_ISREG(after.st_mode) or not same:
            logger.warning("Module job log refused: the file changed while it was opened.")
            raise missing
        return fd, after.st_size
    except BaseException:
        os.close(fd)
        raise


@dataclass
class JobLog:
    job_id: str
    kind: str
    action: str
    module: str
    body: bytes
    size: int
    truncated: bool
    kept: str
    omitted: int = 0


def safe_label(value, default: str = "unknown") -> str:
    """Force a module or action name through [a-z0-9-] and cut it to 40 characters."""
    label = re.sub(r"[^a-z0-9-]", "-", str(value or "").lower())[:40].strip("-")
    return label or default


def _module_label(job: dict) -> str:
    for key in ("plugin_id", "module_id"):
        value = job.get(key)
        if isinstance(value, str) and value:
            return safe_label(value)
    return "batch"


def locate_job(job_id: str):
    """Find a job by its canonical id: ``(kind, record, logs_root)``. Module jobs first, then hotfix jobs. 404 when unknown."""
    for kind, jobs_root, logs_root in (("module", JOBS_ROOT, LOGS_ROOT), ("hotfix", HOTFIX_JOBS_ROOT, HOTFIX_LOGS_ROOT)):
        record = _read_json_file(Path(jobs_root) / f"{job_id}.json")
        if record is not None:
            return kind, record, Path(logs_root)
    raise JobLogError(404, "That module job was not found.", "job_not_found")


def _cut_log(fd: int, size: int):
    """Return ``(raw head, raw tail, omitted)``. A file at or under the cap comes back whole as the head with an empty tail."""
    if size <= MAX_LOG_BYTES:
        data = _read_range(fd, 0, size)
        return data, b"", 0
    head = _read_range(fd, 0, HALF_LOG_BYTES)
    tail = _read_range(fd, size - HALF_LOG_BYTES, HALF_LOG_BYTES)
    cut = head.rfind(b"\n")
    if cut >= 0:
        head = head[:cut + 1]
    cut = tail.find(b"\n")
    if cut >= 0:
        tail = tail[cut + 1:]
    return head, tail, size - len(head) - len(tail)


def read_job_log(job_id) -> JobLog:
    """The scrubbed, capped log of one job. Raises JobLogError (400, 404). Never reads a user-supplied name."""
    job_id = parse_job_id(job_id)
    kind, record, logs_root = locate_job(job_id)
    fd, size = _open_log(logs_root, job_id)
    try:
        head, tail, omitted = _cut_log(fd, size)
    finally:
        os.close(fd)
    if omitted:
        marker = f"[... {omitted} bytes were left out of the middle of this log ...]"
        first = scrub_bytes(head)
        joiner = "" if not first or first.endswith(NEWLINE) else NEWLINE
        text = first + joiner + marker + NEWLINE + scrub_bytes(tail, tail_segment=True)
        kept = "head-and-tail"
    else:
        text = scrub_bytes(head)
        kept = "all"
    return JobLog(job_id=job_id, kind=kind, action=safe_label(record.get("action")), module=_module_label(record),
                  body=text.encode("utf-8"), size=size, truncated=bool(omitted), kept=kept, omitted=omitted)


def download_filename(log: JobLog, today: datetime | None = None) -> str:
    day = (today or datetime.now(UTC)).strftime("%Y-%m-%d")
    return f"module-job-{safe_label(log.module)}-{safe_label(log.action)}-{day}.log"


# ------------------------------------------------------------------------------------------------ history


def _ascii_line(value, limit: int) -> str | None:
    """First line only, printable ASCII, cut to ``limit`` characters. None when nothing is left."""
    if value is None:
        return None
    text = str(value).strip().splitlines()[0] if str(value).strip() else ""
    text = "".join(ch for ch in text if " " <= ch <= "~").strip()
    return text[:limit] or None


def _short_error(value) -> str | None:
    """One plain sentence: scrubbed, first line only, paths removed, printable ASCII, at most 200 characters."""
    if value is None or not str(value).strip():
        return None
    text = scrub_text(clean_text(str(value).encode("utf-8", errors="replace")))
    line = next((part for part in text.splitlines() if part.strip()), "")
    line = re.sub(r"(?<![A-Za-z0-9_:.\-])/[^\s\"'<>|;,()\[\]]*", "<path>", line)
    return _ascii_line(line, 200)


def _module_ids(values) -> list[str]:
    result = []
    for value in values if isinstance(values, (list, tuple)) else []:
        if isinstance(value, str) and _MODULE_ID_RE.match(value) and value != "batch" and value not in result:
            result.append(value)
    return result


def _plan_actions(record: dict) -> list[dict]:
    plan = record.get("plan")
    actions = plan.get("actions") if isinstance(plan, dict) else None
    return [item for item in actions if isinstance(item, dict)] if isinstance(actions, list) else []


def build_row(record: dict, job_id: str, kind: str, logs_root: Path) -> dict:
    """One history row, built from a whitelist. Never from ``public_job``; no log text, path, hash or trust."""
    actions = _plan_actions(record)
    ids = _module_ids([item.get("id") for item in actions])
    for key in ("affected_modules",):
        ids += [item for item in _module_ids(record.get(key)) if item not in ids]
    for key in ("plugin_id", "module_id"):
        ids += [item for item in _module_ids([record.get(key)]) if item not in ids]
    versions = {}
    for item in actions:
        version = item.get("version")
        if isinstance(item.get("id"), str) and item["id"] in ids and isinstance(version, str) and _VERSION_RE.match(version):
            versions[item["id"]] = version
    base = record.get("base_version")
    if kind == "hotfix" and isinstance(base, str) and _VERSION_RE.match(base) and ids:
        versions.setdefault(ids[0], base)
    renamed_from = next((item.get("previous_module_id") for item in actions
                         if item.get("action") == "rename" and isinstance(item.get("previous_module_id"), str)
                         and _MODULE_ID_RE.match(item["previous_module_id"])), None)
    action = _ascii_line(record.get("action"), 40)
    disabled = _module_ids(record.get("disabled_modules"))
    enabled = _module_ids(record.get("enabled_modules"))
    switch = action in ("enable", "disable") and bool(
        disabled or enabled or record.get("reason") == "replacement_conflict"
        or _module_ids(record.get("disable_modules")) or _module_ids(record.get("enable_modules")))
    size = _log_size(logs_root, job_id)
    return {
        "id": job_id,
        "kind": kind,
        "action": action,
        "switch": switch,
        "renamed_from": renamed_from,
        "module_ids": ids,
        "versions": versions or None,
        "requested_by": _ascii_line(record.get("requested_by"), 150),
        "created_at": _ascii_line(record.get("created_at"), 40),
        "started_at": _ascii_line(record.get("started_at"), 40),
        "finished_at": _ascii_line(record.get("finished_at"), 40),
        "status": _ascii_line(record.get("status"), 40),
        "stage": _ascii_line(record.get("stage"), 40),
        "error": _short_error(record.get("error")),
        "has_log": size is not None,
        "log_bytes": size or 0,
        "disabled_modules": disabled,
        "enabled_modules": enabled,
        "reconciled_modules": _module_ids(record.get("reconciled_modules")),
        "hand_back_skipped": _module_ids(record.get("hand_back_skipped")),
    }


def _job_files(jobs_root: Path):
    """``(job id, path)`` of every ``<canonical uuid>.json`` regular file in the folder. Symlinks and odd names are skipped."""
    try:
        entries = list(os.scandir(jobs_root))
    except OSError:
        return []
    found = []
    for entry in entries:
        match = _JOB_FILE_RE.match(entry.name)
        if not match:
            continue
        try:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                continue
        except OSError:
            continue
        found.append((match.group(1), Path(entry.path)))
    return found


def history_rows() -> list[dict]:
    """Every readable module and hotfix job, newest first (ties by id). The retention sweep uses this same list."""
    rows = []
    for kind, jobs_root, logs_root in (("module", JOBS_ROOT, LOGS_ROOT), ("hotfix", HOTFIX_JOBS_ROOT, HOTFIX_LOGS_ROOT)):
        for job_id, path in _job_files(Path(jobs_root)):
            record = _read_json_file(path)
            if record is None:
                continue
            try:
                rows.append(build_row(record, job_id, kind, Path(logs_root)))
            except Exception:  # one odd record never takes the list down
                logger.warning("A module job record could not be summarised and was skipped.", exc_info=True)
    rows.sort(key=lambda row: (row["created_at"] or "", row["id"]), reverse=True)
    return rows


def _positive_int(value, name: str, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        number = int(str(value))
    except ValueError as exc:
        raise HistoryParameterError(f"{name} must be a whole number.") from exc
    if number < 1:
        raise HistoryParameterError(f"{name} must be 1 or more.")
    return number


def page_history(*, page=None, page_size=None, module=None, action=None, status=None, kind=None) -> dict:
    page = _positive_int(page, "page", 1)
    page_size = min(_positive_int(page_size, "page_size", DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE)
    module, action, status, kind = (str(item or "").strip() for item in (module, action, status, kind))
    rows = history_rows()
    if module:
        rows = [row for row in rows if module in row["module_ids"]]
    if action:
        rows = [row for row in rows if str(row["action"] or "").lower() == action.lower()]
    if status:
        rows = [row for row in rows if str(row["status"] or "").lower() == status.lower()]
    if kind:
        rows = [row for row in rows if row["kind"] == kind.lower()]
    total = len(rows)
    pages = (total + page_size - 1) // page_size if total else 0
    offset = (page - 1) * page_size
    return {
        "items": rows[offset:offset + page_size],
        "count": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
        "next_page": page + 1 if page < pages else None,
        "previous_page": page - 1 if page > 1 and pages else None,
    }


# ------------------------------------------------------------------------------------------------ retention


def _parse_time(value) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _gate():
    """``(open, cache)``. A cache error opens the gate: the sweep is bounded and writes no row when it removed nothing."""
    try:
        from django.core.cache import cache

        return cache.get(PRUNE_GATE_KEY) is None, cache
    except Exception:
        logger.debug("The module job retention gate could not use the cache; the sweep runs anyway.", exc_info=True)
        return True, None


def prune_expired(*, dry_run: bool = False, now: datetime | None = None) -> dict:
    """Remove finished job records older than ``MODULE_JOB_RETENTION_DAYS``, at most ``MAX_PRUNE_PER_RUN`` per run, oldest first.

    Kept always: a job that is queued, dispatched or running; a job whose time is missing or unreadable; the newest job (by
    creation time) for any module it names; anything that is not a regular ``<canonical uuid>.json`` file. Hotfix ``applied/``
    and ``history/`` are not touched. Logs are not touched here: only root can delete them (see the helpers' sweep).
    Returns the counts. ``dry_run`` deletes and audits nothing and ignores the hourly gate.
    """
    counts = {"retention_days": MODULE_JOB_RETENTION_DAYS, "records_removed": 0, "hotfix_records_removed": 0,
              "kept_newest_per_module": 0, "kept_active": 0, "logs_awaiting_root_sweep": 0, "dry_run": bool(dry_run)}
    cache = None
    if not dry_run:
        open_gate, cache = _gate()
        if not open_gate:
            counts["skipped"] = "ran_within_the_last_hour"
            return counts
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=MODULE_JOB_RETENTION_DAYS)
    rows = history_rows()
    newest = set()
    seen = set()
    for row in rows:  # newest first
        for module_id in row["module_ids"]:
            if (row["kind"], module_id) not in seen:
                seen.add((row["kind"], module_id))
                newest.add(row["id"])
    eligible = []
    for row in rows:
        status = str(row["status"] or "").lower()
        stamp = _parse_time(row["finished_at"] or row["created_at"])
        if stamp is None or stamp >= cutoff:
            continue
        if not status or status in ACTIVE_STATUSES:
            counts["kept_active"] += 1
            continue
        if row["id"] in newest:
            counts["kept_newest_per_module"] += 1
            continue
        eligible.append((stamp, row["id"], row))
    eligible.sort(key=lambda item: (item[0], item[1]))
    for _stamp, job_id, row in eligible[:MAX_PRUNE_PER_RUN]:
        jobs_root = Path(JOBS_ROOT if row["kind"] == "module" else HOTFIX_JOBS_ROOT)
        path = jobs_root / f"{job_id}.json"
        if not dry_run:
            try:
                info = os.lstat(path)
                if not stat.S_ISREG(info.st_mode):
                    continue
                os.unlink(path)
            except OSError:
                logger.warning("A module job record could not be removed by the retention sweep.", exc_info=True)
                continue
        counts["hotfix_records_removed" if row["kind"] == "hotfix" else "records_removed"] += 1
        counts["logs_awaiting_root_sweep"] += 1 if row["has_log"] else 0
    removed = counts["records_removed"] + counts["hotfix_records_removed"]
    if dry_run:
        return counts
    if removed:
        try:
            from . import audit

            audit.record(
                actor=audit.service_audit_actor(module_id="core", service="module-manager", identity="retention"),
                module_id="core", action="custom:module-job-retention", object_type="module_job_retention",
                metadata={key: counts[key] for key in ("retention_days", "records_removed", "hotfix_records_removed",
                                                       "kept_newest_per_module", "kept_active", "logs_awaiting_root_sweep")},
            )
        except Exception:
            logger.warning("The module job retention audit row could not be written; the removal stands.", exc_info=True)
    if cache is not None:
        try:
            cache.add(PRUNE_GATE_KEY, 1, PRUNE_GATE_SECONDS)
        except Exception:
            logger.debug("The module job retention gate could not be set; the next tick runs the sweep again.", exc_info=True)
    return counts

"""Tec-Tac framework/UI system update discovery, staging, and job dispatch.

The Django process only performs unprivileged discovery/download/inspection work.
Privileged replacement, backup, verification, and rollback are delegated to the
root-owned helper installed outside /opt/tec-tac so it survives self-updates.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

try:  # not on Windows; the cross-process locks need it, the rest of the module does not
    import fcntl
except ImportError:  # pragma: no cover - the development PC
    fcntl = None

from . import module_job_logs
from .safe_files import atomic_json
from .trusted_publishers import PublisherTrustError, verify_release_manifest_signature, verify_release_tree
from .trust_policy import TrustPolicyError, acceptance as trust_acceptance, get_policy as get_trust_policy, require_accepted as require_trust_accepted

STATE_ROOT = Path("/var/lib/tec-tac/system-updates")
CACHE_ROOT = STATE_ROOT / "cache"
RELEASE_CACHE = CACHE_ROOT / "release-cache.json"
RELEASE_CACHE_TTL = timedelta(hours=24)
BRANCH_CACHE_TTL = timedelta(minutes=5)
BRANCH_SUPPRESS_SECONDS = 20
RELEASE_SUPPRESS_SECONDS = 45
SINGLE_FLIGHT_WAIT_SECONDS = 20.0
CACHE_LOCK_WAIT_SECONDS = 5.0
CACHE_SCHEMA = 2
MAX_ETAG_ENTRIES = 64
MAX_COMMIT_METADATA = 200
MAX_RELEASE_VERIFICATIONS = 20
REFRESH_VALUES = ("none", "branch", "release", "all")
STAGED_ROOT = STATE_ROOT / "staged"
JOBS_ROOT = STATE_ROOT / "jobs"
LOGS_ROOT = STATE_ROOT / "logs"
HISTORY_ROOT = STATE_ROOT / "history"
HELPER = Path("/usr/local/sbin/tec-tac-system-update")
CONFIG = Path(os.environ.get("TEC_TAC_CONFIG_FILE", "/opt/tec-tac/etc/tec-tac.conf"))
MAX_PACKAGE_BYTES = 250 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20000
COMPONENTS = {"framework", "ui"}
DEFAULT_SIGNED_RELEASE_MIN_VERSION = {"framework": "1.15.37", "ui": None}


class SystemUpdateError(RuntimeError):
    pass


class GithubRequestError(SystemUpdateError):
    """A GitHub answer that is not a success. ``status`` is the HTTP status, or None for a transport failure."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class GithubRateLimitError(GithubRequestError):
    """GitHub's API rate limit is exhausted (1.17.98). Carries the structured error the API returns."""

    code = "github_rate_limit_exceeded"

    def __init__(self, reset_at: str | None = None, *, status: int | None = 403, cached_data_available: bool = False):
        super().__init__("GitHub API rate limit exhausted.", status)
        self.reset_at = reset_at
        self.cached_data_available = cached_data_available

    def as_dict(self, *, cached_data_available: bool | None = None) -> dict:
        return {
            "code": self.code,
            "detail": "GitHub API rate limit exhausted.",
            "reset_at": self.reset_at,
            "cached_data_available": self.cached_data_available if cached_data_available is None else bool(cached_data_available),
        }


class GithubUnreachableError(GithubRequestError):
    """GitHub could not be reached and a saved answer exists (1.17.98). ``saved_body`` is that answer.

    It is an error, never a fresh check: callers keep the old checked_at, set their error field and may
    show ``saved_body`` as stale. Code that must act on a current answer (an unpinned stage) refuses it.
    """

    def __init__(self, message: str, saved_body: object):
        super().__init__(message, None)
        self.saved_body = saved_body


class StaleCandidateError(SystemUpdateError):
    """A stage asked for a commit that is not the one the check showed (1.17.98)."""

    code = "stale_candidate"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, payload: dict) -> None:
    atomic_json(path, payload, mode=0o660)


def _read_config() -> dict[str, str]:
    values: dict[str, str] = {}
    if CONFIG.is_file():
        for line in CONFIG.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def _development_unsigned_update_allowed() -> bool:
    cfg = _read_config()
    environment = str(cfg.get("TEC_TAC_ENVIRONMENT") or "production").strip().lower()
    flag = str(cfg.get("TEC_TAC_ALLOW_UNSIGNED_DEVELOPMENT_UPDATES") or "").strip().lower()
    return environment == "development" and flag in {"1", "true", "yes", "on"}


def _accept_update_trust(trust: dict, *, subject: str) -> dict:
    try:
        return require_trust_accepted(trust, subject=subject)
    except TrustPolicyError:
        if not bool((trust or {}).get("signed")) and _development_unsigned_update_allowed():
            return {
                "minimum_level": get_trust_policy()["minimum_level"],
                "actual_level": "unsigned",
                "accepted": True,
                "development_unsigned_override": True,
            }
        raise


def _component_root(component: str) -> Path:
    cfg = _read_config()
    if component == "framework":
        return Path(cfg.get("TEC_TAC_FRAMEWORK_SOURCE", "/opt/tec-tac-src/framework"))
    if component == "ui":
        return Path(cfg.get("TEC_TAC_UI_SOURCE", "/opt/tec-tac-src/ui"))
    raise SystemUpdateError("Unknown system component.")


def _repo_name(component: str) -> str:
    cfg = _read_config()
    if component == "framework":
        return cfg.get("FRAMEWORK_REPOSITORY", "jvz007/tac-net-rep")
    if component == "ui":
        return cfg.get("UI_REPOSITORY", "jvz007/tec-tac-ui")
    raise SystemUpdateError("Unknown system component.")



def _signed_release_min_version(component: str) -> str | None:
    defaults = DEFAULT_SIGNED_RELEASE_MIN_VERSION.get(component)
    env_key = f"TEC_TAC_{component.upper()}_SIGNED_RELEASE_MIN_VERSION"
    value = str(os.environ.get(env_key, "")).strip()
    if not value:
        value = str(_read_config().get(env_key, "")).strip()
    if not value:
        value = str(defaults or "").strip()
    return value or None


def _release_requires_signature(component: str, version: str, source: dict | None) -> tuple[bool, str | None]:
    source_type = str((source or {}).get("type") or "offline")
    minimum = _signed_release_min_version(component)
    if source_type != "release" or not minimum:
        return False, minimum
    return _version_key(version) >= _version_key(minimum), minimum


def _unsigned_release_trust(*, component: str, version: str, source: dict | None) -> dict:
    required, minimum = _release_requires_signature(component, version, source)
    source_type = str((source or {}).get("type") or "offline")
    if required:
        raise SystemUpdateError(
            f"Signed {component} releases are required from version {minimum}; this release has no v0.2.0 signed-tree metadata."
        )
    legacy = source_type == "release"
    return {
        "signed": False,
        "verified": False,
        "trusted": False,
        "state": "unsigned",
        "label": "Unsigned / legacy" if legacy else "Unsigned",
        "legacy": legacy,
        "signed_release_min_version": minimum,
        "details": "No signed-tree metadata was present; legacy release fallback is permitted." if legacy else "No signed-tree metadata was present.",
    }


def _github_headers() -> dict[str, str]:
    cfg = _read_config()
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "tec-tac-system-updater/1.3",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token_file = cfg.get("GITHUB_TOKEN_FILE", "/opt/tec-tac/etc/github-token")
    path = Path(token_file)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise SystemUpdateError("GitHub token path must be a regular non-symlink file.")
        st = path.stat()
        tactical_user = str(cfg.get("TACTICAL_USER") or "tactical").strip() or "tactical"
        try:
            tactical_gid = pwd.getpwnam(tactical_user).pw_gid
        except KeyError as exc:
            raise SystemUpdateError("Configured Tactical service account does not exist.") from exc
        if st.st_uid != 0 or st.st_gid != tactical_gid or (st.st_mode & 0o007) or (st.st_mode & 0o020):
            raise SystemUpdateError("GitHub token file must be root-owned, assigned to the Tactical group, not group-writable, and inaccessible to other users.")
        try:
            token = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SystemUpdateError("GitHub token file cannot be read by the Tec-Tac runtime.") from exc
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return headers


_GITHUB_TOKEN_HOSTS = frozenset({"api.github.com", "github.com", "codeload.github.com"})
_MAX_GITHUB_REDIRECTS = 5


def _keeps_github_token(url: str) -> bool:
    """True only for https on one of the three approved GitHub hosts, on the default port."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return False
    return parts.scheme == "https" and host in _GITHUB_TOKEN_HOSTS and port in (None, 443)


class _GithubRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow a GitHub redirect over https only, at most 5 hops, and send the token only to the approved hosts."""

    max_redirections = _MAX_GITHUB_REDIRECTS
    max_repeats = _MAX_GITHUB_REDIRECTS

    def http_error_302(self, req, fp, code, msg, headers):
        # urllib checks the scheme itself and raises HTTPError for file:// and friends; refuse every non-https target first, with our own message.
        target = headers.get("location") or headers.get("uri") or ""
        try:
            scheme = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, target)).scheme.lower()
        except ValueError:
            scheme = ""
        if target and scheme != "https":
            raise SystemUpdateError("GitHub redirected to a non-HTTPS address; the download was refused.")
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise SystemUpdateError("GitHub redirected to a non-HTTPS address; the download was refused.")
        if len(getattr(req, "redirect_dict", {})) >= _MAX_GITHUB_REDIRECTS:
            raise SystemUpdateError("GitHub redirected too many times; the request was refused.")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and not _keeps_github_token(newurl):
            for store in (new.headers, new.unredirected_hdrs):
                for key in [k for k in store if k.lower() == "authorization"]:
                    del store[key]
        return new


def _build_github_opener(*extra_handlers):
    return urllib.request.build_opener(_GithubRedirectHandler, *extra_handlers)


def _github_open(request, *, timeout):
    if urllib.parse.urlsplit(request.full_url).scheme.lower() != "https":
        raise SystemUpdateError("GitHub address must use HTTPS; the request was refused.")
    return _build_github_opener().open(request, timeout=timeout)


_PATH_LOCKS: dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()
_NET = threading.local()


def _network_calls() -> int:
    """Outbound GitHub requests made by this thread so far (used to report whether a check hit the network)."""
    return int(getattr(_NET, "count", 0))


@contextlib.contextmanager
def _file_lock(path: Path, timeout: float):
    """Exclusive lock on ``path``: a thread lock plus fcntl.flock across worker processes.

    Yields True when the lock is held and False when it could not be taken in ``timeout`` seconds
    (or at all). Callers fail closed on False: they use the cache, they never send a second request.
    """
    key = str(path)
    with _PATH_LOCKS_GUARD:
        thread_lock = _PATH_LOCKS.setdefault(key, threading.Lock())
    if not thread_lock.acquire(timeout=timeout):
        yield False
        return
    fd = None
    try:
        held = True
        if fcntl is not None:
            held = False
            try:
                fd = os.open(key, os.O_RDWR | os.O_CREAT, 0o660)
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        held = True
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            break
                        time.sleep(0.05)
            except OSError:
                held = False
        yield held
    finally:
        if fd is not None:
            try:
                os.close(fd)  # closing the descriptor releases the flock
            except OSError:
                pass
        thread_lock.release()


def _cache_update(mutator) -> bool:
    """Read-modify-write the cache file under the short cache lock so workers do not lose each other's updates.

    Returns False (and writes nothing) when the lock or the file cannot be had: the cache is an optimisation.
    """
    try:
        if not CACHE_ROOT.parent.is_dir():
            return False
        CACHE_ROOT.mkdir(parents=True, exist_ok=True)
        with _file_lock(CACHE_ROOT / "release-cache.lock", CACHE_LOCK_WAIT_SECONDS) as held:
            if not held:
                return False
            doc = _read_release_cache()
            mutator(doc)
            _write_release_cache(doc)
            return True
    except OSError:
        return False


def _refresh_lock(component: str, kind: str, ref: str):
    """Single-flight lock for one refresh: github-refresh:<component>:<branch|release>:<ref>."""
    name = hashlib.sha256(f"github-refresh:{component}:{kind}:{ref}".encode()).hexdigest()[:24]
    try:
        CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return _file_lock(CACHE_ROOT / f"github-refresh-{name}.lock", SINGLE_FLIGHT_WAIT_SECONDS)


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _lower_headers(headers: object) -> dict[str, str]:
    try:
        return {str(k).lower(): str(v) for k, v in headers.items()}  # type: ignore[union-attr]
    except AttributeError:
        return {}


def _rate_limit_telemetry(headers: object, *, authenticated: bool) -> dict | None:
    """Non-sensitive rate-limit telemetry from GitHub's X-RateLimit headers. The token is never part of it."""
    h = _lower_headers(headers)
    limit, remaining, used = (_int_or_none(h.get(f"x-ratelimit-{name}")) for name in ("limit", "remaining", "used"))
    reset = _int_or_none(h.get("x-ratelimit-reset"))
    if limit is None and remaining is None and reset is None:
        return None
    reset_at = None
    if reset:
        try:
            reset_at = datetime.fromtimestamp(reset, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            reset_at = None
    return {
        "limit": limit, "remaining": remaining, "used": used, "reset": reset, "reset_at": reset_at,
        "resource": h.get("x-ratelimit-resource") or None,
        "authenticated": bool(authenticated), "observed_at": _utcnow(), "limited": False,
    }


def _github_rate_limit_status() -> dict | None:
    """The saved telemetry, read from the cache file only (never calls GitHub)."""
    try:
        row = (_read_release_cache().get("github") or {}).get("rate_limit")
    except OSError:
        return None
    return dict(row) if isinstance(row, dict) else None


def _rate_limit_blocked_until() -> str | None:
    """reset_at while an exhausted limit has a reset time in the future, else None."""
    row = _github_rate_limit_status()
    if not row or not row.get("limited"):
        return None
    reset = _parse_cached_at(row.get("reset_at"))
    if reset is not None and reset > datetime.now(timezone.utc):
        return row.get("reset_at")
    return None


def _reduce_body(url: str, body: object) -> object:
    """Keep only the fields Tec-Tac reads, so the saved ETag copy stays small."""
    path = urllib.parse.urlsplit(url).path
    if not isinstance(body, dict):
        return body
    if path.endswith("/releases/latest"):
        return {k: body.get(k) for k in ("tag_name", "name", "published_at", "html_url")}
    if "/commits/" in path:
        return {"sha": body.get("sha")}
    if "/branches/" in path:
        commit = body.get("commit") if isinstance(body.get("commit"), dict) else {}
        inner = commit.get("commit") if isinstance(commit.get("commit"), dict) else {}
        committer = inner.get("committer") if isinstance(inner.get("committer"), dict) else {}
        return {"commit": {"sha": commit.get("sha"), "commit": {"committer": {"date": committer.get("date")}}}}
    return body


def _etag_entry(key: str) -> dict | None:
    try:
        row = ((_read_release_cache().get("github") or {}).get("etags") or {}).get(key)
    except OSError:
        return None
    return row if isinstance(row, dict) and "body" in row else None


def _save_github_result(key: str | None, entry: dict | None, telemetry: dict | None) -> None:
    def mutate(doc: dict) -> None:
        github = doc.setdefault("github", {})
        if telemetry is not None:
            github["rate_limit"] = telemetry
        if key is not None and entry is not None:
            etags = github.setdefault("etags", {})
            etags[key] = entry
            if len(etags) > MAX_ETAG_ENTRIES:
                for old in sorted(etags, key=lambda k: str((etags[k] or {}).get("checked_at") or ""))[: len(etags) - MAX_ETAG_ENTRIES]:
                    etags.pop(old, None)

    _cache_update(mutate)


def github_get_json(url: str, cache_key: str | None = None, ttl: timedelta | None = None, force: bool = False, conditional: bool = True) -> object:
    """The one GitHub metadata transport (1.17.98).

    A fresh saved answer (younger than ``ttl``, not ``force``) needs no network. A stale one is
    revalidated with If-None-Match: a 304 only refreshes checked_at and returns the saved body, a 200
    saves body + ETag. A transport failure with a saved answer raises GithubUnreachableError carrying the
    stale body (never returned as if it were fresh); with nothing saved, GithubRequestError. While a saved rate-limit
    reset time is in the future nothing is sent. Every response, 304 and errors included, updates the
    non-sensitive rate-limit telemetry. A 401 or a 403 that is not a rate limit is raised and never saved.
    ``conditional`` False skips the saved copy (immutable content such as a file at a commit).
    """
    key = (cache_key or url) if conditional else None
    entry = _etag_entry(key) if key else None
    if entry and ttl is not None and not force:
        checked = _parse_cached_at(entry.get("checked_at"))
        if checked is not None and datetime.now(timezone.utc) - checked < ttl:
            return entry["body"]
    blocked = _rate_limit_blocked_until()
    if blocked is not None:
        raise GithubRateLimitError(blocked, cached_data_available=entry is not None)
    headers = _github_headers()
    authenticated = "Authorization" in headers
    if entry and entry.get("etag"):
        headers["If-None-Match"] = str(entry["etag"])
    request = urllib.request.Request(url, headers=headers)
    _NET.count = _network_calls() + 1
    try:
        with _github_open(request, timeout=20) as response:
            raw = response.read()
            resp_headers = getattr(response, "headers", None)
            body = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        h = _lower_headers(exc.headers)
        telemetry = _rate_limit_telemetry(exc.headers, authenticated=authenticated)
        if exc.code == 304 and entry:
            _save_github_result(key, {**entry, "checked_at": _utcnow()}, telemetry)
            return entry["body"]
        retry_after = _int_or_none(h.get("retry-after"))
        exhausted = exc.code in (403, 429) and (
            (telemetry is not None and telemetry.get("remaining") == 0) or retry_after is not None or exc.code == 429
        )
        if exhausted:
            reset_at = telemetry.get("reset_at") if telemetry else None
            if retry_after is not None:
                reset_at = datetime.fromtimestamp(time.time() + retry_after, tz=timezone.utc).isoformat()
            telemetry = dict(telemetry or {"authenticated": authenticated, "observed_at": _utcnow()})
            telemetry.update(limited=True, reset_at=reset_at)
            _save_github_result(None, None, telemetry)
            raise GithubRateLimitError(reset_at, status=exc.code, cached_data_available=entry is not None) from exc
        _save_github_result(None, None, telemetry)
        try:
            text = exc.read().decode("utf-8", errors="replace")[:500]
        except (OSError, ValueError, AttributeError):
            text = ""
        raise GithubRequestError(f"GitHub request failed ({exc.code}): {text or exc.reason}", exc.code) from exc
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        if entry:
            # The saved body is kept, but flagged: callers must not record it as a fresh check.
            raise GithubUnreachableError(
                f"GitHub could not be reached ({exc.__class__.__name__}); the saved answer is shown.", entry["body"],
            ) from exc
        raise GithubRequestError(f"GitHub request failed: {exc}") from exc
    telemetry = _rate_limit_telemetry(resp_headers, authenticated=authenticated)
    saved = None
    if key:
        h = _lower_headers(resp_headers)
        saved = {
            "etag": h.get("etag"), "last_modified": h.get("last-modified"),
            "body": _reduce_body(url, body), "checked_at": _utcnow(),
        }
    _save_github_result(key, saved, telemetry)
    return body


def _github_json(url: str) -> object:
    return github_get_json(url)


def _github_content_bytes(repo: str, path: str, ref: str) -> bytes | None:
    encoded_path = urllib.parse.quote(path, safe="/")
    encoded_ref = urllib.parse.quote(ref, safe="")
    url = f"https://api.github.com/repos/{repo}/contents/{encoded_path}?ref={encoded_ref}"
    try:
        payload = github_get_json(url, conditional=False)
    except GithubRequestError as exc:
        if exc.status == 404:
            return None
        raise
    if not isinstance(payload, dict) or payload.get("type") != "file" or payload.get("encoding") != "base64":
        raise SystemUpdateError(f"GitHub returned unexpected content metadata for {path}.")
    try:
        return base64.b64decode(str(payload.get("content") or ""), validate=False)
    except Exception as exc:
        raise SystemUpdateError(f"GitHub returned invalid Base64 content for {path}.") from exc


def _release_signature_preview(component: str, repo: str, commit: str) -> dict:
    manifest = _github_content_bytes(repo, "tec-tac-release.json", commit)
    signature = _github_content_bytes(repo, "tec-tac-release.json.sig", commit)
    if manifest is None and signature is None:
        return {
            "signed": False,
            "verified": False,
            "manifest_verified": False,
            "tree_verified": False,
            "trusted": False,
            "state": "unsigned",
            "details": "No signed-tree manifest or signature is present on this release.",
        }
    if manifest is None or signature is None:
        return {
            "signed": True,
            "verified": False,
            "manifest_verified": False,
            "tree_verified": False,
            "trusted": False,
            "state": "invalid",
            "details": "Release signing metadata is incomplete; both manifest and detached signature are required.",
        }
    try:
        return verify_release_manifest_signature(
            manifest_bytes=manifest,
            signature_bytes=signature,
            expected_component=component,
            required_permissions=(f"{component}.update",),
        )
    except PublisherTrustError as exc:
        return {
            "signed": True,
            "verified": False,
            "manifest_verified": False,
            "tree_verified": False,
            "trusted": False,
            "state": "invalid",
            "error_code": exc.code,
            "details": str(exc),
        }


def _annotate_trust_acceptance(trust: dict | None) -> dict:
    row = dict(trust) if isinstance(trust, dict) else {}
    try:
        row["acceptance_policy"] = trust_acceptance(row)
    except TrustPolicyError as exc:
        policy = get_trust_policy()
        row["acceptance_policy"] = {
            "minimum_level": policy["minimum_level"],
            "minimum_label": policy["minimum_label"],
            "actual_level": None,
            "actual_label": "Invalid / untrusted",
            "accepted": False,
            "detail": str(exc),
        }
    return row


def _safe_archive_name(name: str) -> Path:
    value = PurePosixPath(name.replace("\\", "/"))
    if value.is_absolute() or ".." in value.parts:
        raise SystemUpdateError(f"Unsafe archive path: {name!r}")
    return Path(*value.parts)


def _extract_archive(archive: Path, dest: Path) -> None:
    lower = archive.name.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise SystemUpdateError("Archive contains too many members.")
            if sum(info.file_size for info in infos) > MAX_EXTRACTED_BYTES:
                raise SystemUpdateError("Archive expands beyond the allowed size limit.")
            for info in infos:
                rel = _safe_archive_name(info.filename)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise SystemUpdateError(f"Archive contains a symbolic link: {info.filename!r}")
                target = (dest / rel).resolve()
                try:
                    target.relative_to(dest.resolve())
                except ValueError as exc:
                    raise SystemUpdateError(f"Archive path escapes extraction root: {info.filename!r}") from exc
            zf.extractall(dest)
        return
    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tf:
            members = tf.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise SystemUpdateError("Archive contains too many members.")
            if sum(member.size for member in members if member.isfile()) > MAX_EXTRACTED_BYTES:
                raise SystemUpdateError("Archive expands beyond the allowed size limit.")
            for member in members:
                rel = _safe_archive_name(member.name)
                if member.issym() or member.islnk():
                    raise SystemUpdateError(f"Archive contains a link: {member.name!r}")
                if not (member.isdir() or member.isfile()):
                    raise SystemUpdateError(f"Archive contains an unsupported special file: {member.name!r}")
                target = (dest / rel).resolve()
                try:
                    target.relative_to(dest.resolve())
                except ValueError as exc:
                    raise SystemUpdateError(f"Archive path escapes extraction root: {member.name!r}") from exc
            tf.extractall(dest, filter="data")
        return
    raise SystemUpdateError("Package must end in .zip, .tar.gz, or .tgz")


def _candidate_component(root: Path) -> str | None:
    if (root / "VERSION").is_file() and (root / "install.sh").is_file() and (root / "framwork" / "tec_tac").is_dir():
        return "framework"
    if (root / "VERSION").is_file() and (root / "package.json").is_file() and (root / "src" / "App.vue").is_file() and (root / "scripts" / "install.sh").is_file():
        return "ui"
    return None


def _find_package_root(extracted: Path) -> tuple[str, Path]:
    matches: list[tuple[str, Path]] = []
    for root, dirs, files in os.walk(extracted):
        path = Path(root)
        depth = len(path.relative_to(extracted).parts)
        if depth > 3:
            dirs[:] = []
            continue
        component = _candidate_component(path)
        if component:
            matches.append((component, path))
            dirs[:] = []
    if len(matches) != 1:
        raise SystemUpdateError(f"Package must contain exactly one Tec-Tac framework or UI repository root; found {len(matches)}")
    return matches[0]


def _read_version(root: Path) -> str:
    value = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not value or len(value) > 80 or "\n" in value:
        raise SystemUpdateError("VERSION is missing or invalid.")
    return value


def _version_key(value: str) -> tuple:
    # Deterministic, dependency-free comparison suitable for the project's
    # numeric release versions. Any suffix sorts before a suffix-free release.
    match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$", value.strip(), re.I)
    if not match:
        return (0, 0, 0, 0, value.lower())
    nums = tuple(int(x or 0) for x in match.groups()[:3])
    suffix = (match.group(4) or "").strip()
    rebuild = re.fullmatch(r"-(\d+)", suffix)
    if rebuild:
        return (*nums, 2, int(rebuild.group(1)))
    return (*nums, 1 if not suffix else 0, suffix.lower())


def _satisfies(version: str | None, constraint: str | None) -> bool:
    if not constraint:
        return True
    if not version:
        return False
    text = str(constraint).strip()
    for operator in (">=", "<=", ">", "<", "==", "="):
        if text.startswith(operator):
            wanted = text[len(operator):].strip()
            actual_key = _version_key(version)
            wanted_key = _version_key(wanted)
            return {
                ">=": actual_key >= wanted_key,
                "<=": actual_key <= wanted_key,
                ">": actual_key > wanted_key,
                "<": actual_key < wanted_key,
                "==": actual_key == wanted_key,
                "=": actual_key == wanted_key,
            }[operator]
    return _version_key(version) == _version_key(text)


def _operation(installed: str | None, package: str) -> str:
    if not installed:
        return "install"
    current = _version_key(installed)
    incoming = _version_key(package)
    if incoming > current:
        return "update"
    if incoming < current:
        return "downgrade"
    return "reinstall"


def _installed_version(component: str) -> str | None:
    path = _component_root(component) / "VERSION"
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def inspect_archive(archive: Path, *, source: dict | None = None, release_manifest: Path | None = None, release_signature: Path | None = None) -> dict:
    if not archive.is_file():
        raise SystemUpdateError("Staged system update package was not found.")
    source = source or {"type": "offline"}
    with tempfile.TemporaryDirectory(prefix="tec-tac-system-inspect-") as tmp:
        extracted = Path(tmp) / "payload"
        extracted.mkdir()
        _extract_archive(archive, extracted)
        component, root = _find_package_root(extracted)
        version = _read_version(root)
        package_manifest = None
        manifest_path = root / "tec_tac_package.json"
        if manifest_path.is_file():
            try:
                package_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SystemUpdateError(f"tec_tac_package.json is invalid: {exc}") from exc
            if not isinstance(package_manifest, dict):
                raise SystemUpdateError("tec_tac_package.json must contain an object.")
            declared = package_manifest.get("type")
            expected = "tec-tac-framework" if component == "framework" else "tec-tac-ui"
            if declared and declared != expected:
                raise SystemUpdateError(f"Package manifest type {declared!r} does not match detected component {expected!r}.")
            declared_version = str(package_manifest.get("version", version)).strip()
            if declared_version != version:
                raise SystemUpdateError("Package manifest version does not match VERSION.")

        signed_manifest = root / "tec-tac-release.json"
        signed_signature = root / "tec-tac-release.json.sig"
        if release_manifest is not None or release_signature is not None:
            if release_manifest is None or release_signature is None:
                raise SystemUpdateError("Both tec-tac-release.json and tec-tac-release.json.sig are required for a detached signed update.")
            if signed_manifest.exists() or signed_signature.exists():
                raise SystemUpdateError("Signed release metadata is ambiguous: provide it either inside the archive or as detached uploads, not both.")
            shutil.copyfile(release_manifest, signed_manifest)
            shutil.copyfile(release_signature, signed_signature)
        if signed_manifest.exists() or signed_signature.exists():
            try:
                release_trust = verify_release_tree(root=root, expected_component=component, required_permissions=(f"{component}.update",))
            except PublisherTrustError as exc:
                raise SystemUpdateError(f"Signed release verification failed [{exc.code}]: {exc}") from exc
            release_trust["label"] = "Verified"
            release_trust["legacy"] = False
            release_trust["signed_release_min_version"] = _signed_release_min_version(component)
            release_trust["details"] = f"Verified manifest signature and {release_trust.get('file_count', 0)} release files."
        else:
            release_trust = _unsigned_release_trust(component=component, version=version, source=source)
        try:
            release_trust["acceptance_policy"] = _accept_update_trust(release_trust, subject=f"{component.title()} update")
        except TrustPolicyError as exc:
            raise SystemUpdateError(f"Update trust policy rejected {component} package: {exc}") from exc

    installed = _installed_version(component)
    installable = True
    block_reason = None
    compatibility = {}
    requires = package_manifest.get("requires", {}) if isinstance(package_manifest, dict) else {}
    if isinstance(requires, dict):
        fw_constraint = requires.get("tec-tac-framework")
        if fw_constraint:
            fw_version = version if component == "framework" else _installed_version("framework")
            ok = _satisfies(fw_version, str(fw_constraint))
            compatibility["tec-tac-framework"] = {"installed": fw_version, "requires": str(fw_constraint), "ok": ok}
            if not ok:
                installable = False
                block_reason = f"Requires Tec-Tac Framework {fw_constraint}; installed {fw_version or 'none'}."
    return {
        "component": component,
        "component_label": "Tec-Tac Framework" if component == "framework" else "Tec-Tac UI",
        "version": version,
        "installed_version": installed,
        "operation": _operation(installed, version),
        "manifest": package_manifest,
        "source": source,
        "release_trust": release_trust,
        "compatibility": compatibility,
        "installable": installable,
        "install_block_reason": block_reason,
    }


def _allowed_suffix(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".tar.gz"):
        return ".tar.gz"
    if lower.endswith(".tgz"):
        return ".tgz"
    if lower.endswith(".zip"):
        return ".zip"
    raise SystemUpdateError("Package must end in .zip, .tar.gz, or .tgz")


def _copy_uploaded_sidecar(upload, destination: Path, *, maximum: int = 1024 * 1024) -> tuple[int, str]:
    size = int(getattr(upload, "size", 0) or 0)
    if size <= 0:
        raise SystemUpdateError(f"{getattr(upload, 'name', 'Signed release sidecar')} is empty.")
    if size > maximum:
        raise SystemUpdateError("Signed release sidecar exceeds the 1 MiB limit.")
    digest = hashlib.sha256()
    written = 0
    with destination.open("wb") as handle:
        for chunk in upload.chunks():
            written += len(chunk)
            if written > maximum:
                handle.close()
                destination.unlink(missing_ok=True)
                raise SystemUpdateError("Signed release sidecar exceeds the 1 MiB limit.")
            digest.update(chunk)
            handle.write(chunk)
    if written <= 0:
        destination.unlink(missing_ok=True)
        raise SystemUpdateError("Signed release sidecar is empty.")
    os.chmod(destination, 0o640)
    return written, digest.hexdigest()


def _stage_bytes(reader, *, filename: str, source: dict, expected_component: str | None = None, release_manifest_upload=None, release_signature_upload=None) -> dict:
    suffix = _allowed_suffix(filename)
    if (release_manifest_upload is None) != (release_signature_upload is None):
        raise SystemUpdateError("Both tec-tac-release.json and tec-tac-release.json.sig must be uploaded together.")
    STAGED_ROOT.mkdir(parents=True, exist_ok=True)
    upload_id = str(uuid.uuid4())
    package_path = STAGED_ROOT / f"{upload_id}{suffix}"
    manifest_path = STAGED_ROOT / f"{upload_id}.release.json" if release_manifest_upload is not None else None
    signature_path = STAGED_ROOT / f"{upload_id}.release.json.sig" if release_signature_upload is not None else None
    digest = hashlib.sha256()
    written = 0
    try:
        with package_path.open("wb") as handle:
            while True:
                chunk = reader(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_PACKAGE_BYTES:
                    raise SystemUpdateError(f"Package exceeds the {MAX_PACKAGE_BYTES // (1024 * 1024)} MiB limit.")
                digest.update(chunk)
                handle.write(chunk)
        if written <= 0:
            raise SystemUpdateError("Package is empty.")
        os.chmod(package_path, 0o640)
        sidecars = {}
        if manifest_path is not None and signature_path is not None:
            manifest_size, manifest_sha256 = _copy_uploaded_sidecar(release_manifest_upload, manifest_path)
            signature_size, signature_sha256 = _copy_uploaded_sidecar(release_signature_upload, signature_path)
            sidecars = {
                "release_manifest_path": str(manifest_path),
                "release_manifest_filename": str(getattr(release_manifest_upload, "name", "tec-tac-release.json")),
                "release_manifest_size": manifest_size,
                "release_manifest_sha256": manifest_sha256,
                "release_signature_path": str(signature_path),
                "release_signature_filename": str(getattr(release_signature_upload, "name", "tec-tac-release.json.sig")),
                "release_signature_size": signature_size,
                "release_signature_sha256": signature_sha256,
            }
        preview = inspect_archive(
            package_path, source=source, release_manifest=manifest_path, release_signature=signature_path
        )
        if expected_component and preview["component"] != expected_component:
            raise SystemUpdateError(f"Repository returned {preview['component']} package while {expected_component} was requested.")
    except Exception:
        package_path.unlink(missing_ok=True)
        if manifest_path is not None:
            manifest_path.unlink(missing_ok=True)
        if signature_path is not None:
            signature_path.unlink(missing_ok=True)
        raise
    metadata = {
        "upload_id": upload_id,
        "filename": filename,
        "package_path": str(package_path),
        "sha256": digest.hexdigest(),
        "size": written,
        "created_at": _utcnow(),
        "preview": preview,
        **sidecars,
    }
    _atomic_json(STAGED_ROOT / f"{upload_id}.json", metadata)
    return {k: v for k, v in metadata.items() if not k.endswith("_path") and k != "package_path"}


def stage_uploaded_package(upload, *, release_manifest_upload=None, release_signature_upload=None) -> dict:
    size = int(getattr(upload, "size", 0) or 0)
    if size <= 0:
        raise SystemUpdateError("Package is empty.")
    if size > MAX_PACKAGE_BYTES:
        raise SystemUpdateError(f"Package exceeds the {MAX_PACKAGE_BYTES // (1024 * 1024)} MiB limit.")
    iterator = iter(upload.chunks())
    buffer = bytearray()

    def reader(_size):
        nonlocal buffer
        if buffer:
            value = bytes(buffer)
            buffer = bytearray()
            return value
        try:
            return next(iterator)
        except StopIteration:
            return b""

    return _stage_bytes(
        reader,
        filename=str(getattr(upload, "name", "package.zip")),
        source={"type": "offline"},
        release_manifest_upload=release_manifest_upload,
        release_signature_upload=release_signature_upload,
    )


def _download_to_stage(url: str, *, filename: str, source: dict, component: str) -> dict:
    request = urllib.request.Request(url, headers=_github_headers())
    try:
        response = _github_open(request, timeout=45)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemUpdateError(f"Repository archive download failed ({exc.code}): {body or exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SystemUpdateError(f"Repository archive download failed: {exc}") from exc
    with response:
        return _stage_bytes(response.read, filename=filename, source=source, expected_component=component)


def _empty_cache() -> dict:
    return {
        "schema": CACHE_SCHEMA, "components": {}, "branches": {}, "branch_sources": {},
        "commit_metadata": {}, "release_verification": {}, "github": {"rate_limit": None, "etags": {}},
    }


def _read_release_cache() -> dict:
    """The cache file, schema 2. A schema 1 file is read and upgraded (the next write saves it as schema 2).

    A missing, corrupt or wrong-shape file reads as empty; it is rebuilt by the next check.
    """
    if not RELEASE_CACHE.is_file():
        return _empty_cache()
    try:
        payload = json.loads(RELEASE_CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _empty_cache()
    if not isinstance(payload, dict) or not isinstance(payload.get("components"), dict):
        return _empty_cache()
    for name in ("branches", "branch_sources", "commit_metadata", "release_verification"):
        if not isinstance(payload.get(name), dict):
            payload[name] = {}
    github = payload.get("github") if isinstance(payload.get("github"), dict) else {}
    if not isinstance(github.get("etags"), dict):
        github["etags"] = {}
    if not isinstance(github.get("rate_limit"), dict):
        github["rate_limit"] = None
    payload["github"] = github
    payload["schema"] = CACHE_SCHEMA
    return payload


def _write_release_cache(payload: dict) -> None:
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    _atomic_json(RELEASE_CACHE, payload)


def _parse_cached_at(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _release_from_cache(component: str, *, installed: str | None = None) -> dict | None:
    repo = _repo_name(component)
    row = (_read_release_cache().get("components") or {}).get(component)
    if not isinstance(row, dict) or row.get("repository") != repo:
        return None
    release = row.get("latest_release")
    if not isinstance(release, dict) or not str(release.get("tag") or "").strip():
        return None
    tag = str(release.get("tag") or "").strip()
    return {
        "component": component,
        "repository": repo,
        "installed_version": installed if installed is not None else _installed_version(component),
        "latest_release": {
            "tag": tag,
            "name": release.get("name") or tag,
            "published_at": release.get("published_at"),
            "html_url": release.get("html_url"),
            "release_trust": release.get("release_trust"),
            "commit": release.get("commit"),
            "operation": _operation(installed if installed is not None else _installed_version(component), tag.lstrip("v")),
        },
        "checked_at": row.get("checked_at"),
        "release_error": None,
        "cache": {"hit": True, "stale": False, "ttl_hours": 24},
    }


def cached_online_status(component: str, source: dict | None = None) -> dict:
    """Persisted release row for a component, read-only (no GitHub call).

    1.17.4: with a branch ``source`` the cached stable release is the secondary
    ``stable_release`` and ``latest_release`` is null, so GET /system/updates/ no longer
    shows the stable release as the answer under a branch source. ``source`` is added.
    With no source, or a release source, the answer is unchanged.
    """
    if component not in COMPONENTS:
        raise SystemUpdateError("component must be framework or ui")
    installed = _installed_version(component)
    cached = _release_from_cache(component, installed=installed)
    if cached is not None:
        checked = _parse_cached_at(cached.get("checked_at"))
        cached["cache"]["stale"] = checked is None or datetime.now(timezone.utc) - checked >= RELEASE_CACHE_TTL
        latest = cached.get("latest_release")
        if isinstance(latest, dict):
            latest["release_trust"] = _annotate_trust_acceptance(latest.get("release_trust"))
    else:
        cached = {
            "component": component,
            "repository": _repo_name(component),
            "installed_version": installed,
            "latest_release": None,
            "checked_at": None,
            "release_error": None,
            "cache": {"hit": False, "stale": True, "ttl_hours": 24},
        }
    if _is_branch_source(source):
        cached["stable_release"] = cached["latest_release"]
        cached["latest_release"] = None
        cached["source"] = {"type": "branch", "ref": str(source.get("ref") or "")}
    return cached


def _is_branch_source(source: object) -> bool:
    return isinstance(source, dict) and source.get("type") == "branch"


def _trust_fingerprint() -> str:
    """Fingerprint of the trust policy and the trusted publisher keys; a change forces a signature re-check."""
    try:
        policy: object = get_trust_policy()
    except TrustPolicyError:
        policy = {"unreadable": True}
    try:
        from . import trusted_publishers as _tp

        lister = getattr(_tp, "list_trusted_publishers", None)
        publishers: object = lister() if lister else []
    except (ImportError, OSError, ValueError, TypeError):
        publishers = [{"unreadable": True}]
    blob = json.dumps({"policy": policy, "publishers": publishers}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _cached_signature_preview(component: str, repo: str, commit: str) -> dict:
    """The display-only signature preview, cached by repository + release commit + trust fingerprint.

    A network or transient error is never cached (it raises before anything is saved). The preview is
    display only: staging still runs the full inspect_archive verification on the downloaded bytes.
    """
    key = f"{repo}:{commit.lower()}"
    fingerprint = _trust_fingerprint()
    row = (_read_release_cache().get("release_verification") or {}).get(key)
    if isinstance(row, dict) and row.get("fingerprint") == fingerprint and isinstance(row.get("preview"), dict):
        return dict(row["preview"])
    preview = _release_signature_preview(component, repo, commit)

    def mutate(doc: dict) -> None:
        store = doc.setdefault("release_verification", {})
        store[key] = {"fingerprint": fingerprint, "preview": preview, "checked_at": _utcnow()}
        if len(store) > MAX_RELEASE_VERIFICATIONS:
            for old in sorted(store, key=lambda k: str((store[k] or {}).get("checked_at") or ""))[: len(store) - MAX_RELEASE_VERIFICATIONS]:
                store.pop(old, None)

    _cache_update(mutate)
    return preview


def _release_online_status(component: str, *, force: bool = False, notes: dict | None = None) -> dict:
    """The stable-release answer. Fresh cache: no network. Force inside 45 s of the last check: the saved answer."""
    if notes is None:
        notes = {}
    if component not in COMPONENTS:
        raise SystemUpdateError("component must be framework or ui")
    cached = cached_online_status(component)
    checked = _parse_cached_at(cached.get("checked_at"))
    fresh = checked is not None and datetime.now(timezone.utc) - checked < RELEASE_CACHE_TTL
    if cached.get("latest_release") and fresh and not force:
        return cached
    if force and cached.get("latest_release") and checked is not None and (datetime.now(timezone.utc) - checked).total_seconds() < RELEASE_SUPPRESS_SECONDS:
        notes["suppressed"] = True
        return cached
    started = datetime.now(timezone.utc)
    with _refresh_lock(component, "release", "latest") as held:
        again = cached_online_status(component)
        again_checked = _parse_cached_at(again.get("checked_at"))
        if again.get("latest_release") and again_checked is not None and (
            again_checked > started or (not force and datetime.now(timezone.utc) - again_checked < RELEASE_CACHE_TTL)
        ):
            notes["shared"] = True  # another request refreshed it while this one waited
            return again
        if not held:
            # Fail closed to the saved answer; never send a second request.
            again["release_error"] = "Another update check is already running; the saved result is shown."
            return again
        return _fetch_release_status(component, again, notes)


def _fetch_release_status(component: str, cached: dict, notes: dict) -> dict:
    repo = _repo_name(component)
    installed = _installed_version(component)
    payload = {
        "component": component,
        "repository": repo,
        "installed_version": installed,
        "latest_release": None,
        "checked_at": None,
        "release_error": None,
        "cache": {"hit": False, "stale": False, "ttl_hours": 24},
    }
    try:
        release = _github_json(f"https://api.github.com/repos/{repo}/releases/latest")
        if not isinstance(release, dict):
            raise SystemUpdateError("GitHub returned an unexpected release response.")
        tag = str(release.get("tag_name", "")).strip()
        if not tag:
            raise SystemUpdateError("GitHub did not return a stable release tag.")
        encoded_tag = urllib.parse.quote(tag, safe="")
        commit_info = _github_json(f"https://api.github.com/repos/{repo}/commits/{encoded_tag}")
        commit = str(commit_info.get("sha", "")) if isinstance(commit_info, dict) else ""
        if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            raise SystemUpdateError("Unable to resolve stable release to an exact commit SHA.")
        trust_preview = _annotate_trust_acceptance(_cached_signature_preview(component, repo, commit))
        checked_at = _utcnow()
        release_row = {
            "tag": tag,
            "name": release.get("name") or tag,
            "published_at": release.get("published_at"),
            "html_url": release.get("html_url"),
            "commit": commit,
            "release_trust": trust_preview,
        }

        def mutate(doc: dict) -> None:
            doc.setdefault("components", {})[component] = {
                "repository": repo,
                "checked_at": checked_at,
                "latest_release": release_row,
            }

        _cache_update(mutate)  # the cache is an optimisation; the answer is still good
        payload["checked_at"] = checked_at
        payload["latest_release"] = {
            **release_row,
            "operation": _operation(installed, tag.lstrip("v")),
        }
    except SystemUpdateError as exc:
        # A transient repository failure must not erase the last known stable
        # release. Return the persisted value as stale telemetry when available.
        if cached.get("latest_release"):
            payload = cached
            payload["cache"] = {"hit": True, "stale": True, "ttl_hours": 24}
        payload["release_error"] = str(exc)
        if isinstance(exc, GithubRateLimitError):
            notes["rate_limit"] = exc
    return payload


def _short(commit: object) -> str | None:
    return str(commit)[:7] if isinstance(commit, str) and commit else None


def _installed_source_commit(component: str, repo: str) -> tuple[str | None, dict | None]:
    """The GitHub commit the installed code came from, or (None, None) when unknown.

    This is the provenance recorded on the most recent succeeded install job of the
    component (1.17.2). It is not read from source_git: before 1.17.98 the root helper
    committed the verified bytes to a local branch, so that SHA never equalled GitHub's head.
    If the most recent install came from another repository, from an offline upload
    or from before 1.17.2, it has no matching commit and the answer is unknown.
    """
    newest: dict | None = None
    newest_at = ""
    for root in (HISTORY_ROOT, JOBS_ROOT):
        if not root.is_dir():
            continue
        for path in root.glob("*.json"):
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(job, dict) or job.get("status") != "succeeded":
                continue
            if job.get("component") != component or job.get("action", "install") != "install":
                continue
            finished = str(job.get("finished_at") or job.get("created_at") or "")
            if newest is None or finished > newest_at:
                newest, newest_at = job, finished
    source = (newest or {}).get("source")
    if not isinstance(source, dict) or source.get("repository") != repo:
        return None, None
    commit = source.get("commit")
    commit = commit.lower() if isinstance(commit, str) and re.fullmatch(r"[0-9a-fA-F]{40}", commit) else None
    return commit, {"type": source.get("type"), "ref": source.get("ref")}


_SHA40 = re.compile(r"[0-9a-fA-F]{40}")


def _branch_row(component: str, repo: str, ref: str) -> dict | None:
    """The saved head of a branch (schema 2 branch_sources, or the schema 1 row), or None."""
    doc = _read_release_cache()
    row = (doc.get("branch_sources") or {}).get(f"{repo}:{ref}")
    if not isinstance(row, dict):
        legacy = (doc.get("branches") or {}).get(component)
        if isinstance(legacy, dict) and legacy.get("repository") == repo and legacy.get("ref") == ref:
            row = {
                "head_commit": legacy.get("head_commit"), "head_date": legacy.get("head_date"),
                "checked_at": legacy.get("checked_at"), "last_network_check": legacy.get("checked_at"),
            }
    if isinstance(row, dict) and isinstance(row.get("head_commit"), str) and _SHA40.fullmatch(row["head_commit"]):
        return row
    return None


def _age_seconds(value: object) -> float | None:
    parsed = _parse_cached_at(value)
    return None if parsed is None else (datetime.now(timezone.utc) - parsed).total_seconds()


def _branch_head(component: str, repo: str, ref: str, *, force: bool, notes: dict | None = None) -> dict:
    """Head commit and date of a branch: one conditional GET /branches/<ref> when the saved head is stale.

    A saved head younger than 5 minutes needs no request. A forced refresh inside 20 s of the last
    network check returns the saved head ('recently_refreshed'). Concurrent refreshes (threads or
    workers) take one lock: the first sends the request, the others read what it saved.
    """
    if notes is None:
        notes = {}

    def out(row: dict) -> dict:
        return {"head_commit": row["head_commit"], "head_date": row.get("head_date")}

    row = _branch_row(component, repo, ref)
    if row is not None:
        checked_age = _age_seconds(row.get("checked_at"))
        if not force and checked_age is not None and checked_age < BRANCH_CACHE_TTL.total_seconds():
            return out(row)
        network_age = _age_seconds(row.get("last_network_check"))
        if force and network_age is not None and network_age < BRANCH_SUPPRESS_SECONDS:
            notes["suppressed"] = True
            return out(row)
    started = datetime.now(timezone.utc)
    with _refresh_lock(component, "branch", ref) as held:
        row = _branch_row(component, repo, ref)
        if row is not None:
            last = _parse_cached_at(row.get("last_network_check"))
            checked_age = _age_seconds(row.get("checked_at"))
            if (last is not None and last > started) or (
                not force and checked_age is not None and checked_age < BRANCH_CACHE_TTL.total_seconds()
            ):
                notes["shared"] = True
                return out(row)
        if not held:
            if row is not None:
                notes["lock_unavailable"] = True
                return out(row)  # fail closed to the saved head, never a second request
            raise SystemUpdateError("Another update check is already running; try again in a moment.")
        url = f"https://api.github.com/repos/{repo}/branches/{urllib.parse.quote(ref, safe='')}"
        try:
            info = _github_json(url)
        except GithubRateLimitError as exc:
            notes["rate_limit"] = exc
            if row is not None:
                return out(row)
            raise
        except GithubUnreachableError as exc:
            # Show the saved head with the error; its checked_at stays as it was, so the next check tries again.
            if row is not None:
                notes["branch_error"] = str(exc)
                return out(row)
            raise
        commit_row = info.get("commit") if isinstance(info, dict) else None
        if not isinstance(commit_row, dict):
            raise SystemUpdateError("Unable to resolve branch commit.")
        commit = str(commit_row.get("sha", ""))
        if not _SHA40.fullmatch(commit):
            raise SystemUpdateError("GitHub returned an invalid branch commit SHA.")
        inner = commit_row.get("commit") if isinstance(commit_row.get("commit"), dict) else {}
        committer = inner.get("committer") if isinstance(inner.get("committer"), dict) else {}
        head_date = committer.get("date") if isinstance(committer.get("date"), str) else None

        def mutate(doc: dict) -> None:
            now = _utcnow()
            etag = (((doc.get("github") or {}).get("etags") or {}).get(url) or {}).get("etag")
            sources = doc.setdefault("branch_sources", {})
            sources[f"{repo}:{ref}"] = {
                "head_commit": commit, "head_date": head_date, "checked_at": now, "etag": etag, "last_network_check": now,
            }
            if len(sources) > 40:
                for old in sorted(sources, key=lambda k: str((sources[k] or {}).get("last_network_check") or ""))[: len(sources) - 40]:
                    sources.pop(old, None)
            doc.setdefault("branches", {})[component] = {
                "repository": repo, "ref": ref, "checked_at": now, "head_commit": commit, "head_date": head_date,
            }

        _cache_update(mutate)  # the cache is an optimisation; the answer is still good
        return {"head_commit": commit, "head_date": head_date}


_PLAUSIBLE_VERSION = re.compile(r"v?\d+(?:\.\d+){1,2}(?:-[0-9A-Za-z.]+)?")


def _plausible_version(value: object) -> str | None:
    text = value.strip() if isinstance(value, str) else ""
    return text if text and len(text) <= 40 and _PLAUSIBLE_VERSION.fullmatch(text) else None


def _branch_head_version(component: str, repo: str, ref: str, head_commit: str, *, force: bool = False) -> str | None:
    """The VERSION file at a commit, or None when it cannot be read.

    Content at a commit never changes, so the value is saved under repo:sha in commit_metadata with no
    expiry and reused on every later check (``force`` does not bypass it). It never raises: a failed
    read leaves the state unknown. It is only called when no installed commit is known.
    """
    try:
        key = f"{repo}:{head_commit.lower()}"
        meta = (_read_release_cache().get("commit_metadata") or {}).get(key)
        saved = _plausible_version(meta.get("version")) if isinstance(meta, dict) else None
        if saved:
            return saved
        raw = _github_content_bytes(repo, "VERSION", head_commit)
        version = _plausible_version(raw.decode("utf-8")) if raw is not None else None
        if version is None:
            return None

        def mutate(doc: dict) -> None:
            store = doc.setdefault("commit_metadata", {})
            store[key] = {"version": version, "signature_checked": False, "checked_at": _utcnow()}
            if len(store) > MAX_COMMIT_METADATA:
                for old in sorted(store, key=lambda k: str((store[k] or {}).get("checked_at") or ""))[: len(store) - MAX_COMMIT_METADATA]:
                    store.pop(old, None)

        _cache_update(mutate)
        return version
    except (SystemUpdateError, UnicodeDecodeError, OSError, ValueError):  # a VERSION read never raises or sets branch_error
        return None


def _branch_status(component: str, ref: str, *, force: bool, notes: dict | None = None) -> tuple[dict, str | None]:
    repo = _repo_name(component)
    branch = {
        "ref": ref, "head_commit": None, "head_short": None, "head_date": None,
        "installed_commit": None, "installed_short": None, "installed_source": None,
        "state": "unknown", "differs": None,
        "basis": None, "head_version": None, "installed_version": None,
    }
    error = None
    if notes is None:
        notes = {}
    try:
        head = _branch_head(component, repo, ref, force=force, notes=notes)
        error = notes.pop("branch_error", None)  # the saved head is shown, flagged as not refreshed
        branch.update(head_commit=head["head_commit"].lower(), head_short=_short(head["head_commit"]), head_date=head["head_date"])
        installed_commit, installed_source = _installed_source_commit(component, repo)
        branch.update(installed_commit=installed_commit, installed_short=_short(installed_commit), installed_source=installed_source)
        if installed_commit:
            branch["differs"] = installed_commit != branch["head_commit"]
            branch["state"] = "differs" if branch["differs"] else "same"
            branch["basis"] = "commit"
        else:
            # 1.17.3 (CQ11): no install recorded a commit, so compare VERSION files. This is weaker
            # than a commit match: a branch can gain commits without a VERSION bump.
            head_version = _branch_head_version(component, repo, ref, branch["head_commit"], force=force)
            installed_version = _plausible_version(_installed_version(component))
            branch.update(head_version=head_version, installed_version=installed_version)
            if head_version and installed_version:
                branch["differs"] = _version_key(head_version) != _version_key(installed_version)
                branch["state"] = "differs" if branch["differs"] else "same"
                branch["basis"] = "version"
    except GithubRateLimitError as exc:
        notes["rate_limit"] = exc
        error = str(exc)
    except SystemUpdateError as exc:
        error = str(exc)
    except Exception as exc:  # a branch failure must never hide the release data
        error = f"Branch check failed: {exc.__class__.__name__}"
    return branch, error


def _normalize_refresh(refresh: object, force: bool, source: dict | None) -> str:
    """The refresh scope. An explicit value wins; force=true keeps its old meaning for the active source, never 'all'."""
    if refresh is None or str(refresh).strip() == "":
        if force:
            return "branch" if _is_branch_source(source) else "release"
        return "none"
    value = str(refresh).strip().lower()
    if value not in REFRESH_VALUES:
        raise SystemUpdateError("refresh must be none, branch, release or all.")
    return value


def _finish_online(payload: dict, *, requested: str, calls_before: int, notes: dict, has_data: bool) -> dict:
    """Add the refresh object and the saved rate-limit telemetry; surface exhaustion with or without saved data."""
    network = _network_calls() > calls_before
    limited = notes.get("rate_limit")
    if limited is not None and not network:
        reason = "rate_limited"
    elif notes.get("suppressed") and not network:
        reason = "recently_refreshed"
    elif network:
        reason = "refreshed" if requested != "none" else "cache_stale"
    elif notes.get("shared"):
        reason = "refreshed_by_another_request"
    else:
        reason = "cache_fresh"
    payload["refresh"] = {"network_request": network, "reason": reason, "requested": requested}
    payload["github_rate_limit"] = _github_rate_limit_status()
    if limited is not None:
        if not has_data:
            limited.cached_data_available = False
            raise limited
        payload["github_rate_limit_error"] = limited.as_dict(cached_data_available=True)
    return payload


def online_status(component: str, *, force: bool = False, source: dict | None = None, refresh: str | None = None) -> dict:
    """Online status for a component.

    ``refresh`` is none (default, saved answers; at most one conditional request per stale component),
    branch, release or all. ``force`` stays as an alias: for a branch source it means refresh=branch, for a
    release source refresh=release, never all (1.17.98). With no source or a release source the answer is
    the stable-release answer with no ``stable_release`` key. With a branch source the branch result is
    primary and ``latest_release`` stays null (1.17.3); ``source``, ``branch`` and ``branch_error`` are
    added, and so is ``stable_release``, the stable release as secondary information. It is read from the
    saved copy and shown stale until refresh=release or all: a branch refresh makes one request,
    GET /branches/<ref>, and never touches the release. A release failure sets release_error only. A branch
    failure sets branch_error only and never hides stable_release. Exhausted GitHub limits add
    github_rate_limit_error and keep the saved answer; with nothing saved GithubRateLimitError is raised.
    """
    if component not in COMPONENTS:
        raise SystemUpdateError("component must be framework or ui")
    requested = _normalize_refresh(refresh, force, source)
    force_branch = requested in ("branch", "all")
    force_release = requested in ("release", "all")
    notes: dict = {}
    calls_before = _network_calls()
    if not _is_branch_source(source):
        payload = _release_online_status(component, force=force_release, notes=notes)
        return _finish_online(payload, requested=requested, calls_before=calls_before, notes=notes, has_data=bool(payload.get("latest_release")))
    ref = str(source.get("ref") or "")
    payload = {
        "component": component,
        "repository": _repo_name(component),
        "installed_version": _installed_version(component),
        "latest_release": None,
        "checked_at": None,
        "release_error": None,
        "cache": {"hit": False, "stale": False, "ttl_hours": 24},
        "source": {"type": "branch", "ref": ref},
        "stable_release": None,
    }
    try:
        if force_release:
            release = _release_online_status(component, force=True, notes=notes)
        else:
            release = cached_online_status(component)  # saved copy only; a branch refresh never fetches the release
        payload["stable_release"] = release.get("latest_release")
        payload["checked_at"] = release.get("checked_at")
        payload["cache"] = release.get("cache") or payload["cache"]
        payload["release_error"] = release.get("release_error")
    except (SystemUpdateError, OSError, ValueError, TypeError, KeyError) as exc:
        # A release failure, even a cache write error, must never fail the branch answer.
        payload["release_error"] = (
            str(exc) if isinstance(exc, SystemUpdateError) else f"Release check failed: {exc.__class__.__name__}"
        )
    payload["branch"], payload["branch_error"] = _branch_status(component, ref, force=force_branch, notes=notes)
    has_data = bool(payload["branch"].get("head_commit")) or bool(payload.get("stable_release"))
    return _finish_online(payload, requested=requested, calls_before=calls_before, notes=notes, has_data=has_data)


def list_branches(component: str) -> dict:
    if component not in COMPONENTS:
        raise SystemUpdateError("component must be framework or ui")
    repo = _repo_name(component)
    url = f"https://api.github.com/repos/{repo}/branches?per_page=100"
    limited = None
    try:
        branches = _github_json(url)
    except GithubRateLimitError as exc:
        entry = _etag_entry(url)
        if not entry or not isinstance(entry.get("body"), list):
            raise
        branches, limited = entry["body"], exc.as_dict(cached_data_available=True)
    except GithubUnreachableError as exc:
        branches = exc.saved_body  # the branch picker keeps showing the saved list, as before 1.17.98
    if not isinstance(branches, list):
        raise SystemUpdateError("GitHub returned an unexpected branch response.")
    result = {
        "component": component,
        "repository": repo,
        "branches": [
            {"name": str(item.get("name", "")), "sha": str((item.get("commit") or {}).get("sha", ""))}
            for item in branches if isinstance(item, dict) and item.get("name")
        ],
    }
    if limited is not None:
        result["github_rate_limit_error"] = limited
    return result


_STALE_MESSAGE = "The update you checked is no longer the one on record. Refresh the check and try again."


def stage_online_package(component: str, source_type: str, ref: str | None = None, commit: str | None = None) -> dict:
    """Download, inspect and stage an online package.

    With ``commit`` (1.17.98) the stage is pinned to what the check showed: the commit must equal the saved
    branch head or saved release commit, and then no metadata call is made, only the archive download.
    Anything else raises StaleCandidateError; Core never installs another commit silently. Without
    ``commit`` the branch or release is resolved as before; when GitHub cannot be reached the saved answer
    is refused (GithubUnreachableError), never staged. Full archive verification runs either way.
    """
    if component not in COMPONENTS:
        raise SystemUpdateError("component must be framework or ui")
    repo = _repo_name(component)
    pinned = None
    if commit is not None and str(commit).strip():
        pinned = str(commit).strip().lower()
        if not _SHA40.fullmatch(pinned):
            raise SystemUpdateError("commit must be a 40-character hexadecimal SHA.")
    if source_type == "release":
        if pinned:
            row = (_read_release_cache().get("components") or {}).get(component)
            saved = row.get("latest_release") if isinstance(row, dict) and row.get("repository") == repo else None
            if not isinstance(saved, dict) or not saved.get("tag") or str(saved.get("commit") or "").lower() != pinned:
                raise StaleCandidateError(_STALE_MESSAGE)
            tag, commit = str(saved["tag"]), pinned
        else:
            release = _github_json(f"https://api.github.com/repos/{repo}/releases/latest")
            if not isinstance(release, dict) or not release.get("tag_name"):
                raise SystemUpdateError("No latest GitHub release was returned for this repository.")
            tag = str(release["tag_name"])
            encoded_tag = urllib.parse.quote(tag, safe="")
            commit_info = _github_json(f"https://api.github.com/repos/{repo}/commits/{encoded_tag}")
            commit = str(commit_info.get("sha", "")) if isinstance(commit_info, dict) else ""
            if not _SHA40.fullmatch(commit):
                raise SystemUpdateError("Unable to resolve stable release to an exact commit SHA.")
        shaish = commit
        source = {"type": "release", "repository": repo, "ref": tag, "commit": commit}
    elif source_type == "branch":
        branch = (ref or "").strip()
        if not branch or len(branch) > 200:
            raise SystemUpdateError("A branch name is required.")
        if pinned:
            row = _branch_row(component, repo, branch)
            if row is None or row["head_commit"].lower() != pinned:
                raise StaleCandidateError(_STALE_MESSAGE)
            commit = pinned
        else:
            encoded = urllib.parse.quote(branch, safe="")
            branch_info = _github_json(f"https://api.github.com/repos/{repo}/branches/{encoded}")
            if not isinstance(branch_info, dict) or not branch_info.get("commit"):
                raise SystemUpdateError("Unable to resolve branch commit.")
            commit = str((branch_info.get("commit") or {}).get("sha", ""))
            if not _SHA40.fullmatch(commit):
                raise SystemUpdateError("GitHub returned an invalid branch commit SHA.")
        shaish = commit
        source = {"type": "branch", "repository": repo, "ref": branch, "commit": commit}
    else:
        raise SystemUpdateError("source_type must be release or branch")

    url = f"https://api.github.com/repos/{repo}/zipball/{urllib.parse.quote(shaish, safe='')}"
    filename = f"{component}-{source_type}-{str(shaish)[:12]}.zip"
    return _download_to_stage(url, filename=filename, source=source, component=component)


def _load_stage(upload_id: str) -> dict:
    try:
        uuid.UUID(str(upload_id))
    except ValueError as exc:
        raise SystemUpdateError("Invalid upload id.") from exc
    meta_path = STAGED_ROOT / f"{upload_id}.json"
    if not meta_path.is_file():
        raise SystemUpdateError("Staged system update package was not found or has already been consumed.")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemUpdateError("Staged package metadata is invalid.") from exc
    package_path = Path(str(meta.get("package_path", ""))).resolve()
    try:
        package_path.relative_to(STAGED_ROOT.resolve())
    except ValueError as exc:
        raise SystemUpdateError("Staged package path is invalid.") from exc
    if not package_path.is_file():
        raise SystemUpdateError("Staged package file is missing.")
    meta["package_path"] = str(package_path)
    for key in ("release_manifest_path", "release_signature_path"):
        raw = meta.get(key)
        if not raw:
            continue
        sidecar = Path(str(raw)).resolve()
        try:
            sidecar.relative_to(STAGED_ROOT.resolve())
        except ValueError as exc:
            raise SystemUpdateError("Staged signed release sidecar path is invalid.") from exc
        if not sidecar.is_file():
            raise SystemUpdateError("Staged signed release sidecar file is missing.")
        meta[key] = str(sidecar)
    return meta


def discard_stage(upload_id: str) -> None:
    meta = _load_stage(upload_id)
    Path(meta["package_path"]).unlink(missing_ok=True)
    for key in ("release_manifest_path", "release_signature_path"):
        if meta.get(key):
            Path(meta[key]).unlink(missing_ok=True)
    (STAGED_ROOT / f"{upload_id}.json").unlink(missing_ok=True)


def _new_job(payload: dict) -> dict:
    JOBS_ROOT.mkdir(parents=True, exist_ok=True)
    job_id = str(uuid.uuid4())
    job = {
        "id": job_id,
        "status": "queued",
        "created_at": _utcnow(),
        "started_at": None,
        "finished_at": None,
        "stage": "queued",
        "error": None,
        "error_type": None,
        "rollback": None,
        **payload,
    }
    _atomic_json(JOBS_ROOT / f"{job_id}.json", job)
    return job


def _dispatch(job_id: str) -> None:
    if not HELPER.is_file():
        raise SystemUpdateError(f"Privileged system update helper is not installed at {HELPER}.")
    try:
        subprocess.run(["sudo", "-n", str(HELPER), "--dispatch", job_id], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=15)
    except subprocess.CalledProcessError as exc:
        raise SystemUpdateError((exc.stderr or "System update helper dispatch failed.").strip()) from exc
    except subprocess.TimeoutExpired as exc:
        raise SystemUpdateError("System update helper dispatch timed out.") from exc


def queue_install(upload_id: str, *, allow_downgrade: bool = False, requested_by: str | None = None) -> dict:
    meta = _load_stage(upload_id)
    preview = meta.get("preview") or {}
    operation = preview.get("operation")
    try:
        current_acceptance = _accept_update_trust(preview.get("release_trust"), subject="System update")
        if isinstance(preview.get("release_trust"), dict):
            preview["release_trust"]["acceptance_policy"] = current_acceptance
    except TrustPolicyError as exc:
        raise SystemUpdateError(f"Update trust policy rejected staged system update: {exc}") from exc
    if not preview.get("installable", False):
        raise SystemUpdateError(preview.get("install_block_reason") or "System update package is not compatible with this installation.")
    if operation == "downgrade" and not allow_downgrade:
        raise SystemUpdateError("Downgrade requires explicit allow_downgrade=true confirmation.")
    # The privileged helper treats this file as a request only. It resolves the
    # staged package from upload_id and independently re-verifies trust as root.
    job = _new_job({
        "action": "install",
        "component": preview.get("component"),
        "upload_id": upload_id,
        "allow_downgrade": bool(allow_downgrade),
        "requested_by": str(requested_by or ""),
        "version": preview.get("version"),
        "operation": operation,
        # Provenance only (1.17.2). The root helper copies a sanitised copy into the
        # history row; it is never an execution authority.
        "source": preview.get("source") if isinstance(preview.get("source"), dict) else {"type": "offline"},
    })
    try:
        _dispatch(job["id"])
    except Exception:
        (JOBS_ROOT / f"{job['id']}.json").unlink(missing_ok=True)
        raise
    return public_job(job)


def public_job(job: dict, *, include_log_tail: bool = True) -> dict:
    allowed = {
        "id", "status", "created_at", "started_at", "finished_at", "stage", "error", "error_type",
        "rollback", "action", "component", "version", "installed_version", "operation", "package_sha256",
        "package_filename", "source", "release_trust", "backup_path", "requested_by", "source_git",
    }
    result = {k: v for k, v in job.items() if k in allowed}
    # 1.17.67 (additive): the size of the kept log, so the UI can show a Download button only when there is something to download
    job_key = str(job.get("id") or "")
    log_bytes = module_job_logs._log_size(LOGS_ROOT, job_key) if module_job_logs._UUID_RE.match(job_key) else None
    result["log_bytes"] = log_bytes
    result["has_log"] = log_bytes is not None
    if not include_log_tail:
        return result
    # 1.17.96: the last 200 lines (was 80), read from the end of the file only.
    result["log_tail"] = module_job_logs.tail_lines(LOGS_ROOT / f"{job.get('id')}.log")
    return result


def get_job(job_id: str) -> dict:
    try:
        uuid.UUID(str(job_id))
    except ValueError as exc:
        raise SystemUpdateError("Invalid job id.") from exc
    path = JOBS_ROOT / f"{job_id}.json"
    if not path.is_file():
        # 1.17.67: a job that finished and was removed from the jobs folder is still in history
        history = module_job_logs._read_json_file(HISTORY_ROOT / f"{str(job_id).lower()}.json")
        if history is None:
            raise SystemUpdateError("System update job was not found.")
        return public_job(history)
    try:
        job = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemUpdateError("System update job status is unreadable.") from exc
    return public_job(job)


LIST_SCAN_FILES = 500  # the list reads the newest files by modification time, never more


def _find_job_record(job_id: str):
    """The record of one job: the jobs folder first, then history. None when neither has a readable regular file."""
    for root in (JOBS_ROOT, HISTORY_ROOT):
        record = module_job_logs._read_json_file(Path(root) / f"{job_id}.json")
        if record is not None:
            return record
    return None


def list_jobs(*, page=None, page_size=None, component=None, status=None) -> dict:
    """The system update jobs, newest first, a page at a time (1.17.67). Jobs folder and history are merged by file name (history wins). Only
    the newest ``LIST_SCAN_FILES`` files are read. Whitelisted fields only: no log text, no path of the backup. Raises
    ``module_job_logs.HistoryParameterError`` for a bad page or page_size."""
    page = module_job_logs._positive_int(page, "page", 1)
    page_size = min(module_job_logs._positive_int(page_size, "page_size", module_job_logs.DEFAULT_PAGE_SIZE), module_job_logs.MAX_PAGE_SIZE)
    component, status = str(component or "").strip().lower(), str(status or "").strip().lower()
    files = {}
    for root in (JOBS_ROOT, HISTORY_ROOT):  # history is read last, so its file wins
        for job_id, path in module_job_logs._job_files(Path(root)):
            try:
                files[job_id] = (os.lstat(path).st_mtime, job_id, path)
            except OSError:
                continue
    newest = sorted(files.values(), key=lambda item: (item[0], item[1]), reverse=True)[:LIST_SCAN_FILES]
    rows = []
    for _mtime, job_id, path in newest:
        record = module_job_logs._read_json_file(path)
        if record is None or str(record.get("id") or job_id) != job_id:
            continue
        if component and str(record.get("component") or "").lower() != component:
            continue
        if status and str(record.get("status") or "").lower() != status:
            continue
        row = public_job(record, include_log_tail=False)
        row.pop("backup_path", None)
        rows.append(row)
    rows.sort(key=lambda row: (row.get("finished_at") or row.get("created_at") or "", str(row.get("id") or "")), reverse=True)
    total = len(rows)
    pages = (total + page_size - 1) // page_size if total else 0
    offset = (page - 1) * page_size
    return {
        "jobs": rows[offset:offset + page_size], "count": len(rows[offset:offset + page_size]), "total": total, "page": page, "page_size": page_size,
        "pages": pages, "next_page": page + 1 if page < pages else None, "previous_page": page - 1 if page > 1 and pages else None,
    }


def read_job_log(job_id):
    """The scrubbed, capped text of the log of one system update job (1.17.67). Raises ``module_job_logs.JobLogError``: 400 for a bad id, 404
    ``job_not_found`` for an unknown or unreadable job and 404 ``no_log`` when no log was kept."""
    job_id = module_job_logs.parse_job_id(str(job_id))
    record = _find_job_record(job_id)
    if record is None:
        raise module_job_logs.JobLogError(404, "That system update job was not found.", "job_not_found")
    return module_job_logs.read_log_for(
        job_id, LOGS_ROOT, ((None, ".log"),), record, (), kind="system-update", action=str(record.get("action") or "install"),
        module=str(record.get("component") or ""))


def _recent_history(limit: int = 12) -> list[dict]:
    items = []
    roots = [HISTORY_ROOT, JOBS_ROOT]
    seen = set()
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.glob("*.json"):
            if path.name in seen:
                continue
            seen.add(path.name)
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if payload.get("status") not in {"succeeded", "failed"}:
                continue
            items.append(public_job(payload))
    items.sort(key=lambda item: item.get("finished_at") or item.get("created_at") or "", reverse=True)
    return items[:limit]


def _saved_update_sources() -> dict:
    from .runtime_settings import get_update_sources

    return get_update_sources()


def system_status() -> dict:
    saved_sources = _saved_update_sources()
    return {
        "framework": {
            "version": _installed_version("framework"),
            "repository": _repo_name("framework"),
        },
        "ui": {
            "version": _installed_version("ui"),
            "repository": _repo_name("ui"),
        },
        # Read-only persisted release discovery lets the UI show the last known
        # stable versions immediately, before any GitHub request is necessary.
        "release_cache": {
            component: cached_online_status(component, saved_sources.get(component))
            for component in sorted(COMPONENTS)
        },
        "accepted_archives": [".zip", ".tar.gz", ".tgz"],
        "advanced_sources": {"branch_requires_unlock": True},
        "update_sources": saved_sources,
        # 1.17.98: the saved GitHub rate-limit telemetry, read from the cache file only (no GitHub call).
        "github_rate_limit": _github_rate_limit_status(),
        "signed_release_policy": {component: {"minimum_version": _signed_release_min_version(component)} for component in sorted(COMPONENTS)},
        "update_trust_policy": get_trust_policy(),
        "history": _recent_history(),
    }

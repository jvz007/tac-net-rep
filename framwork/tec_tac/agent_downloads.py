"""Core's agent file download (Core 1.18.37, capability core.agent_downloads 1.0.0; 1.1.0 in Core 1.18.39 adds the public installer;
Core 1.18.40 makes that route cheap).

A verified module (for example Endpoint Agent Management) owns a file in its own folder, such as an agent MSI. It asks Core for a short
link for ONE device and ONE file (``grant_download``). The device then fetches the file over HTTPS from Core's own host with the same
agent token and agent id the websocket uses (route GET /api/tfd/agent-downloads/<token>/, see agent_download_views.py).

What Core does here: it checks who is calling, checks the file, hashes it, stores a short-lived grant (Django's cache, only the HASH of the
link token is a key) and writes a strict audit row. What Core does not do: it never knows what the file means, never keeps a copy and
never serves anything the module did not grant to that device.

Core 1.18.39 (AD-74, capability 1.1.0): ONE public installer. The one publisher module (INSTALLER_PUBLISHERS) marks one file of its own as the
current Endpoint Agent installer (``publish_installer``); Core serves exactly that file, without sign-in, at the fixed route
GET /api/tfd/endpoint-agent/installer.msi (agent_download_views.InstallerDownloadView). The file carries no secret: the agent it installs
cannot connect without its own token. Core never redirects.

Core 1.18.40 (same capability version): the SHA-256 is computed once, at publish, and stored with the file's size and modified time
(``mtime_ns``, migration 0047). A serve re-hashes only when the size or modified time differ from the published ones. The route has 2
installer slots (INSTALLER_MAX_INFLIGHT), taken before the store is read, and answers 404 while the publisher module is disabled.

Secrets: the link token is returned once to the caller and is never logged, audited or kept in the clear (the cache holds its SHA-256).
Every refusal carries a reason code only. No Django import at the top of this file.
"""
from __future__ import annotations

import errno
import hashlib
import hmac
import logging
import os
import re
import secrets
import stat
import time
from datetime import datetime, timezone
from typing import Any

from .endpoint_transport import AGENT_ID_PATTERN

logger = logging.getLogger("tec_tac.agent_downloads")

CAPABILITY_ID = "core.agent_downloads"
CAPABILITY_VERSION = "1.1.0"
ROUTE_PATTERN = "agent-downloads/<str:token>/"
ROUTE_PATH = "/api/tfd/agent-downloads/<str:token>/"
MIN_TTL_SECONDS = 30
DEFAULT_TTL_SECONDS = 600
MAX_TTL_SECONDS = 900  # 15 minutes
MAX_FILE_BYTES = 100_000_000  # the safe reading of the agent's "100 MB"
MAX_PATH_CHARS = 4096
MAX_INFLIGHT = 8  # downloads being served at once, across all Core processes
INFLIGHT_TTL_SECONDS = 120  # the counter heals itself when a worker dies mid-download
CHUNK_BYTES = 1024 * 1024

GRANT_PREFIX = "tec-tac:agentdl:grant:"
SLOT_PREFIX = "tec-tac:agentdl:slot:"
INFLIGHT_KEY = "tec-tac:agentdl:inflight"
INSTALLER_INFLIGHT_KEY = "tec-tac:agentdl:installer-inflight"  # 1.18.39: its own counter, so an anonymous flood cannot starve device downloads
INSTALLER_MAX_INFLIGHT = 2  # 1.18.40: below the smallest uwsgi worker count (6); a flood costs one cache increment once both are taken
INSTALLER_ROUTE_PATH = "/api/tfd/endpoint-agent/installer.msi"
INSTALLER_SLOT = "endpoint-agent"  # the one row of the installer store
INSTALLER_PUBLISHERS = ("endpoint-agent-management",)  # the only module that may publish (AD-74 names it); widen by adding an id
INSTALLER_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]{1,32})?$")
INSTALLER_VERSION_MAX = 40
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
LINK_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")  # secrets.token_urlsafe(32)
MODULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}(:[0-9]{1,5})?$")

AUDIT_GRANTED = "custom:agent-download-granted"
AUDIT_REVOKED = "custom:agent-download-revoked"
AUDIT_SERVED = "custom:agent-download-served"
AUDIT_REFUSED = "custom:agent-download-refused"
AUDIT_INSTALLER_PUBLISHED = "custom:agent-installer-published"
AUDIT_INSTALLER_UNPUBLISHED = "custom:agent-installer-unpublished"

_now = time.time  # tests replace it
_islink = os.path.islink
_lstat = os.lstat
_fstat = os.fstat
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)  # 0 on Windows, where the symlink walk is the only guard
_BINARY = getattr(os, "O_BINARY", 0)


def _cache():
    from django.core.cache import cache

    return cache


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def grant_key(token: str) -> str:
    return GRANT_PREFIX + _sha(token)


def slot_key(module_id: str, agent_id: str, path: str) -> str:
    return SLOT_PREFIX + _sha(f"{module_id}\0{agent_id}\0{path}")


def _verified_module_id() -> str | None:
    """The verified calling module id, from the call stack and never from an argument; None for Core and for anything unverifiable.
    Every frame of this file is skipped, so this may be called from any depth of the provider."""
    from .caller_identity import calling_module_for_core_provider

    try:
        identity = calling_module_for_core_provider(provider_file=__file__)
    except Exception:
        return None
    if identity is None or not isinstance(identity.module_id, str) or not MODULE_ID_PATTERN.fullmatch(identity.module_id):
        return None
    if ".." in identity.module_id:
        return None
    return identity.module_id


def _invalid(reason: str) -> dict:
    return {"outcome": "invalid", "url": None, "path": None, "expires": None, "expires_in": None, "reason": reason}


def _unavailable(reason: str) -> dict:
    return {"outcome": "unavailable", "url": None, "path": None, "expires": None, "expires_in": None, "reason": reason}


def _denied() -> dict:
    return {"outcome": "denied", "url": None, "path": None, "expires": None, "expires_in": None, "reason": None}


# ------------------------------------------------------------------------------------------------ the file
def _norm(path: str) -> str:
    return os.path.normcase(path)


def _syntax_reason(path) -> str | None:
    """bad_path when the path is not a plain absolute path with no '..', no NUL and no odd separators."""
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_CHARS or "\0" in path:
        return "bad_path"
    if not os.path.isabs(path) or any(part == ".." for part in re.split(r"[\\/]", path)):
        return "bad_path"
    if _norm(os.path.normpath(path)) != _norm(path):
        return "bad_path"
    return None


def _roots(module_id: str) -> list[tuple[str, str]]:
    """(real path, case-normalised real path) of the two folders a module may share files from: its installed plugin folder and
    <TEC_TAC_STATE_ROOT>/<module id>/. An empty list when the module is not an installed, non-legacy extension."""
    from . import registry
    from .config import load_layout

    plugin = next((p for p in registry.discover_plugins() if p.plugin_id == module_id), None)
    if plugin is None or plugin.plugin_type != "extension" or plugin.legacy:
        return []
    folders = [str(plugin.root)]
    state_root = (load_layout().get("TEC_TAC_STATE_ROOT") or "/var/lib/tec-tac").strip()
    if state_root:
        folders.append(os.path.join(state_root, module_id))
    roots = []
    for folder in folders:
        real = os.path.realpath(folder)
        roots.append((real, _norm(real)))
    return roots


def _inside(norm_path: str, norm_root: str) -> bool:
    return norm_path.startswith(norm_root.rstrip(os.sep) + os.sep)


def check_path(module_id: str, path) -> tuple[str | None, str | None]:
    """(reason, real_root). Syntax, root, symlink and shape checks of a path as given. No file is opened and nothing is hashed here."""
    reason = _syntax_reason(path)
    if reason:
        return reason, None
    roots = _roots(module_id)
    norm_path = _norm(path)
    root = next((r for r in roots if _inside(norm_path, r[1])), None)
    if root is None:
        return "outside_module_folder", None
    current = root[0]
    for part in [p for p in re.split(r"[\\/]", path[len(root[0]):]) if p]:
        current = os.path.join(current, part)
        if _islink(current):
            return "symlink_refused", None
    if _norm(os.path.realpath(path)) != norm_path:
        return "symlink_refused", None
    try:
        info = _lstat(path)
    except OSError:
        return "not_a_file", None
    if not stat.S_ISREG(info.st_mode) or info.st_size < 1:
        return "not_a_file", None
    if info.st_size > MAX_FILE_BYTES:
        return "too_large", None
    return None, root[0]


def open_verified(module_id: str, path: str, sha256: str, expected_size: int | None = None, trusted_mtime_ns: int | None = None):
    """Open a granted file for hashing and serving: (file object, size, None) or (None, 0, reason).

    The path is checked again, the file is opened with O_NOFOLLOW, and the SHA-256 is computed through that same descriptor. The file
    object that is returned is that descriptor, rewound, so what is sent is what was hashed. A file problem is a reason code; an
    unexpected OS error (for example no free descriptors) is raised, so the route can answer 503 and keep the grant.

    ``trusted_mtime_ns`` (1.18.40, public installer only): when it is given and the descriptor's size equals ``expected_size`` and its modified
    time equals it, the read pass is skipped; the published hash was computed at publish from this same file. Any difference runs the full
    re-hash as before. A file whose size or modified time moved while it was being read is a hash_mismatch, so the modified time that a
    caller reads from the returned handle belongs to the bytes that were hashed."""
    reason, _root = check_path(module_id, path)
    if reason:
        return None, 0, reason
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _BINARY)
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ELOOP, errno.ENOTDIR, errno.EISDIR):
            return None, 0, "not_a_file"
        raise
    try:
        info = _fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1:
            os.close(fd)
            return None, 0, "not_a_file"
        if info.st_size > MAX_FILE_BYTES:
            os.close(fd)
            return None, 0, "too_large"
        if expected_size is not None and info.st_size != expected_size:
            os.close(fd)
            return None, 0, "hash_mismatch"
        trusted = (trusted_mtime_ns is not None and expected_size is not None and info.st_size == expected_size
                   and int(info.st_mtime_ns) == trusted_mtime_ns)
        if not trusted:
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(fd, CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FILE_BYTES:
                    os.close(fd)
                    return None, 0, "too_large"
                digest.update(chunk)
            if total != info.st_size or not hmac.compare_digest(digest.hexdigest().encode("ascii"), sha256.encode("ascii")):
                os.close(fd)
                return None, 0, "hash_mismatch"
            after = _fstat(fd)
            if after.st_size != info.st_size or after.st_mtime_ns != info.st_mtime_ns:
                os.close(fd)
                return None, 0, "hash_mismatch"
        os.lseek(fd, 0, os.SEEK_SET)
        handle = os.fdopen(fd, "rb")
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return handle, int(info.st_size), None


def safe_file_name(path: str) -> str:
    """The base name for Content-Disposition and for the audit row: letters, digits, dot, dash and underscore only."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(path.replace("\\", "/")))[:100].strip(".")
    return name or "download.bin"


# ------------------------------------------------------------------------------------------------ audit
def _audit(action: str, *, agent_id, message: str, metadata: dict, strict: bool, actor: str = "service", refusal: bool = False) -> None:
    """One Core audit row. strict raises when the row cannot be written. Never holds a token, a link or a full path."""
    from . import audit as audit_core

    audit_core._record_agent_download(action=action, agent_id=agent_id, message=message, metadata=metadata, strict=strict, actor=actor, refusal=refusal)


def record_served(grant: dict, agent_id: str, ip: str) -> None:
    """The strict row written BEFORE the first byte: the download started (sendfile gives no completion). Raises when it cannot be written."""
    _audit(AUDIT_SERVED, agent_id=agent_id, actor="device", strict=True, message="Agent file download started.", metadata={
        "granting_module": grant["module_id"], "file": grant["name"], "size": grant["size"], "sha256": grant["sha256"], "ip": ip,
    })


def record_refusal(reason: str, agent_id, ip: str) -> None:
    """One non-strict row for an identity refusal, behind the endpoint transport's refusal budget. Never raises."""
    try:
        from . import endpoint_transport as et

        if not et.refusal_row_allowed():
            return
        safe_agent = agent_id if isinstance(agent_id, str) and AGENT_ID_PATTERN.fullmatch(agent_id) else None
        _audit(AUDIT_REFUSED, agent_id=safe_agent, actor="device" if safe_agent else "service", strict=False, refusal=True,
               message="Agent file download refused.", metadata={k: v for k, v in {"reason": reason, "ip": ip}.items() if v})
    except Exception:
        logger.warning("The agent download refusal row could not be written (%s).", reason)


# ------------------------------------------------------------------------------------------------ link host
def _link_host() -> str | None:
    """The first Django ALLOWED_HOSTS entry, as Tactical builds the agent's api host. None when it is empty, a wildcard or not a host."""
    from django.conf import settings

    try:
        hosts = list(getattr(settings, "ALLOWED_HOSTS", None) or [])
    except Exception:
        return None
    host = hosts[0] if hosts else None
    if not isinstance(host, str) or not HOST_PATTERN.fullmatch(host.strip()) or "*" in host or host.strip().startswith("."):
        return None
    return host.strip()


# ------------------------------------------------------------------------------------------------ grant and revoke
def grant_download(module_id, *, agent_id, path, sha256, ttl_seconds=DEFAULT_TTL_SECONDS) -> dict:
    """Grant one device one short link to one file of the calling module. See docs/agent-downloads.md.

    Returns {outcome: ok|denied|invalid|unavailable, url, path, expires, expires_in, reason}. Sync: call it from a Celery task or a
    request thread. The caller is verified from the call stack and must be ``module_id``; any other caller, Core and an unverifiable
    caller get denied. A second grant for the same device and file replaces the first."""
    caller = _verified_module_id()
    if caller is None or module_id != caller:
        return _denied()
    if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
        return _invalid("bad_agent_id")
    if not isinstance(sha256, str) or not SHA256_PATTERN.fullmatch(sha256):
        return _invalid("bad_sha256")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        return _invalid("bad_ttl")
    ttl = max(MIN_TTL_SECONDS, min(MAX_TTL_SECONDS, ttl_seconds))
    try:
        reason, _root = check_path(caller, path)
    except Exception:
        logger.warning("The agent download path could not be checked.", exc_info=True)
        return _unavailable("path_unavailable")
    if reason:
        return _invalid(reason)
    try:
        handle, size, reason = open_verified(caller, path, sha256)
    except OSError:
        logger.warning("The agent download file could not be read.", exc_info=True)
        return _unavailable("file_unavailable")
    if reason:
        return _invalid(reason)
    handle.close()
    host = _link_host()
    if host is None:
        return _unavailable("host_unavailable")

    token = secrets.token_urlsafe(32)
    new_key = grant_key(token)
    slot = slot_key(caller, agent_id, path)
    expires_at = _now() + ttl
    expires = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    value = {"module_id": caller, "agent_id": agent_id, "path": path, "sha256": sha256, "size": size, "name": safe_file_name(path),
             "expires_at": expires_at}
    cache = _cache()
    try:
        previous = cache.get(slot)
        cache.set(new_key, value, timeout=ttl)
        cache.set(slot, new_key, timeout=ttl)
    except Exception:
        logger.warning("The agent download grant could not be stored.", exc_info=True)
        _forget(cache, new_key)
        return _unavailable("cache_unavailable")
    try:
        _audit(AUDIT_GRANTED, agent_id=agent_id, strict=True, message="Agent file download granted.", metadata={
            "requested_by_module": caller, "file": value["name"], "size": size, "sha256": sha256, "ttl_seconds": ttl, "expires": expires,
            "replaced": previous is not None,
        })
    except Exception:
        logger.warning("The agent download audit row could not be written; the grant is withdrawn.")
        _forget(cache, new_key)
        try:
            if previous is not None:
                cache.set(slot, previous, timeout=ttl)
            else:
                cache.delete(slot)
        except Exception:
            logger.warning("The agent download slot could not be restored.", exc_info=True)
        return _unavailable("audit_unavailable")
    if isinstance(previous, str) and previous != new_key:
        _forget(cache, previous)
    return {"outcome": "ok", "url": f"https://{host}/api/tfd/agent-downloads/{token}/", "path": f"/api/tfd/agent-downloads/{token}/",
            "expires": expires, "expires_in": ttl, "reason": None}


def revoke_download(module_id, *, agent_id, path) -> dict:
    """Withdraw the calling module's own grant for one device and file. Returns {outcome: ok|denied|invalid|unavailable, revoked}.
    Only the module that granted can revoke (the slot key holds its verified id). A row is written only when something was revoked."""
    caller = _verified_module_id()
    if caller is None or module_id != caller:
        return {"outcome": "denied", "revoked": False}
    if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id) or _syntax_reason(path):
        return {"outcome": "invalid", "revoked": False}
    cache = _cache()
    slot = slot_key(caller, agent_id, path)
    try:
        key = cache.get(slot)
        if not isinstance(key, str) or not key.startswith(GRANT_PREFIX):
            return {"outcome": "ok", "revoked": False}
        value = cache.get(key)
        cache.delete(key)
        cache.delete(slot)
    except Exception:
        logger.warning("The agent download grant could not be revoked.", exc_info=True)
        return {"outcome": "unavailable", "revoked": False}
    try:
        _audit(AUDIT_REVOKED, agent_id=agent_id, strict=False, message="Agent file download revoked.", metadata={
            "requested_by_module": caller, "file": safe_file_name(path), "sha256": (value or {}).get("sha256"),
        })
    except Exception:
        logger.warning("The agent download revoke row could not be written.")
    return {"outcome": "ok", "revoked": True}


def _forget(cache, key: str) -> None:
    try:
        cache.delete(key)
    except Exception:
        logger.warning("An agent download grant could not be removed from the cache.", exc_info=True)


# ------------------------------------------------------------------------------------------------ serving helpers (agent_download_views.py)
def load_grant(token: str) -> dict | None:
    """The live grant of a link token, or None (unknown, malformed or expired). Raises when the cache is down: the route answers 503."""
    if not isinstance(token, str) or not LINK_TOKEN_PATTERN.fullmatch(token):
        return None
    value = _cache().get(grant_key(token))
    if not isinstance(value, dict) or float(value.get("expires_at") or 0) <= _now():
        return None
    return value


def drop_grant(token: str, grant: dict) -> None:
    """Remove a grant and its slot after a file problem. Never raises."""
    cache = _cache()
    _forget(cache, grant_key(token))
    try:
        slot = slot_key(grant["module_id"], grant["agent_id"], grant["path"])
        if cache.get(slot) == grant_key(token):
            cache.delete(slot)
    except Exception:
        logger.warning("An agent download slot could not be removed.", exc_info=True)


def acquire_slot(key: str = INFLIGHT_KEY, limit: int = MAX_INFLIGHT) -> bool:
    """Take one of the ``limit`` serving slots (a cache counter shared by every process). False when all are taken. Raises on a cache fault.

    ``key`` (1.18.39) names the counter: the default is the device download counter, INSTALLER_INFLIGHT_KEY is the public installer's own.
    ``limit`` (1.18.40) defaults to MAX_INFLIGHT (8); the installer route passes INSTALLER_MAX_INFLIGHT (2)."""
    cache = _cache()
    cache.add(key, 0, timeout=INFLIGHT_TTL_SECONDS)
    try:
        used = int(cache.incr(key))
    except ValueError:  # the counter expired between add and incr
        cache.add(key, 1, timeout=INFLIGHT_TTL_SECONDS)
        return True
    cache.touch(key, INFLIGHT_TTL_SECONDS)  # 1.18.38: activity renews the lifetime, so the counter never expires under a running download
    if used > limit:
        release_slot(key)
        return False
    return True


def release_slot(key: str = INFLIGHT_KEY) -> None:
    """Give a serving slot back. Never raises and never leaves the counter below zero."""
    try:
        cache = _cache()
        if int(cache.decr(key)) < 0:
            cache.set(key, 0, timeout=INFLIGHT_TTL_SECONDS)
        else:
            cache.touch(key, INFLIGHT_TTL_SECONDS)  # 1.18.38: the other downloads still running keep the counter alive
    except ValueError:
        pass  # the counter expired: it heals itself
    except Exception:
        logger.warning("The agent download slot could not be released.", exc_info=True)


# ------------------------------------------------------------------------------------------------ the public installer (1.18.39, AD-74)
class _StoreFault(Exception):
    """The installer row could not be read or written."""


class _AuditFault(Exception):
    """The strict installer audit row could not be written."""


def _installer_model():
    from .models import TecTacPublishedInstaller

    return TecTacPublishedInstaller


def _atomic():
    from django.db import transaction

    return transaction.atomic()


def _installer_audit(action: str, *, message: str, metadata: dict) -> None:
    from . import audit as audit_core

    audit_core._record_agent_installer(action=action, message=message, metadata=metadata, strict=True)


def _installer_caller(module_id) -> str | None:
    """The verified caller when it is the module_id argument AND an installer publisher; None for everyone else (Core, unverifiable, mismatch)."""
    caller = _verified_module_id()
    if caller is None or module_id != caller or caller not in INSTALLER_PUBLISHERS:
        return None
    return caller


def _installer_result(outcome: str, reason: str | None = None) -> dict:
    return {"outcome": outcome, "reason": reason}


def load_installer() -> dict | None:
    """The one published installer as {module_id, path, sha256, size, version, mtime_ns}, or None (mtime_ns is None for a row published by 1.18.39). Raises when the store cannot be read: the route answers 503."""
    row = _installer_model().objects.filter(slot=INSTALLER_SLOT).first()
    if row is None:
        return None
    return {"module_id": row.module_id, "path": row.path, "sha256": row.sha256, "size": int(row.size), "version": row.version,
            "mtime_ns": None if row.mtime_ns is None else int(row.mtime_ns)}


def installer_publisher_enabled(module_id: str) -> bool:
    """True when the publisher module is enabled (1.18.40). A module with no record is enabled by default; a corrupt state file is False (fail closed).
    Raises when the state cannot be read: the route answers 503. The installer row is never touched, so the file returns when the module is enabled again."""
    from . import module_state

    return bool(module_state.is_enabled(module_id, module_state.load_state()))


def publish_installer(module_id, *, path, sha256, version) -> dict:
    """Make one file of the calling module the public Endpoint Agent installer. See docs/agent-downloads.md.

    Returns {outcome: ok|denied|invalid|unavailable, reason}. The caller is verified from the call stack, must be ``module_id`` and must be
    one of INSTALLER_PUBLISHERS. Only one installer exists: a new publish replaces the old one. The store write and the strict audit row
    are one transaction, so no row means nothing is published."""
    caller = _installer_caller(module_id)
    if caller is None:
        return _installer_result("denied")
    if not isinstance(sha256, str) or not SHA256_PATTERN.fullmatch(sha256):
        return _installer_result("invalid", "bad_sha256")
    if not isinstance(version, str) or len(version) > INSTALLER_VERSION_MAX or not INSTALLER_VERSION_PATTERN.fullmatch(version):
        return _installer_result("invalid", "bad_version")
    reason = _syntax_reason(path)
    if reason:
        return _installer_result("invalid", reason)
    name = os.path.basename(path.replace("\\", "/"))
    if len(name) <= len(".msi") or not name.lower().endswith(".msi"):
        return _installer_result("invalid", "not_msi")
    try:
        reason, _root = check_path(caller, path)
    except Exception:
        logger.warning("The installer path could not be checked.", exc_info=True)
        return _installer_result("unavailable", "path_unavailable")
    if reason:
        return _installer_result("invalid", reason)
    try:
        handle, size, reason = open_verified(caller, path, sha256)
    except OSError:
        logger.warning("The installer file could not be read.", exc_info=True)
        return _installer_result("unavailable", "file_unavailable")
    if reason:
        return _installer_result("invalid", reason)
    try:
        mtime_ns = int(_fstat(handle.fileno()).st_mtime_ns)
    except OSError:
        logger.warning("The installer file could not be read.", exc_info=True)
        return _installer_result("unavailable", "file_unavailable")
    finally:
        handle.close()
    file_name = safe_file_name(path)
    try:
        with _atomic():
            try:
                model = _installer_model()
                current = model.objects.filter(slot=INSTALLER_SLOT).first()
                replaced_version = None if current is None else current.version
                model.objects.update_or_create(slot=INSTALLER_SLOT, defaults={
                    "module_id": caller, "path": path, "sha256": sha256, "size": size, "version": version, "mtime_ns": mtime_ns,
                })
            except Exception as exc:
                raise _StoreFault() from exc
            try:
                _installer_audit(AUDIT_INSTALLER_PUBLISHED, message="Agent installer published.", metadata={
                    "published_by_module": caller, "file": file_name, "size": size, "sha256": sha256, "version": version,
                    "replaced_version": replaced_version,
                })
            except Exception as exc:
                raise _AuditFault() from exc
    except _AuditFault:
        logger.warning("The installer audit row could not be written; the publish is rolled back.")
        return _installer_result("unavailable", "audit_unavailable")
    except Exception:
        logger.warning("The installer could not be stored.", exc_info=True)
        return _installer_result("unavailable", "store_unavailable")
    return _installer_result("ok")


def unpublish_installer(module_id) -> dict:
    """Withdraw the public installer when it is the calling module's own. Returns {outcome: ok|denied|unavailable, unpublished}.
    Nothing to remove (or a file another module published) is ok with unpublished False and writes no row."""
    caller = _installer_caller(module_id)
    if caller is None:
        return {"outcome": "denied", "unpublished": False}
    try:
        with _atomic():
            try:
                model = _installer_model()
                current = model.objects.filter(slot=INSTALLER_SLOT).first()
                if current is None or current.module_id != caller:
                    return {"outcome": "ok", "unpublished": False}
                version, sha256, size, path = current.version, current.sha256, int(current.size), current.path
                model.objects.filter(slot=INSTALLER_SLOT).delete()
            except Exception as exc:
                raise _StoreFault() from exc
            try:
                _installer_audit(AUDIT_INSTALLER_UNPUBLISHED, message="Agent installer unpublished.", metadata={
                    "unpublished_by_module": caller, "file": safe_file_name(path), "size": size, "sha256": sha256, "version": version,
                })
            except Exception as exc:
                raise _AuditFault() from exc
    except _AuditFault:
        logger.warning("The installer audit row could not be written; the installer stays published.")
        return {"outcome": "unavailable", "unpublished": False}
    except Exception:
        logger.warning("The installer could not be withdrawn.", exc_info=True)
        return {"outcome": "unavailable", "unpublished": False}
    return {"outcome": "ok", "unpublished": True}


# ------------------------------------------------------------------------------------------------ the capability
class AgentDownloadsProvider:
    """The capability provider. Every operation verifies the calling module from the call stack, never from ``module_id``."""

    def grant_download(self, *, module_id, agent_id, path, sha256, ttl_seconds=DEFAULT_TTL_SECONDS):
        return grant_download(module_id, agent_id=agent_id, path=path, sha256=sha256, ttl_seconds=ttl_seconds)

    def revoke_download(self, *, module_id, agent_id, path):
        return revoke_download(module_id, agent_id=agent_id, path=path)

    def publish_installer(self, *, module_id, path, sha256, version):
        return publish_installer(module_id, path=path, sha256=sha256, version=version)

    def unpublish_installer(self, *, module_id):
        return unpublish_installer(module_id)


_PROVIDER = AgentDownloadsProvider()


def agent_downloads_contract_metadata() -> dict[str, Any]:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["grant_download", "revoke_download", "publish_installer", "unpublish_installer"],
        "requires_framework": ">=1.18.37",
        "operation_versions": {
            "grant_download": {"added_in": "1.0.0", "requires_framework": ">=1.18.37"},
            "revoke_download": {"added_in": "1.0.0", "requires_framework": ">=1.18.37"},
            "publish_installer": {"added_in": "1.1.0", "requires_framework": ">=1.18.39"},
            "unpublish_installer": {"added_in": "1.1.0", "requires_framework": ">=1.18.39"},
        },
        "caller": "Any verified, enabled, non-legacy extension, for its own files only. Core verifies the caller from the call stack (core.caller_identity), never from the module_id argument, which must equal the verified id. Core itself, an unverifiable caller and any mismatch get outcome denied. No module id is named in Core.",
        "roots": "The file must lie, as given, inside the calling module's installed plugin folder or <TEC_TAC_STATE_ROOT>/<module id>/ (default /var/lib/tec-tac/<module id>/). No part of the path below that folder may be a symlink, and the path must be its own real path.",
        "limits": {"file_bytes": MAX_FILE_BYTES, "ttl_seconds": {"min": MIN_TTL_SECONDS, "default": DEFAULT_TTL_SECONDS, "max": MAX_TTL_SECONDS}, "downloads_in_flight": MAX_INFLIGHT},
        "operations_detail": {
            "grant_download": "grant_download(module_id, *, agent_id, path, sha256, ttl_seconds=600) -> {outcome: ok|denied|invalid|unavailable, url, path, expires, expires_in, reason}. Core checks the file, hashes it and refuses unless the SHA-256 matches. invalid reasons: bad_agent_id, bad_sha256, bad_ttl, bad_path, outside_module_folder, symlink_refused, not_a_file, too_large, hash_mismatch. unavailable reasons: cache_unavailable, host_unavailable, audit_unavailable, file_unavailable, path_unavailable. A second grant for the same device and file replaces the first. Sync: call it from a Celery task or a request thread.",
            "revoke_download": "revoke_download(module_id, *, agent_id, path) -> {outcome: ok|denied|invalid|unavailable, revoked}. Withdraws only the calling module's own grant for that device and file.",
            "publish_installer": "publish_installer(module_id, *, path, sha256, version) -> {outcome: ok|denied|invalid|unavailable, reason}. Added in 1.1.0 (needs framework >=1.18.39). Makes one .msi file of the calling module the public Endpoint Agent installer. Only a module in installer.publishers may call it (today endpoint-agent-management); the caller is verified from the call stack. invalid reasons: bad_sha256, bad_version, bad_path, not_msi, outside_module_folder, symlink_refused, not_a_file, too_large, hash_mismatch. unavailable reasons: store_unavailable, audit_unavailable, file_unavailable, path_unavailable. One installer exists: a new publish replaces the old one. A strict audit row (custom:agent-installer-published) is written in the same transaction as the store, so no row means nothing is published. Sync: call it from a Celery task or a request thread.",
            "unpublish_installer": "unpublish_installer(module_id) -> {outcome: ok|denied|unavailable, unpublished}. Added in 1.1.0 (needs framework >=1.18.39). Withdraws the public installer when it is the calling module's own; nothing to remove is ok, unpublished False, with no row. A strict row (custom:agent-installer-unpublished) is written in the same transaction.",
        },
        "installer": {
            "route": {"method": "GET", "path": INSTALLER_ROUTE_PATH, "authorization": "none: no sign-in, no code, no expiry"},
            "publishers": list(INSTALLER_PUBLISHERS),
            "limits": {"file_bytes": MAX_FILE_BYTES, "downloads_in_flight": MAX_INFLIGHT, "installer_in_flight": INSTALLER_MAX_INFLIGHT, "version_chars": INSTALLER_VERSION_MAX},
            "verification": "Core computes the SHA-256 once, at publish, and stores it with the file size and modified time. At every serve it re-checks the path and the descriptor it sends, and recomputes the SHA-256 only when the size or modified time differ from the published ones. Any mismatch, missing file, symlink, module that is disabled or module no longer installed answers 404 with an empty body. Never a redirect.",
            "audit": "Strict rows on publish and unpublish (module core, provenance agent-downloads, object type agent-installer; the file name, size, SHA-256 and version, never a full path). No row per anonymous download: the rate limit belongs to the web application firewall.",
            "errors": {"200": "the raw file", "403": "plain-text connection", "404": "nothing published, the file no longer matches, or the publisher module is disabled or no longer installed", "503": "both installer slots are busy, or a server fault (Retry-After 30)"},
        },
        "route": {"method": "GET", "path": ROUTE_PATH, "host": "the first Django ALLOWED_HOSTS entry, over HTTPS"},
        "identity": "The device sends Authorization: Token <Tactical agent token> and X-Agent-Id, checked exactly as the endpoint websocket checks them (AD-54 E5), and shares its failure counters. A leaked link alone serves nothing, and a link granted to one device never serves another.",
        "audit": "Strict Core rows (module core, provenance agent-downloads): custom:agent-download-granted before a link is returned, custom:agent-download-served before the first byte (the download started; it does not say it finished). Non-strict: custom:agent-download-revoked and custom:agent-download-refused (identity refusals only). Never the link token, the link or the full path.",
        "errors": {"200": "the raw file", "401": "identity refused", "403": "plain-text connection", "404": "unknown, expired or other device's link, or a changed file", "429": "too many failed checks (Retry-After 60)", "503": "busy or a server fault (Retry-After 30)"},
        "core_does_not": "Core does not know what the file means, keep a copy, redirect, resume or serve ranges, or choose which file a device gets.",
        "added_in": "1.0.0 (Core 1.18.37). Needs framework >=1.18.37. 1.1.0 (Core 1.18.39) adds publish_installer, unpublish_installer and the public installer route; needs framework >=1.18.39. Additive: nothing existing changed. Core 1.18.40 keeps 1.1.0: hash once at publish, 2 installer slots, no serve while the publisher is disabled.",
    }


def register_core_agent_downloads_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="A short, device-bound download link for a file a verified module owns (an agent installer), served by Core over HTTPS, and the one public Endpoint Agent installer address.",
        operations=("grant_download", "revoke_download", "publish_installer", "unpublish_installer"),
        metadata=agent_downloads_contract_metadata(),
    )

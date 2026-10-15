"""Tec-Tac module repository catalog and online package staging.

Repository indexes are metadata only. Downloaded packages are SHA-256 verified
and then passed into the existing Module Management v2 staging/install pipeline.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from datetime import datetime, time as dt_time, timezone
from pathlib import Path

from .safe_files import atomic_json
from .module_manager import MAX_PACKAGE_BYTES, STAGED_ROOT, _atomic_json, _load_stage
from .module_manager_v2 import (
    LicensingRequirementError,
    ModuleManagerV2Error,
    _check_runtime_requirements,
    installed_catalog_v2,
    stage_uploaded_artifact,
    discard_v2_stage,
    attach_source_provenance,
)
from .module_state import ModuleStateError, version_satisfies

REPOSITORY_ROOT = Path("/var/lib/tec-tac/module-manager/repositories")
CONFIG_FILE = REPOSITORY_ROOT / "repositories.json"
CACHE_ROOT = REPOSITORY_ROOT / "cache"
MAX_INDEX_BYTES = 2 * 1024 * 1024
REPO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
TRUST_LEVELS = {"official", "internal", "custom"}
MAX_SKIPPED_RECORDS = 100
MAX_SKIPPED_TEXT = 100
MAX_SKIPPED_REASON = 300
MAX_INFORMATIONAL_TEXT = 64
SKIPPED_REASON_FOR_OTHERS = "This entry was skipped. A module manager can see the reason."
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")

logger = logging.getLogger("tec_tac.module_repository")

# 1.17.42 (CQ121): the official repository is seeded once, disabled, and never rebuilt by code. The index path is an assumption until
# Johan confirms it (CQ125). An administrator edits, enables, disables or removes the entry through the repository routes.
DEFAULT_REPOSITORIES = (
    {
        "id": "tec-tac-official",
        "name": "Tec-Tac official modules (Tech Flow Dynamics)",
        "url": "https://lic-service.tec-tac.techxflow.net.za/modules/index.json",
        "trust": "official",
        "priority": 100,
        "enabled": False,
    },
)
DEFAULTS_SEEDED_KEY = "defaults_seeded"

# 1.17.42 (CQ122): the daily sync is a module-owned Scheduler action. Its owner tuple is the stable identity of the schedule.
SYNC_ACTION_ID = "tec-tac.module-repository-sync"
SYNC_OWNER_MODULE = "tec-tac"
SYNC_OWNER_KEY = "module-repository-sync"
SYNC_RUN_TIME = dt_time(3, 0)
SYNC_MISSED_GRACE_MINUTES = 360


class ModuleRepositoryError(RuntimeError):
    pass


class _RemoteAddressRefused(ModuleRepositoryError):
    """The SSRF guard refused an address. This fails the whole index; it is never a skipped entry (1.17.39)."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_config() -> dict:
    return {"schema": 1, "repositories": []}


def _atomic_repo_json(path: Path, payload: dict) -> None:
    atomic_json(path, payload, mode=0o660)


def load_repositories() -> dict:
    if not CONFIG_FILE.is_file():
        return _default_config()
    try:
        payload = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModuleRepositoryError(f"Repository configuration is unreadable: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("repositories", []), list):
        raise ModuleRepositoryError("Repository configuration has an invalid structure.")
    payload.setdefault("schema", 1)
    payload.setdefault("repositories", [])
    return payload


def _validated_port(parsed: urllib.parse.ParseResult, *, label: str) -> int | None:
    try:
        port = parsed.port
    except ValueError as exc:
        raise ModuleRepositoryError(f"{label} contains an invalid port.") from exc
    if port is not None and not (1 <= int(port) <= 65535):
        raise ModuleRepositoryError(f"{label} contains an invalid port.")
    return port


def _clean_url(value: str) -> str:
    url = str(value or "").strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        raise ModuleRepositoryError("Repository URL must be an absolute http:// or https:// URL.")
    _validated_port(parsed, label="Repository URL")
    if parsed.username or parsed.password:
        raise ModuleRepositoryError("Credentials must not be embedded in repository URLs.")
    return url


def _normalize_address(address: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _always_blocked_address(address: ipaddress._BaseAddress) -> bool:
    address = _normalize_address(address)
    return bool(
        address.is_loopback or address.is_link_local or address.is_multicast
        or address.is_reserved or address.is_unspecified
    )


def _private_address(address: ipaddress._BaseAddress) -> bool:
    address = _normalize_address(address)
    return bool(address.is_private or (isinstance(address, ipaddress.IPv4Address) and address in _CGNAT))


def _resolve_remote_url(value: str, *, trust: str = "custom") -> tuple[str, urllib.parse.ParseResult, tuple[ipaddress._BaseAddress, ...]]:
    url = _clean_url(value)
    parsed = urllib.parse.urlparse(url)
    host = str(parsed.hostname or "").strip().rstrip(".")
    if not host or host.lower() == "localhost":
        raise _RemoteAddressRefused("Repository URL resolves to a prohibited local address.")
    addresses = set()
    try:
        addresses.add(_normalize_address(ipaddress.ip_address(host)))
    except ValueError:
        try:
            for row in socket.getaddrinfo(host, _validated_port(parsed, label="Repository URL") or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM):
                addresses.add(_normalize_address(ipaddress.ip_address(row[4][0].split("%", 1)[0])))
        except (OSError, ValueError) as exc:
            raise ModuleRepositoryError("Repository hostname could not be resolved.") from exc
    if not addresses:
        raise ModuleRepositoryError("Repository hostname did not resolve to an address.")
    if any(_always_blocked_address(address) for address in addresses):
        raise _RemoteAddressRefused("Repository URL resolves to a prohibited local, link-local, or reserved address.")
    if trust != "internal" and any(_private_address(address) for address in addresses):
        raise _RemoteAddressRefused("Repository URL resolves to a private or carrier-grade NAT address. Mark an administrator-controlled LAN repository as trust=internal to permit private addressing.")
    return url, parsed, tuple(sorted(addresses, key=lambda value: (value.version, str(value))))


def _validate_remote_url(value: str, *, trust: str = "custom") -> str:
    return _resolve_remote_url(value, trust=trust)[0]


def _proxy_url_for(parsed: urllib.parse.ParseResult) -> str | None:
    host = str(parsed.hostname or "")
    if not host or urllib.request.proxy_bypass(host):
        return None
    proxy = str((urllib.request.getproxies() or {}).get(parsed.scheme) or "").strip()
    if not proxy:
        return None
    proxy_parsed = urllib.parse.urlparse(proxy if "://" in proxy else f"http://{proxy}")
    if proxy_parsed.scheme != "http" or not proxy_parsed.hostname:
        raise ModuleRepositoryError("Repository proxy must be an absolute http:// proxy URL.")
    _validated_port(proxy_parsed, label="Repository proxy URL")
    return urllib.parse.urlunparse(proxy_parsed)


def _authority(host: str, port: int, scheme: str) -> str:
    default = 443 if scheme == "https" else 80
    rendered = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return rendered if port == default else f"{rendered}:{port}"


def _proxy_authorization(parsed: urllib.parse.ParseResult) -> str | None:
    if parsed.username is None:
        return None
    username = urllib.parse.unquote(parsed.username)
    password = urllib.parse.unquote(parsed.password or "")
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _pinned_proxy_get(url: str, address: ipaddress._BaseAddress, proxy_url: str, *, maximum: int, timeout: int) -> tuple[int, str | None, bytes]:
    parsed = urllib.parse.urlparse(url)
    host = str(parsed.hostname or "")
    port = _validated_port(parsed, label="Repository URL") or (443 if parsed.scheme == "https" else 80)
    proxy = urllib.parse.urlparse(proxy_url)
    proxy_host = str(proxy.hostname or "")
    proxy_port = _validated_port(proxy, label="Repository proxy URL") or 80
    proxy_auth = _proxy_authorization(proxy)
    conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
    path = urllib.parse.urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
    target_authority = _authority(host, port, parsed.scheme)
    headers = {
        "User-Agent": "Tec-Tac-Module-Repository/1.8",
        "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.1",
        "Host": target_authority,
    }
    try:
        if parsed.scheme == "https":
            tunnel_headers = {"Host": target_authority}
            if proxy_auth:
                tunnel_headers["Proxy-Authorization"] = proxy_auth
            pinned_host = f"[{address}]" if address.version == 6 else str(address)
            conn.set_tunnel(pinned_host, port, headers=tunnel_headers)
            conn.connect()
            context = ssl.create_default_context()
            conn.sock = context.wrap_socket(conn.sock, server_hostname=host)
            conn.request("GET", path, headers=headers)
        else:
            if proxy_auth:
                headers["Proxy-Authorization"] = proxy_auth
            pinned_host = f"[{address}]" if address.version == 6 else str(address)
            pinned_url = urllib.parse.urlunparse((
                "http", f"{pinned_host}:{port}", parsed.path or "/", parsed.params, parsed.query, ""
            ))
            conn.request("GET", pinned_url, headers=headers)
        response = conn.getresponse()
        location = response.getheader("Location")
        body = _read_bounded(response, maximum)
        return int(response.status), location, body
    finally:
        conn.close()


def _pinned_get(url: str, address: ipaddress._BaseAddress, *, maximum: int, timeout: int) -> tuple[int, str | None, bytes]:
    parsed = urllib.parse.urlparse(url)
    host = str(parsed.hostname or "")
    port = _validated_port(parsed, label="Repository URL") or (443 if parsed.scheme == "https" else 80)
    raw = socket.create_connection((str(address), port), timeout=timeout)
    conn = None
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            wrapped = context.wrap_socket(raw, server_hostname=host)
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
            conn.sock = wrapped
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.sock = raw
        path = urllib.parse.urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
        conn.request("GET", path, headers={"User-Agent": "Tec-Tac-Module-Repository/1.8", "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.1"})
        response = conn.getresponse()
        location = response.getheader("Location")
        body = _read_bounded(response, maximum)
        return int(response.status), location, body
    finally:
        if conn is not None:
            conn.close()
        else:
            raw.close()


def _fetch(url: str, maximum: int, timeout: int = 12, *, trust: str = "custom") -> bytes:
    current = str(url)
    for redirect_count in range(6):
        safe_url, _, addresses = _resolve_remote_url(current, trust=trust)
        last_error = None
        result = None
        proxy_url = _proxy_url_for(urllib.parse.urlparse(safe_url))
        for address in addresses:
            try:
                if proxy_url:
                    result = _pinned_proxy_get(safe_url, address, proxy_url, maximum=maximum, timeout=timeout)
                else:
                    result = _pinned_get(safe_url, address, maximum=maximum, timeout=timeout)
                break
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                last_error = exc
        if result is None:
            raise ModuleRepositoryError("Repository request failed due to a network or TLS error.") from last_error
        status, location, body = result
        if status in {301, 302, 303, 307, 308}:
            if not location:
                raise ModuleRepositoryError(f"Repository request returned HTTP {status} without a redirect target.")
            if redirect_count >= 5:
                raise ModuleRepositoryError("Repository request exceeded the redirect limit.")
            current = urllib.parse.urljoin(safe_url, location)
            continue
        if status < 200 or status >= 300:
            raise ModuleRepositoryError(f"Repository request returned HTTP {status}.")
        return body
    raise ModuleRepositoryError("Repository request exceeded the redirect limit.")


def _clean_repo_id(value: str | None, name: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        raw = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "repo"
        raw = raw[:54] + "-" + uuid.uuid4().hex[:8]
    if not REPO_ID_RE.fullmatch(raw):
        raise ModuleRepositoryError("Repository id must be 2-64 lowercase letters, numbers, dashes or underscores.")
    return raw


def public_repository(record: dict) -> dict:
    result = dict(record)
    result.pop("auth_token", None)
    return result


def list_repositories() -> list[dict]:
    payload = load_repositories()
    return sorted((public_repository(item) for item in payload["repositories"]), key=lambda item: (int(item.get("priority", 100)), item.get("name", "")))


def upsert_repository(data: dict, repository_id: str | None = None) -> dict:
    if not isinstance(data, dict):
        raise ModuleRepositoryError("Repository payload must be an object.")
    config = load_repositories()
    repos = list(config["repositories"])
    current = next((item for item in repos if item.get("id") == repository_id), None) if repository_id else None
    name = str(data.get("name", current.get("name") if current else "") or "").strip()
    if not name:
        raise ModuleRepositoryError("Repository name is required.")
    rid = _clean_repo_id(repository_id or data.get("id"), name)
    if repository_id and rid != repository_id:
        raise ModuleRepositoryError("Repository id cannot be changed.")
    if not current and any(item.get("id") == rid for item in repos):
        raise ModuleRepositoryError(f"Repository {rid!r} already exists.")
    trust = str(data.get("trust", current.get("trust") if current else "custom") or "custom").strip().lower()
    if trust not in TRUST_LEVELS:
        raise ModuleRepositoryError("Repository trust must be official, internal, or custom.")
    url = _validate_remote_url(data.get("url", current.get("url") if current else ""), trust=trust)
    try:
        priority = int(data.get("priority", current.get("priority") if current else 100))
    except (TypeError, ValueError) as exc:
        raise ModuleRepositoryError("Repository priority must be an integer.") from exc
    if priority < 0 or priority > 10000:
        raise ModuleRepositoryError("Repository priority must be between 0 and 10000.")
    enabled = data.get("enabled", current.get("enabled") if current else True)
    if not isinstance(enabled, bool):
        raise ModuleRepositoryError("Repository enabled must be true or false.")
    record = {
        "id": rid,
        "name": name,
        "url": url,
        "enabled": enabled,
        "priority": priority,
        "trust": trust,
        "created_at": current.get("created_at") if current else _utcnow(),
        "updated_at": _utcnow(),
    }
    if current:
        repos = [record if item.get("id") == rid else item for item in repos]
    else:
        repos.append(record)
    config["repositories"] = repos
    _atomic_repo_json(CONFIG_FILE, config)
    return public_repository(record)


def delete_repository(repository_id: str) -> None:
    config = load_repositories()
    before = len(config["repositories"])
    config["repositories"] = [item for item in config["repositories"] if item.get("id") != repository_id]
    if len(config["repositories"]) == before:
        raise ModuleRepositoryError(f"Repository {repository_id!r} was not found.")
    _atomic_repo_json(CONFIG_FILE, config)
    (CACHE_ROOT / f"{repository_id}.json").unlink(missing_ok=True)


def _repo(repository_id: str) -> dict:
    for item in load_repositories()["repositories"]:
        if item.get("id") == repository_id:
            return item
    raise ModuleRepositoryError(f"Repository {repository_id!r} was not found.")


def _read_bounded(response, maximum: int) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, maximum - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise ModuleRepositoryError("Remote content exceeds the configured size limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_release(raw: dict, repo_url: str, *, trust: str = "custom") -> dict:
    if not isinstance(raw, dict):
        raise ModuleRepositoryError("Repository modules entries must be objects.")
    module_id = str(raw.get("id", "")).strip()
    version = str(raw.get("version", "")).strip()
    download = str(raw.get("download", "")).strip()
    sha256 = str(raw.get("sha256", "")).strip().lower()
    if not module_id or not version or not download:
        raise ModuleRepositoryError("Every repository module entry requires id, version and download.")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", module_id):
        raise ModuleRepositoryError(
            f"Repository module id is invalid: {module_id!r}. Use only letters, digits, '-' and '_' (a dot is not allowed)."
        )
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise ModuleRepositoryError(f"Repository module {module_id} {version} requires a valid SHA-256 digest.")
    # Validate semantic version and constraints using the same parser as Module Manager.
    try:
        version_satisfies(version, "*")
    except ModuleStateError as exc:
        raise ModuleRepositoryError(str(exc)) from exc
    dependencies = raw.get("dependencies") or {}
    optional = raw.get("optional_dependencies") or {}
    requires = raw.get("requires") or {}
    for label, mapping in (("dependencies", dependencies), ("optional_dependencies", optional), ("requires", requires)):
        if not isinstance(mapping, dict):
            raise ModuleRepositoryError(f"{module_id} {label} must be an object.")
        for _, constraint in mapping.items():
            try:
                version_satisfies("0.0.0", str(constraint or "*"))
            except ModuleStateError as exc:
                raise ModuleRepositoryError(str(exc)) from exc
    absolute = urllib.parse.urljoin(repo_url, download)
    _validate_remote_url(absolute, trust=trust)
    signature_ref = str(raw.get("signature") or "").strip()
    metadata_ref = str(raw.get("release_metadata") or raw.get("metadata") or "").strip()
    signature_url = urllib.parse.urljoin(repo_url, signature_ref) if signature_ref else None
    metadata_url = urllib.parse.urljoin(repo_url, metadata_ref) if metadata_ref else None
    if bool(signature_url) != bool(metadata_url):
        raise ModuleRepositoryError(f"Repository module {module_id} {version} must publish both signature and release_metadata together.")
    if signature_url:
        _validate_remote_url(signature_url, trust=trust)
        _validate_remote_url(metadata_url, trust=trust)
    return {
        "id": module_id,
        "name": str(raw.get("name") or module_id),
        "description": str(raw.get("description") or ""),
        "version": version,
        "download": download,
        "download_url": absolute,
        "sha256": sha256,
        "signature_url": signature_url,
        "release_metadata_url": metadata_url,
        "dependencies": {str(k): str(v) for k, v in dependencies.items()},
        "optional_dependencies": {str(k): str(v) for k, v in optional.items()},
        "requires": {str(k): str(v) for k, v in requires.items()},
        # Informational only (1.17.39): Core shows them and never acts on them.
        "channel": _informational_text(raw.get("channel")),
        "lifecycle": _informational_text(raw.get("lifecycle")),
        "recommended": raw.get("recommended") if isinstance(raw.get("recommended"), bool) else None,
        "downgrade_policy": _informational_text(raw.get("downgrade_policy")),
        "signing_environment": _informational_text(raw.get("signing_environment")),
    }


def _informational_text(value) -> str | None:
    # A bad value becomes null and never invalidates the entry (1.17.39).
    if not isinstance(value, str):
        return None
    return _CONTROL_CHARACTERS.sub("", value).strip()[:MAX_INFORMATIONAL_TEXT] or None


def _plain_text(value, limit: int) -> str | None:
    # Untrusted text from a remote index: control characters removed, length capped (1.17.39).
    if not isinstance(value, str):
        return None
    return _CONTROL_CHARACTERS.sub("", value)[:limit]


def _skipped_record(index: int, raw, reason: str) -> dict:
    fields = raw if isinstance(raw, dict) else {}
    return {
        "index": index,
        "id": _plain_text(fields.get("id"), MAX_SKIPPED_TEXT),
        "version": _plain_text(fields.get("version"), MAX_SKIPPED_TEXT),
        "reason": _plain_text(reason, MAX_SKIPPED_REASON) or "",
    }


def _accepted_releases(raw_modules: list, repo: dict) -> tuple[list[dict], list[dict]]:
    """Validate each index entry on its own (1.17.39). Returns the kept releases and every skipped record, in index order.

    An entry that fails validation is skipped and recorded. Both copies of a duplicate id and version are skipped, because
    neither can be trusted. A remote address refused by the SSRF guard still fails the whole index. An index whose entries
    are all invalid fails, so a broken publish cannot empty a good cache.
    """
    trust = repo.get("trust", "custom")
    accepted: list[tuple[int, dict]] = []
    skipped: list[dict] = []
    for index, item in enumerate(raw_modules):
        try:
            accepted.append((index, _validate_release(item, repo["url"], trust=trust)))
        except _RemoteAddressRefused:
            raise
        except (ModuleRepositoryError, ValueError) as exc:
            skipped.append(_skipped_record(index, item, str(exc)))
    copies = Counter((release["id"], release["version"]) for _, release in accepted)
    modules = []
    for index, release in accepted:
        if copies[(release["id"], release["version"])] > 1:
            skipped.append(_skipped_record(index, release, "duplicate"))
        else:
            modules.append(release)
    if raw_modules and not modules:
        raise ModuleRepositoryError(
            f"Every one of the {len(raw_modules)} entries in the repository index was invalid, so the index was not used. "
            "The previous catalog is kept."
        )
    skipped.sort(key=lambda record: record["index"])
    return modules, skipped


def _skipped_summary(payload: dict) -> tuple[int, list]:
    count = payload.get("skipped_count")
    records = payload.get("skipped")
    return (
        count if isinstance(count, int) and not isinstance(count, bool) else 0,
        records if isinstance(records, list) else [],
    )


def sync_repository(repository_id: str) -> dict:
    repo = _repo(repository_id)
    started = _utcnow()
    try:
        body = _fetch(repo["url"], MAX_INDEX_BYTES, trust=repo.get("trust", "custom"))
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict) or int(payload.get("schema", 0)) != 1:
            raise ModuleRepositoryError("Repository index must be a schema 1 JSON object.")
        raw_modules = payload.get("modules")
        if not isinstance(raw_modules, list):
            raise ModuleRepositoryError("Repository index modules must be an array.")
        modules, skipped = _accepted_releases(raw_modules, repo)
        cache = {
            "schema": 1,
            "repository_id": repository_id,
            "repository": payload.get("repository") if isinstance(payload.get("repository"), dict) else {},
            "synced_at": _utcnow(),
            "status": "ok",
            "error": None,
            "modules": modules,
            "skipped": skipped[:MAX_SKIPPED_RECORDS],
            "skipped_count": len(skipped),
        }
        CACHE_ROOT.mkdir(parents=True, exist_ok=True)
        _atomic_repo_json(CACHE_ROOT / f"{repository_id}.json", cache)
        sync = {
            "status": "ok",
            "synced_at": cache["synced_at"],
            "error": None,
            "module_count": len(modules),
            "skipped_count": len(skipped),
            "skipped": skipped[:MAX_SKIPPED_RECORDS],
        }
        return {**public_repository(repo), "sync": sync}
    except Exception as exc:
        cache_path = CACHE_ROOT / f"{repository_id}.json"
        existing = {}
        if cache_path.is_file():
            try:
                existing = json.loads(cache_path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        existing.update({"schema": 1, "repository_id": repository_id, "status": "error", "last_attempt_at": started, "error": str(exc)})
        CACHE_ROOT.mkdir(parents=True, exist_ok=True)
        _atomic_repo_json(cache_path, existing)
        raise ModuleRepositoryError(str(exc)) from exc


def repository_status(repository_id: str) -> dict:
    repo = _repo(repository_id)
    path = CACHE_ROOT / f"{repository_id}.json"
    sync = {"status": "never", "synced_at": None, "error": None, "module_count": 0, "skipped_count": 0, "skipped": []}
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            skipped_count, skipped = _skipped_summary(payload)
            sync = {
                "status": payload.get("status") or "unknown",
                "synced_at": payload.get("synced_at"),
                "last_attempt_at": payload.get("last_attempt_at"),
                "error": payload.get("error"),
                "module_count": len(payload.get("modules") or []),
                "skipped_count": skipped_count,
                "skipped": skipped,
            }
        except Exception as exc:
            sync = {"status": "error", "synced_at": None, "error": str(exc), "module_count": 0, "skipped_count": 0, "skipped": []}
    return {**public_repository(repo), "sync": sync}


def all_repository_status() -> list[dict]:
    return [repository_status(item["id"]) for item in list_repositories()]


def sync_all(enabled_only: bool = True) -> list[dict]:
    results = []
    for repo in list_repositories():
        if enabled_only and not repo.get("enabled", True):
            results.append({**repo, "sync": {"status": "disabled", "synced_at": None, "error": None, "module_count": 0, "skipped_count": 0, "skipped": []}})
            continue
        try:
            results.append(sync_repository(repo["id"]))
        except ModuleRepositoryError as exc:
            status = repository_status(repo["id"])
            status["sync"]["error"] = str(exc)
            results.append(status)
    return results


def _cached_modules(repo: dict) -> list[dict]:
    path = CACHE_ROOT / f"{repo['id']}.json"
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    result = []
    for item in payload.get("modules") or []:
        if isinstance(item, dict):
            result.append({**item, "repository_id": repo["id"], "repository_name": repo["name"], "repository_priority": repo["priority"], "repository_trust": repo["trust"]})
    return result


def _candidate_compatibility(candidate: dict, installed: dict[str, dict]) -> dict:
    runtime = _check_runtime_requirements(candidate.get("requires") or {})
    problems = [{"type": "runtime", **item} for item in runtime if not item.get("satisfied")]
    dependency_status = []
    for dep_id, constraint in (candidate.get("dependencies") or {}).items():
        dep = installed.get(dep_id)
        satisfied = bool(dep and version_satisfies(dep.get("extension_version") or "0.0.0", constraint))
        dependency_status.append({
            "id": dep_id,
            "constraint": constraint,
            "installed": bool(dep),
            "installed_version": dep.get("extension_version") if dep else None,
            "satisfied": satisfied,
        })
        if not satisfied:
            problems.append({"type": "dependency", "dependency": dep_id, "constraint": constraint, "installed_version": dep.get("extension_version") if dep else None})
    return {"compatible": not problems, "runtime_requirements": runtime, "dependency_status": dependency_status, "problems": problems}


_AVAILABILITY_MESSAGES = {
    "no_repository": "No module repository is set up. Add one under Repositories, then sync it.",
    "not_synced": "A module repository is set up but has not been synced yet. Sync it to see what is available.",
    "sync_failed": "Every module repository failed its last sync. Check the repository address, then sync again.",
    "empty": "The module repositories were synced, but they offer no modules.",
    "ready": "",
}


def _availability(repos: list[dict], offered_count: int, installed_only_count: int) -> dict:
    """What the Online catalog can honestly say about itself (1.17.41).

    A repository counts as synced when it has a cache from a successful sync, even if a later sync failed: the old modules stay offered.
    """
    statuses = [repository_status(repo["id"])["sync"] for repo in repos]
    synced = sum(1 for sync in statuses if sync.get("synced_at"))
    if not repos:
        state = "no_repository"
    elif not synced:
        state = "sync_failed" if all(sync.get("status") == "error" for sync in statuses) else "not_synced"
    elif not offered_count:
        state = "empty"
    else:
        state = "ready"
    return {
        "state": state,
        "enabled_repositories": len(repos),
        "synced_repositories": synced,
        "message": _AVAILABILITY_MESSAGES[state],
        "installed_only_count": installed_only_count,
    }


def online_catalog() -> dict:
    repos = [repo for repo in list_repositories() if repo.get("enabled", True)]
    installed_list = [item for item in installed_catalog_v2() if not item.get("legacy")]
    installed = {item["id"]: item for item in installed_list}
    releases = []
    for repo in repos:
        releases.extend(_cached_modules(repo))
    by_module: dict[str, list[dict]] = {}
    for release in releases:
        by_module.setdefault(release["id"], []).append(release)

    items = []
    # 1.17.41: modules[] holds only what an enabled repository offers. An installed module no repository offers goes to installed_only[].
    installed_only = [
        {
            "id": module_id,
            "name": item.get("name") or module_id,
            "installed_version": item.get("extension_version"),
            "installed_source": item.get("source") or None,
        }
        for module_id, item in sorted(installed.items()) if module_id not in by_module
    ]
    for module_id in sorted(by_module):
        current = installed.get(module_id)
        source = (current or {}).get("source") or {}
        choices = by_module.get(module_id, [])
        choices.sort(key=lambda item: (int(item.get("repository_priority", 100)), item.get("repository_id", ""), item.get("version", "")))
        source_repo = source.get("repository_id")
        pinned = [item for item in choices if item.get("repository_id") == source_repo] if source_repo else []
        pool = pinned or choices
        # Repository priority selects the source first. The highest semantic
        # version is then selected only inside that source. This prevents a
        # second repository at the same priority from silently winning by version.
        selected = None
        if pool:
            winning_repo = sorted(
                {item["repository_id"] for item in pool},
                key=lambda rid: min(
                    (int(item.get("repository_priority", 100)), rid)
                    for item in pool if item["repository_id"] == rid
                ),
            )[0]
            cohort = [item for item in pool if item["repository_id"] == winning_repo]
            for candidate in cohort:
                if selected is None or version_satisfies(candidate["version"], f">{selected['version']}"):
                    selected = candidate
        compatibility = _candidate_compatibility(selected, installed) if selected else None
        installed_version = current.get("extension_version") if current else None
        update_available = bool(selected and installed_version and version_satisfies(selected["version"], f">{installed_version}"))
        source_conflict = bool(source_repo and not pinned)
        items.append({
            "id": module_id,
            "name": (selected or current or {}).get("name") or module_id,
            "description": (selected or {}).get("description") or "",
            "installed": bool(current),
            "installed_version": installed_version,
            "installed_source": source or None,
            "latest_version": selected.get("version") if selected else None,
            "selected_repository_id": selected.get("repository_id") if selected else None,
            "selected_repository_name": selected.get("repository_name") if selected else None,
            "selected_repository_trust": selected.get("repository_trust") if selected else None,
            "update_available": update_available,
            "compatible": compatibility.get("compatible") if compatibility else None,
            "compatibility": compatibility,
            "source_conflict": source_conflict,
            "available_sources": sorted({item["repository_id"] for item in choices}),
            # Informational (1.17.39), taken from the selected release. Null when nothing is selected or the cache predates them.
            "channel": (selected or {}).get("channel"),
            "lifecycle": (selected or {}).get("lifecycle"),
            "recommended": (selected or {}).get("recommended"),
            "downgrade_policy": (selected or {}).get("downgrade_policy"),
            "signing_environment": (selected or {}).get("signing_environment"),
            "releases": choices,
        })
    return {
        "schema": 1,
        "modules": items,
        "count": len(items),
        "installed_only": installed_only,
        "availability": _availability(repos, len(items), len(installed_only)),
        "repositories": all_repository_status(),
    }


class _PathUpload:
    def __init__(self, path: Path, name: str):
        self.path = path
        self.name = name
        self.size = path.stat().st_size
    def chunks(self, chunk_size=64 * 1024):
        with self.path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                yield chunk


def stage_repository_package(repository_id: str, module_id: str, version: str | None = None, allow_source_change: bool = False) -> dict:
    repo = _repo(repository_id)
    if not repo.get("enabled", True):
        raise ModuleRepositoryError("Repository is disabled.")
    installed = {item["id"]: item for item in installed_catalog_v2() if not item.get("legacy")}
    current_source = (installed.get(module_id) or {}).get("source") or {}
    pinned_repo = current_source.get("repository_id")
    if pinned_repo and pinned_repo != repository_id and not allow_source_change:
        raise ModuleRepositoryError(
            f"Module {module_id} is pinned to repository {pinned_repo!r}. An explicit source change is required."
        )
    candidates = [item for item in _cached_modules(repo) if item.get("id") == module_id]
    if version:
        candidates = [item for item in candidates if item.get("version") == version]
    if not candidates:
        raise ModuleRepositoryError("Requested module/version is not present in the repository cache. Sync the repository first.")
    candidate = candidates[0]
    for item in candidates[1:]:
        if version_satisfies(item["version"], f">{candidate['version']}"):
            candidate = item
    data = _fetch(candidate["download_url"], MAX_PACKAGE_BYTES, trust=repo.get("trust", "custom"))
    digest = hashlib.sha256(data).hexdigest()
    if digest != candidate["sha256"]:
        raise ModuleRepositoryError(f"Package SHA-256 mismatch for {module_id} {candidate['version']}.")
    suffix = Path(urllib.parse.urlparse(candidate["download_url"]).path).name or f"{module_id}-{candidate['version']}.zip"
    try:
        with tempfile.TemporaryDirectory(prefix="tec-tac-online-module-") as tmp:
            package_path = Path(tmp) / suffix
            package_path.write_bytes(data)
            signature_upload = None
            metadata_upload = None
            if candidate.get("signature_url"):
                signature_data = _fetch(candidate["signature_url"], 1024 * 1024, trust=repo.get("trust", "custom"))
                signature_name = Path(urllib.parse.urlparse(candidate["signature_url"]).path).name or f"{suffix}.sig"
                signature_path = Path(tmp) / signature_name
                signature_path.write_bytes(signature_data)
                signature_upload = _PathUpload(signature_path, signature_name)
                metadata_data = _fetch(candidate["release_metadata_url"], 1024 * 1024, trust=repo.get("trust", "custom"))
                metadata_name = Path(urllib.parse.urlparse(candidate["release_metadata_url"]).path).name or f"{suffix}.release.json"
                metadata_path = Path(tmp) / metadata_name
                metadata_path.write_bytes(metadata_data)
                metadata_upload = _PathUpload(metadata_path, metadata_name)
            staged = stage_uploaded_artifact(_PathUpload(package_path, suffix), signature_upload=signature_upload, metadata_upload=metadata_upload)
        preview = staged.get("preview") or {}
        kind = str(staged.get("kind") or preview.get("kind") or "package")
        if kind == "bundle":
            child = next((
                item for item in (preview.get("packages") or [])
                if item.get("id") == module_id and item.get("extension_version") == candidate["version"]
            ), None)
            identity_matches = child is not None
        else:
            identity_matches = preview.get("id") == module_id and preview.get("extension_version") == candidate["version"]
        if not identity_matches:
            try:
                discard_v2_stage(staged["upload_id"])
            except Exception:
                pass
            raise ModuleRepositoryError(
                f"Downloaded artifact does not contain repository module {module_id} {candidate['version']}."
            )
    except (ModuleRepositoryError, LicensingRequirementError):
        raise
    except Exception as exc:
        raise ModuleRepositoryError(f"Downloaded package inspection failed: {exc}") from exc
    source = {
        "repository_id": repository_id,
        "repository_name": repo["name"],
        "repository_trust": repo["trust"],
        "package_sha256": digest,
        "repository_url": repo["url"],
        "artifact_kind": str(staged.get("kind") or "package"),
        "publisher_trust": staged.get("publisher_trust") or (staged.get("preview") or {}).get("publisher_trust"),
        "requested_module_id": module_id,
        "requested_version": candidate["version"],
        "version": candidate["version"],
        "staged_at": _utcnow(),
    }
    if staged.get("kind") == "bundle":
        source["bundle_id"] = (preview or {}).get("id")
        source["bundle_version"] = (preview or {}).get("version")
    attach_source_provenance(staged["upload_id"], source)
    staged["source"] = source
    return staged


# ---------------------------------------------------------------------------------------------- 1.17.42: default repository and daily sync


def seed_default_repositories() -> list[str]:
    """Seed each DEFAULT_REPOSITORIES entry once and return the ids this call seeded (1.17.42, CQ121). Called from the Scheduler tick.

    The top-level key ``defaults_seeded`` lists the ids already handled. An id on that list is never seeded again, so an entry an
    administrator removed stays removed, and an edited or disabled entry is never touched. An entry with the same id or the same
    URL as an existing one gets only the marker. The function never raises: an unreadable or unwritable configuration logs a
    warning and the next tick tries again.
    """
    try:
        config = load_repositories()
        marked = config.get(DEFAULTS_SEEDED_KEY)
        marked = [str(item) for item in marked] if isinstance(marked, list) else []
        repos = list(config["repositories"])
        seeded: list[str] = []
        changed = False
        for default in DEFAULT_REPOSITORIES:
            if default["id"] in marked:
                continue
            exists = any(item.get("id") == default["id"] or item.get("url") == default["url"] for item in repos)
            if not exists:
                # The same URL check as upsert_repository, so the seeded entry is no less valid than a manual one.
                url = _validate_remote_url(default["url"], trust=default["trust"])
                now = _utcnow()
                repos.append({
                    "id": default["id"],
                    "name": default["name"],
                    "url": url,
                    "enabled": default["enabled"],
                    "priority": default["priority"],
                    "trust": default["trust"],
                    "created_at": now,
                    "updated_at": now,
                })
                seeded.append(default["id"])
            marked.append(default["id"])
            changed = True
        if changed:
            config["repositories"] = repos
            config[DEFAULTS_SEEDED_KEY] = marked
            _atomic_repo_json(CONFIG_FILE, config)
        return seeded
    except Exception as exc:
        logger.warning("The default module repository was not seeded; the next tick tries again: %s", exc)
        return []


def run_scheduled_sync(context=None) -> dict:
    """The daily sync (1.17.42, CQ122). Called by the Scheduler action tec-tac.module-repository-sync.

    It runs sync_all over the enabled repositories and writes one count-only audit row. A failed repository never fails the run. When
    every enabled repository fails, the run raises SchedulerPermanentError, so the run history shows it. The audit row and the result
    hold counts only: no address and no error text from a remote index.
    """
    from .audit import record, service_audit_actor
    from .scheduler import SchedulerPermanentError

    tried = ok = failed = skipped_entries = 0
    for item in sync_all(enabled_only=True):
        sync = item.get("sync") or {}
        if sync.get("status") == "disabled":
            continue
        tried += 1
        # sync_all sets sync.error when a repository's sync raised, and leaves it empty on success.
        if sync.get("error"):
            failed += 1
        else:
            ok += 1
        skipped_entries += int(sync.get("skipped_count") or 0)
    counts = {"repositories": tried, "ok": ok, "failed": failed, "entries_skipped": skipped_entries}
    record(
        actor=service_audit_actor(module_id="core", service="module-repository", identity="daily-sync"),
        module_id="core",
        action="sync",
        object_type="module_repository",
        object_id=SYNC_OWNER_KEY,
        message="Daily module repository sync ran.",
        after=counts,
    )
    if tried and not ok:
        raise SchedulerPermanentError(f"Every enabled module repository failed its sync ({failed} of {tried}). The previous catalogs are kept.")
    return counts


def ensure_repository_sync_schedule() -> bool:
    """Create the daily sync schedule (03:00 server time, run on recovery within 6 hours) when no row holds its owner tuple (1.17.42,
    CQ122). Returns True when this call created it. An existing schedule is never re-saved, so an administrator's change to it survives,
    and a deleted row comes back on the next tick. The function never raises. Called from the Scheduler tick."""
    try:
        from django.conf import settings

        from .models import TecTacSchedule
        from .scheduler import get_owned_schedule, reconcile_schedule

        if get_owned_schedule(SYNC_OWNER_MODULE, SYNC_OWNER_KEY) is not None:
            return False
        reconcile_schedule(
            owner_module=SYNC_OWNER_MODULE,
            owner_key=SYNC_OWNER_KEY,
            action_id=SYNC_ACTION_ID,
            schedule_type=TecTacSchedule.ScheduleType.DAILY,
            name="Module repository sync (daily, 03:00)",
            run_time=SYNC_RUN_TIME,
            timezone_name=str(getattr(settings, "TIME_ZONE", "") or "UTC"),
            missed_policy=TecTacSchedule.MissedPolicy.RUN_ON_RECOVERY,
            missed_grace_minutes=SYNC_MISSED_GRACE_MINUTES,
            concurrency_policy=TecTacSchedule.ConcurrencyPolicy.SKIP,
            retry_count=0,
        )
        return True
    except Exception as exc:
        logger.warning("The daily module repository sync schedule was not created; the next tick tries again: %s", exc)
        return False


def sync_schedule_status() -> dict | None:
    """The daily sync as the Repositories page states it (1.17.42): enabled, time, timezone, next run, last run and last status.
    None when the schedule does not exist. The address of a repository is never part of it."""
    from .models import TecTacSchedule
    from .scheduler import get_owned_schedule

    owned = get_owned_schedule(SYNC_OWNER_MODULE, SYNC_OWNER_KEY)
    if owned is None:
        return None
    row = TecTacSchedule.objects.filter(
        owner_type=TecTacSchedule.OwnerType.MODULE, owner_module=SYNC_OWNER_MODULE, owner_key=SYNC_OWNER_KEY,
    ).first()
    return {
        "enabled": owned["enabled"],
        "time": row.run_time.strftime("%H:%M") if row is not None and row.run_time else None,
        "timezone": row.timezone if row is not None else None,
        "next_run_at": owned["next_run_at"],
        "last_run_at": owned["last_run_at"],
        "last_run_status": owned["last_run_status"],
    }

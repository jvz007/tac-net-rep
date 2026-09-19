"""Tec-Tac module repository catalog and online package staging.

Repository indexes are metadata only. Downloaded packages are SHA-256 verified
and then passed into the existing Module Management v2 staging/install pipeline.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .module_manager import MAX_PACKAGE_BYTES, STAGED_ROOT, _atomic_json, _load_stage
from .module_manager_v2 import (
    LicensingRequirementError,
    ModuleManagerV2Error,
    _check_runtime_requirements,
    installed_catalog_v2,
    stage_uploaded_artifact,
    discard_v2_stage,
)
from .module_state import ModuleStateError, version_satisfies

REPOSITORY_ROOT = Path("/var/lib/tec-tac/module-manager/repositories")
CONFIG_FILE = REPOSITORY_ROOT / "repositories.json"
CACHE_ROOT = REPOSITORY_ROOT / "cache"
MAX_INDEX_BYTES = 2 * 1024 * 1024
REPO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
TRUST_LEVELS = {"official", "internal", "custom"}


class ModuleRepositoryError(RuntimeError):
    pass


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_config() -> dict:
    return {"schema": 1, "repositories": []}


def _atomic_repo_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o660)
    os.replace(tmp, path)


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


def _clean_url(value: str) -> str:
    url = str(value or "").strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ModuleRepositoryError("Repository URL must be an absolute http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ModuleRepositoryError("Credentials must not be embedded in repository URLs.")
    return url


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
    url = _clean_url(data.get("url", current.get("url") if current else ""))
    trust = str(data.get("trust", current.get("trust") if current else "custom") or "custom").strip().lower()
    if trust not in TRUST_LEVELS:
        raise ModuleRepositoryError("Repository trust must be official, internal, or custom.")
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


def _fetch(url: str, maximum: int, timeout: int = 12) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "Tec-Tac-Module-Repository/1.7"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            _clean_url(response.geturl())
            status = getattr(response, "status", 200)
            if status < 200 or status >= 300:
                raise ModuleRepositoryError(f"Repository request returned HTTP {status}.")
            return _read_bounded(response, maximum)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ModuleRepositoryError(f"Repository request failed: {exc}") from exc


def _validate_release(raw: dict, repo_url: str) -> dict:
    if not isinstance(raw, dict):
        raise ModuleRepositoryError("Repository modules entries must be objects.")
    module_id = str(raw.get("id", "")).strip()
    version = str(raw.get("version", "")).strip()
    download = str(raw.get("download", "")).strip()
    sha256 = str(raw.get("sha256", "")).strip().lower()
    if not module_id or not version or not download:
        raise ModuleRepositoryError("Every repository module entry requires id, version and download.")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", module_id):
        raise ModuleRepositoryError(f"Repository module id is invalid: {module_id!r}.")
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
    _clean_url(absolute)
    return {
        "id": module_id,
        "name": str(raw.get("name") or module_id),
        "description": str(raw.get("description") or ""),
        "version": version,
        "download": download,
        "download_url": absolute,
        "sha256": sha256,
        "dependencies": {str(k): str(v) for k, v in dependencies.items()},
        "optional_dependencies": {str(k): str(v) for k, v in optional.items()},
        "requires": {str(k): str(v) for k, v in requires.items()},
    }


def sync_repository(repository_id: str) -> dict:
    repo = _repo(repository_id)
    started = _utcnow()
    try:
        body = _fetch(repo["url"], MAX_INDEX_BYTES)
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict) or int(payload.get("schema", 0)) != 1:
            raise ModuleRepositoryError("Repository index must be a schema 1 JSON object.")
        raw_modules = payload.get("modules")
        if not isinstance(raw_modules, list):
            raise ModuleRepositoryError("Repository index modules must be an array.")
        modules = [_validate_release(item, repo["url"]) for item in raw_modules]
        identities = [(item["id"], item["version"]) for item in modules]
        if len(identities) != len(set(identities)):
            raise ModuleRepositoryError("Repository index contains duplicate module id/version entries.")
        cache = {
            "schema": 1,
            "repository_id": repository_id,
            "repository": payload.get("repository") if isinstance(payload.get("repository"), dict) else {},
            "synced_at": _utcnow(),
            "status": "ok",
            "error": None,
            "modules": modules,
        }
        CACHE_ROOT.mkdir(parents=True, exist_ok=True)
        _atomic_repo_json(CACHE_ROOT / f"{repository_id}.json", cache)
        return {**public_repository(repo), "sync": {"status": "ok", "synced_at": cache["synced_at"], "error": None, "module_count": len(modules)}}
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
    sync = {"status": "never", "synced_at": None, "error": None, "module_count": 0}
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            sync = {
                "status": payload.get("status") or "unknown",
                "synced_at": payload.get("synced_at"),
                "last_attempt_at": payload.get("last_attempt_at"),
                "error": payload.get("error"),
                "module_count": len(payload.get("modules") or []),
            }
        except Exception as exc:
            sync = {"status": "error", "synced_at": None, "error": str(exc), "module_count": 0}
    return {**public_repository(repo), "sync": sync}


def all_repository_status() -> list[dict]:
    return [repository_status(item["id"]) for item in list_repositories()]


def sync_all(enabled_only: bool = True) -> list[dict]:
    results = []
    for repo in list_repositories():
        if enabled_only and not repo.get("enabled", True):
            results.append({**repo, "sync": {"status": "disabled", "synced_at": None, "error": None, "module_count": 0}})
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
    for module_id in sorted(set(by_module) | set(installed)):
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
            "releases": choices,
        })
    return {"schema": 1, "modules": items, "count": len(items), "repositories": all_repository_status()}


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
    data = _fetch(candidate["download_url"], MAX_PACKAGE_BYTES)
    digest = hashlib.sha256(data).hexdigest()
    if digest != candidate["sha256"]:
        raise ModuleRepositoryError(f"Package SHA-256 mismatch for {module_id} {candidate['version']}.")
    suffix = Path(urllib.parse.urlparse(candidate["download_url"]).path).name or f"{module_id}-{candidate['version']}.zip"
    try:
        with tempfile.TemporaryDirectory(prefix="tec-tac-online-module-") as tmp:
            package_path = Path(tmp) / suffix
            package_path.write_bytes(data)
            staged = stage_uploaded_artifact(_PathUpload(package_path, suffix))
        preview = staged.get("preview") or {}
        if staged.get("kind") == "bundle" or preview.get("id") != module_id or preview.get("extension_version") != candidate["version"]:
            try:
                discard_v2_stage(staged["upload_id"])
            except Exception:
                pass
            raise ModuleRepositoryError(
                f"Downloaded package identity does not match repository metadata for {module_id} {candidate['version']}."
            )
    except (ModuleRepositoryError, LicensingRequirementError):
        raise
    except Exception as exc:
        raise ModuleRepositoryError(f"Downloaded package inspection failed: {exc}") from exc
    meta = _load_stage(staged["upload_id"])
    source = {
        "repository_id": repository_id,
        "repository_name": repo["name"],
        "repository_trust": repo["trust"],
        "package_sha256": digest,
        "repository_url": repo["url"],
        "version": candidate["version"],
        "staged_at": _utcnow(),
    }
    meta["source_provenance"] = source
    _atomic_json(STAGED_ROOT / f"{staged['upload_id']}.json", meta)
    staged["source"] = source
    return staged

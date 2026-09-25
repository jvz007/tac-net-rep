"""Tec-Tac framework/UI system update discovery, staging, and job dispatch.

The Django process only performs unprivileged discovery/download/inspection work.
Privileged replacement, backup, verification, and rollback are delegated to the
root-owned helper installed outside /opt/tec-tac so it survives self-updates.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from .trusted_publishers import PublisherTrustError, verify_release_manifest_signature, verify_release_tree
from .trust_policy import TrustPolicyError, acceptance as trust_acceptance, get_policy as get_trust_policy, require_accepted as require_trust_accepted

STATE_ROOT = Path("/var/lib/tec-tac/system-updates")
CACHE_ROOT = STATE_ROOT / "cache"
RELEASE_CACHE = CACHE_ROOT / "release-cache.json"
RELEASE_CACHE_TTL = timedelta(hours=24)
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


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o660)
    os.replace(tmp, path)


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
    if path.is_file():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_json(url: str) -> object:
    request = urllib.request.Request(url, headers=_github_headers())
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemUpdateError(f"GitHub request failed ({exc.code}): {body or exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise SystemUpdateError(f"GitHub request failed: {exc}") from exc


def _github_content_bytes(repo: str, path: str, ref: str) -> bytes | None:
    encoded_path = urllib.parse.quote(path, safe="/")
    encoded_ref = urllib.parse.quote(ref, safe="")
    url = f"https://api.github.com/repos/{repo}/contents/{encoded_path}?ref={encoded_ref}"
    request = urllib.request.Request(url, headers=_github_headers())
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemUpdateError(f"GitHub request failed ({exc.code}): {body or exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise SystemUpdateError(f"GitHub request failed: {exc}") from exc
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


def inspect_archive(archive: Path, *, source: dict | None = None) -> dict:
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


def _stage_bytes(reader, *, filename: str, source: dict, expected_component: str | None = None) -> dict:
    suffix = _allowed_suffix(filename)
    STAGED_ROOT.mkdir(parents=True, exist_ok=True)
    upload_id = str(uuid.uuid4())
    package_path = STAGED_ROOT / f"{upload_id}{suffix}"
    digest = hashlib.sha256()
    written = 0
    with package_path.open("wb") as handle:
        while True:
            chunk = reader(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_PACKAGE_BYTES:
                handle.close()
                package_path.unlink(missing_ok=True)
                raise SystemUpdateError(f"Package exceeds the {MAX_PACKAGE_BYTES // (1024 * 1024)} MiB limit.")
            digest.update(chunk)
            handle.write(chunk)
    if written <= 0:
        package_path.unlink(missing_ok=True)
        raise SystemUpdateError("Package is empty.")
    os.chmod(package_path, 0o640)
    try:
        preview = inspect_archive(package_path, source=source)
        if expected_component and preview["component"] != expected_component:
            raise SystemUpdateError(f"Repository returned {preview['component']} package while {expected_component} was requested.")
    except Exception:
        package_path.unlink(missing_ok=True)
        raise
    metadata = {
        "upload_id": upload_id,
        "filename": filename,
        "package_path": str(package_path),
        "sha256": digest.hexdigest(),
        "size": written,
        "created_at": _utcnow(),
        "preview": preview,
    }
    _atomic_json(STAGED_ROOT / f"{upload_id}.json", metadata)
    return {k: v for k, v in metadata.items() if k != "package_path"}


def stage_uploaded_package(upload) -> dict:
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

    return _stage_bytes(reader, filename=str(getattr(upload, "name", "package.zip")), source={"type": "offline"})


def _download_to_stage(url: str, *, filename: str, source: dict, component: str) -> dict:
    request = urllib.request.Request(url, headers=_github_headers())
    try:
        response = urllib.request.urlopen(request, timeout=45)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemUpdateError(f"Repository archive download failed ({exc.code}): {body or exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SystemUpdateError(f"Repository archive download failed: {exc}") from exc
    with response:
        return _stage_bytes(response.read, filename=filename, source=source, expected_component=component)


def _read_release_cache() -> dict:
    if not RELEASE_CACHE.is_file():
        return {"schema": 1, "components": {}}
    try:
        payload = json.loads(RELEASE_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema": 1, "components": {}}
    if not isinstance(payload, dict) or not isinstance(payload.get("components"), dict):
        return {"schema": 1, "components": {}}
    payload.setdefault("schema", 1)
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


def cached_online_status(component: str) -> dict:
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
        return cached
    return {
        "component": component,
        "repository": _repo_name(component),
        "installed_version": installed,
        "latest_release": None,
        "checked_at": None,
        "release_error": None,
        "cache": {"hit": False, "stale": True, "ttl_hours": 24},
    }


def online_status(component: str, *, force: bool = False) -> dict:
    if component not in COMPONENTS:
        raise SystemUpdateError("component must be framework or ui")
    repo = _repo_name(component)
    installed = _installed_version(component)
    cached = cached_online_status(component)
    checked = _parse_cached_at(cached.get("checked_at"))
    fresh = checked is not None and datetime.now(timezone.utc) - checked < RELEASE_CACHE_TTL
    if cached.get("latest_release") and fresh and not force:
        return cached

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
        trust_preview = _annotate_trust_acceptance(_release_signature_preview(component, repo, commit))
        checked_at = _utcnow()
        release_row = {
            "tag": tag,
            "name": release.get("name") or tag,
            "published_at": release.get("published_at"),
            "html_url": release.get("html_url"),
            "commit": commit,
            "release_trust": trust_preview,
        }
        cache_doc = _read_release_cache()
        cache_doc.setdefault("components", {})[component] = {
            "repository": repo,
            "checked_at": checked_at,
            "latest_release": release_row,
        }
        _write_release_cache(cache_doc)
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
    return payload


def list_branches(component: str) -> dict:
    if component not in COMPONENTS:
        raise SystemUpdateError("component must be framework or ui")
    repo = _repo_name(component)
    branches = _github_json(f"https://api.github.com/repos/{repo}/branches?per_page=100")
    if not isinstance(branches, list):
        raise SystemUpdateError("GitHub returned an unexpected branch response.")
    return {
        "component": component,
        "repository": repo,
        "branches": [
            {"name": str(item.get("name", "")), "sha": str((item.get("commit") or {}).get("sha", ""))}
            for item in branches if isinstance(item, dict) and item.get("name")
        ],
    }


def stage_online_package(component: str, source_type: str, ref: str | None = None) -> dict:
    if component not in COMPONENTS:
        raise SystemUpdateError("component must be framework or ui")
    repo = _repo_name(component)
    if source_type == "release":
        release = _github_json(f"https://api.github.com/repos/{repo}/releases/latest")
        if not isinstance(release, dict) or not release.get("tag_name"):
            raise SystemUpdateError("No latest GitHub release was returned for this repository.")
        tag = str(release["tag_name"])
        encoded_tag = urllib.parse.quote(tag, safe="")
        commit_info = _github_json(f"https://api.github.com/repos/{repo}/commits/{encoded_tag}")
        commit = str(commit_info.get("sha", "")) if isinstance(commit_info, dict) else ""
        if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            raise SystemUpdateError("Unable to resolve stable release to an exact commit SHA.")
        shaish = commit
        source = {"type": "release", "repository": repo, "ref": tag, "commit": commit}
    elif source_type == "branch":
        branch = (ref or "").strip()
        if not branch or len(branch) > 200:
            raise SystemUpdateError("A branch name is required.")
        encoded = urllib.parse.quote(branch, safe="")
        branch_info = _github_json(f"https://api.github.com/repos/{repo}/branches/{encoded}")
        if not isinstance(branch_info, dict) or not branch_info.get("commit"):
            raise SystemUpdateError("Unable to resolve branch commit.")
        commit = str((branch_info.get("commit") or {}).get("sha", ""))
        if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
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
    return meta


def discard_stage(upload_id: str) -> None:
    meta = _load_stage(upload_id)
    Path(meta["package_path"]).unlink(missing_ok=True)
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
    })
    try:
        _dispatch(job["id"])
    except Exception:
        (JOBS_ROOT / f"{job['id']}.json").unlink(missing_ok=True)
        raise
    return public_job(job)


def public_job(job: dict) -> dict:
    allowed = {
        "id", "status", "created_at", "started_at", "finished_at", "stage", "error", "error_type",
        "rollback", "action", "component", "version", "installed_version", "operation", "package_sha256",
        "package_filename", "source", "release_trust", "backup_path", "requested_by", "source_git",
    }
    result = {k: v for k, v in job.items() if k in allowed}
    log_path = LOGS_ROOT / f"{job.get('id')}.log"
    if log_path.is_file():
        try:
            result["log_tail"] = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-80:]
        except OSError:
            result["log_tail"] = []
    else:
        result["log_tail"] = []
    return result


def get_job(job_id: str) -> dict:
    try:
        uuid.UUID(str(job_id))
    except ValueError as exc:
        raise SystemUpdateError("Invalid job id.") from exc
    path = JOBS_ROOT / f"{job_id}.json"
    if not path.is_file():
        raise SystemUpdateError("System update job was not found.")
    try:
        job = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemUpdateError("System update job status is unreadable.") from exc
    return public_job(job)


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


def system_status() -> dict:
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
        "release_cache": {component: cached_online_status(component) for component in sorted(COMPONENTS)},
        "accepted_archives": [".zip", ".tar.gz", ".tgz"],
        "advanced_sources": {"branch_requires_unlock": True},
        "signed_release_policy": {component: {"minimum_version": _signed_release_min_version(component)} for component in sorted(COMPONENTS)},
        "update_trust_policy": get_trust_policy(),
        "history": _recent_history(),
    }

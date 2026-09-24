"""Trusted Tec-Tac publisher and signed-package verification.

The package signature covers the exact archive bytes. Release metadata is not
itself signed and is therefore treated only as selector/consistency metadata;
all identity and policy decisions are resolved from the local root-managed
trust store.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

TRUST_ROOT = Path(os.environ.get("TEC_TAC_TRUSTED_PUBLISHERS_ROOT", "/etc/tec-tac/trusted-publishers"))
CONFIG_FILE = Path(os.environ.get("TEC_TAC_CONFIG_FILE", "/opt/tec-tac/etc/tec-tac.conf"))
SUPPORTED_SCHEMA = 1
SUPPORTED_ALGORITHM = "Ed25519"
TREE_SCHEMA = 2
TREE_MANIFEST = "tec-tac-release.json"
TREE_SIGNATURE = "tec-tac-release.json.sig"
MAX_TREE_FILES = 20000
MAX_TREE_MANIFEST_BYTES = 8 * 1024 * 1024
logger = logging.getLogger(__name__)
_PUBLISHER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class PublisherTrustError(RuntimeError):
    def __init__(self, message: str, *, code: str = "publisher_trust_error"):
        super().__init__(message)
        self.code = code


def _server_environment() -> str:
    explicit = str(os.environ.get("TEC_TAC_ENVIRONMENT", "")).strip().lower()
    if explicit:
        return explicit
    if CONFIG_FILE.is_file():
        try:
            for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
                raw = line.strip()
                if not raw or raw.startswith("#") or "=" not in raw:
                    continue
                key, value = raw.split("=", 1)
                if key.strip() == "TEC_TAC_ENVIRONMENT":
                    value = value.strip().lower()
                    if value:
                        return value
        except OSError:
            pass
    return "production"


def _read_json(path: Path, label: str) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PublisherTrustError(f"{label} is missing: {path}", code="trust_material_missing") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise PublisherTrustError(f"{label} is unreadable: {exc}", code="trust_material_invalid") from exc
    if not isinstance(payload, dict):
        raise PublisherTrustError(f"{label} must contain a JSON object.", code="trust_material_invalid")
    return payload


def _safe_basename(value: str, label: str) -> str:
    value = str(value or "").strip()
    if not value or Path(value).name != value or "/" in value or "\\" in value:
        raise PublisherTrustError(f"{label} must be a plain filename.", code="metadata_invalid")
    return value


def _decode_public_key(data: bytes) -> Ed25519PublicKey:
    stripped = data.strip()
    if stripped.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_public_key(stripped)
        except Exception as exc:
            raise PublisherTrustError("Trusted publisher public key PEM is invalid.", code="public_key_invalid") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise PublisherTrustError("Trusted publisher key is not Ed25519.", code="public_key_invalid")
        return key

    text = stripped.decode("ascii", errors="ignore").strip()
    if text.lower().startswith("ed25519:"):
        text = text.split(":", 1)[1].strip()
    raw = None
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        raw = bytes.fromhex(text)
    else:
        try:
            raw = base64.b64decode(text, validate=True)
        except Exception:
            raw = stripped if len(stripped) == 32 else None
    if raw is None or len(raw) != 32:
        raise PublisherTrustError("Trusted publisher public key must encode exactly 32 Ed25519 bytes.", code="public_key_invalid")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise PublisherTrustError("Trusted publisher public key is invalid.", code="public_key_invalid") from exc


def _decode_signature(data: bytes) -> bytes:
    text = data.decode("ascii", errors="strict").strip()
    if not text.lower().startswith("ed25519:"):
        raise PublisherTrustError("Detached signature must use ed25519:<base64-signature> format.", code="signature_invalid")
    try:
        raw = base64.b64decode(text.split(":", 1)[1].strip(), validate=True)
    except Exception as exc:
        raise PublisherTrustError("Detached Ed25519 signature is not valid Base64.", code="signature_invalid") from exc
    if len(raw) != 64:
        raise PublisherTrustError("Detached Ed25519 signature must decode to 64 bytes.", code="signature_invalid")
    return raw


def _publisher_policy(publisher_id: str, key_id: str, trust_root: Path | None = None) -> tuple[dict, dict, Path]:
    if not _PUBLISHER_RE.fullmatch(publisher_id):
        raise PublisherTrustError("Release publisher_id is invalid.", code="publisher_invalid")
    if not _KEY_RE.fullmatch(key_id):
        raise PublisherTrustError("Release key_id is invalid.", code="key_invalid")
    root = (trust_root or TRUST_ROOT).resolve()
    publisher_dir = (root / publisher_id).resolve()
    try:
        publisher_dir.relative_to(root)
    except ValueError as exc:
        raise PublisherTrustError("Publisher trust path escapes the trust root.", code="publisher_invalid") from exc
    policy = _read_json(publisher_dir / "publisher.json", "Publisher policy")
    if int(policy.get("schema", 0) or 0) != SUPPORTED_SCHEMA:
        raise PublisherTrustError("Publisher policy schema is unsupported.", code="publisher_policy_invalid")
    if str(policy.get("publisher_id") or "") != publisher_id:
        raise PublisherTrustError("Release publisher_id does not match local publisher policy.", code="publisher_mismatch")
    if str(policy.get("status") or "").lower() != "trusted":
        raise PublisherTrustError("Publisher is not trusted by local policy.", code="publisher_untrusted")

    keys = policy.get("keys")
    key_record = None
    if isinstance(keys, list):
        for item in keys:
            if isinstance(item, dict) and str(item.get("key_id") or "") == key_id:
                key_record = dict(item)
                break
    elif str(policy.get("key_id") or "") == key_id:
        key_record = {
            "key_id": key_id,
            "status": policy.get("key_status", "active"),
            "algorithm": policy.get("algorithm", SUPPORTED_ALGORITHM),
            "public_key": policy.get("public_key", "public.key"),
        }
    if key_record is None:
        raise PublisherTrustError("Signing key is not present in local publisher policy.", code="key_unknown")
    if str(key_record.get("status") or "").lower() != "active":
        raise PublisherTrustError("Signing key is not active.", code="key_revoked")
    algorithm = str(key_record.get("algorithm") or SUPPORTED_ALGORITHM)
    if algorithm.lower() != SUPPORTED_ALGORITHM.lower():
        raise PublisherTrustError("Local signing key algorithm is not Ed25519.", code="algorithm_mismatch")
    key_name = _safe_basename(str(key_record.get("public_key_file") or key_record.get("public_key") or "public.key"), "public key filename")
    return policy, key_record, publisher_dir / key_name


def _permissions(policy: dict, key_record: dict) -> set[str]:
    publisher = policy.get("permissions") or []
    key_permissions = key_record.get("permissions")
    if not isinstance(publisher, list) or any(not isinstance(v, str) or not v.strip() for v in publisher):
        raise PublisherTrustError("Publisher permissions are invalid.", code="publisher_policy_invalid")
    result = {v.strip() for v in publisher}
    if key_permissions is not None:
        if not isinstance(key_permissions, list) or any(not isinstance(v, str) or not v.strip() for v in key_permissions):
            raise PublisherTrustError("Signing-key permissions are invalid.", code="publisher_policy_invalid")
        result &= {v.strip() for v in key_permissions}
    return result


def verify_release_files(
    *,
    package_path: Path,
    package_filename: str,
    signature_path: Path | None,
    signature_filename: str | None,
    metadata_path: Path | None,
    required_permissions: Iterable[str] = ("module.install",),
    require_signed: bool = False,
    trust_root: Path | None = None,
    server_environment: str | None = None,
) -> dict:
    """Verify a staged package against the local trusted-publisher policy.

    Unsigned packages are returned as ``state=unsigned`` unless ``require_signed``
    is true. If either sidecar is present, both are required and any validation
    failure is fail-closed.
    """
    package_path = Path(package_path)
    package_filename = _safe_basename(package_filename, "package filename")
    if signature_path is None and metadata_path is None:
        if require_signed:
            raise PublisherTrustError("This package requires a trusted publisher signature.", code="signature_required")
        return {
            "signed": False,
            "verified": False,
            "trusted": False,
            "state": "unsigned",
            "package_sha256": _sha256(package_path),
            "required_permissions": sorted(set(required_permissions)),
            "approved_permissions": [],
            "server_environment": (server_environment or _server_environment()).lower(),
        }
    if signature_path is None or metadata_path is None:
        raise PublisherTrustError("Signed packages require both detached signature and release metadata.", code="signature_material_incomplete")

    metadata = _read_json(Path(metadata_path), "Release metadata")
    if int(metadata.get("schema", 0) or 0) != SUPPORTED_SCHEMA:
        raise PublisherTrustError("Release metadata schema is unsupported.", code="metadata_invalid")
    algorithm = str(metadata.get("algorithm") or "")
    if algorithm.lower() != SUPPORTED_ALGORITHM.lower():
        raise PublisherTrustError("Release metadata algorithm must be Ed25519.", code="algorithm_mismatch")
    if _safe_basename(str(metadata.get("filename") or ""), "release filename") != package_filename:
        raise PublisherTrustError("Release metadata filename does not match the uploaded ZIP filename.", code="filename_mismatch")
    expected_sig = _safe_basename(str(metadata.get("signature") or ""), "release signature filename")
    actual_sig = _safe_basename(signature_filename or Path(signature_path).name, "signature filename")
    if expected_sig != actual_sig:
        raise PublisherTrustError("Release metadata signature filename does not match the uploaded signature filename.", code="filename_mismatch")

    digest = _sha256(package_path)
    expected_digest = str(metadata.get("sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest) or digest != expected_digest:
        raise PublisherTrustError("Package SHA-256 does not match release metadata.", code="sha256_mismatch")

    publisher_id = str(metadata.get("publisher_id") or "").strip()
    key_id = str(metadata.get("key_id") or "").strip()
    policy, key_record, public_key_path = _publisher_policy(publisher_id, key_id, trust_root=trust_root)

    effective_environment = str(server_environment or _server_environment()).strip().lower()
    policy_environment = str(policy.get("environment") or "production").strip().lower()
    metadata_environment = str(metadata.get("environment") or policy_environment).strip().lower()
    if policy_environment != effective_environment or metadata_environment != policy_environment:
        raise PublisherTrustError(
            f"Publisher environment mismatch: server={effective_environment}, publisher={policy_environment}, release={metadata_environment}.",
            code="environment_mismatch",
        )

    granted = _permissions(policy, key_record)
    required = {str(v).strip() for v in required_permissions if str(v).strip()}
    missing = sorted(required - granted)
    if missing:
        raise PublisherTrustError("Publisher policy does not grant required permission(s): " + ", ".join(missing), code="publisher_permission_denied")

    try:
        public_key_data = public_key_path.read_bytes()
    except OSError as exc:
        raise PublisherTrustError(f"Trusted publisher public key is unavailable: {exc}", code="trust_material_missing") from exc
    public_key = _decode_public_key(public_key_data)
    try:
        signature = _decode_signature(Path(signature_path).read_bytes())
    except OSError as exc:
        raise PublisherTrustError(f"Detached signature is unavailable: {exc}", code="signature_material_incomplete") from exc
    try:
        public_key.verify(signature, package_path.read_bytes())
    except InvalidSignature as exc:
        raise PublisherTrustError("Detached Ed25519 signature is invalid for the exact package bytes.", code="signature_invalid") from exc

    logger.info(
        "Tec-Tac publisher trust verified publisher=%s key=%s sha256=%s environment=%s permissions=%s",
        publisher_id, key_id, digest, effective_environment, ",".join(sorted(required)),
    )
    return {
        "signed": True,
        "verified": True,
        "trusted": True,
        "state": "verified",
        "publisher_id": publisher_id,
        "publisher_display_name": str(policy.get("display_name") or publisher_id),
        "key_id": key_id,
        "algorithm": SUPPORTED_ALGORITHM,
        "package_sha256": digest,
        "required_permissions": sorted(required),
        "approved_permissions": sorted(granted),
        "publisher_environment": policy_environment,
        "release_environment": metadata_environment,
        "server_environment": effective_environment,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def list_trusted_publishers(trust_root: Path | None = None) -> list[dict]:
    root = trust_root or TRUST_ROOT
    if not root.is_dir():
        return []
    rows = []
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if not child.is_dir():
            continue
        try:
            policy = _read_json(child / "publisher.json", "Publisher policy")
            rows.append({
                "publisher_id": str(policy.get("publisher_id") or child.name),
                "display_name": str(policy.get("display_name") or child.name),
                "status": str(policy.get("status") or "unknown"),
                "environment": str(policy.get("environment") or "production"),
                "permissions": list(policy.get("permissions") or []),
                "keys": list(policy.get("keys") or []),
            })
        except PublisherTrustError as exc:
            rows.append({"publisher_id": child.name, "status": "invalid", "error": str(exc), "code": exc.code})
    return rows



def _tree_relative_path(value: str) -> str:
    """Validate and normalize one schema-2 release-tree relative path."""
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value or value.startswith("/"):
        raise PublisherTrustError(f"Unsafe signed release path: {value!r}", code="tree_path_invalid")
    pure = PurePosixPath(value)
    parts = pure.parts
    if not parts or any(part in {"", ".", "..", ".git"} for part in parts):
        raise PublisherTrustError(f"Unsafe signed release path: {value!r}", code="tree_path_invalid")
    normalized = "/".join(parts)
    if normalized != value:
        raise PublisherTrustError(f"Signed release path is not canonical: {value!r}", code="tree_path_invalid")
    if len(parts) == 1 and normalized in {TREE_MANIFEST, TREE_SIGNATURE}:
        raise PublisherTrustError(f"Signing output cannot be listed as a release file: {value}", code="tree_path_invalid")
    return normalized


def _tree_digest_file(path: Path) -> tuple[int, str]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise PublisherTrustError(f"Unable to inspect signed release file {path}: {exc}", code="tree_file_unreadable") from exc
    if not stat.S_ISREG(info.st_mode):
        raise PublisherTrustError(f"Signed release entry must be a regular file: {path}", code="tree_special_file")
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
                size += len(block)
    except OSError as exc:
        raise PublisherTrustError(f"Unable to read signed release file {path}: {exc}", code="tree_file_unreadable") from exc
    if size != info.st_size:
        raise PublisherTrustError(f"Signed release file changed while hashing: {path}", code="tree_file_changed")
    return size, digest.hexdigest()


def _actual_release_tree(root: Path) -> dict[str, tuple[int, str]]:
    """Return the schema-2 release tree, excluding only root signing files and .git."""
    root = Path(root).resolve()
    found: dict[str, tuple[int, str]] = {}
    pending = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            entries = list(directory.iterdir())
        except OSError as exc:
            raise PublisherTrustError(f"Unable to enumerate signed release tree: {exc}", code="tree_file_unreadable") from exc
        for entry in entries:
            name = entry.name
            if not prefix and (name == ".git" or name in {TREE_MANIFEST, TREE_SIGNATURE}):
                continue
            rel = f"{prefix}/{name}" if prefix else name
            rel = _tree_relative_path(rel)
            try:
                info = entry.lstat()
            except OSError as exc:
                raise PublisherTrustError(f"Unable to inspect signed release entry {rel}: {exc}", code="tree_file_unreadable") from exc
            if stat.S_ISDIR(info.st_mode):
                pending.append((entry, rel))
            elif stat.S_ISREG(info.st_mode):
                found[rel] = _tree_digest_file(entry)
            else:
                raise PublisherTrustError(f"Signed release contains a link or special file: {rel}", code="tree_special_file")
            if len(found) > MAX_TREE_FILES:
                raise PublisherTrustError("Signed release contains too many files.", code="tree_file_count_invalid")
    return dict(sorted(found.items()))



def verify_release_manifest_signature(
    *,
    manifest_bytes: bytes,
    signature_bytes: bytes,
    expected_component: str | None = None,
    required_permissions: Iterable[str] = (),
    trust_root: Path | None = None,
    server_environment: str | None = None,
) -> dict:
    """Verify signed-tree manifest identity/signature without verifying tree bytes.

    This is intended for release discovery UI. It proves that the manifest was
    signed by a locally trusted publisher key, but it deliberately does not
    claim that the downloadable source tree matches the manifest. Full
    ``verify_release_tree`` verification remains mandatory after staging.
    """
    if len(manifest_bytes) > MAX_TREE_MANIFEST_BYTES:
        raise PublisherTrustError("Release tree manifest exceeds its size limit.", code="tree_signature_material_invalid")
    if len(signature_bytes) > 256:
        raise PublisherTrustError("Release tree signature exceeds its size limit.", code="tree_signature_material_invalid")
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise PublisherTrustError(f"Release tree manifest is invalid: {exc}", code="tree_manifest_invalid") from exc
    if not isinstance(manifest, dict):
        raise PublisherTrustError("Release tree manifest must contain a JSON object.", code="tree_manifest_invalid")
    allowed = {"schema", "component", "version", "publisher_id", "key_id", "algorithm", "files"}
    unknown = sorted(set(manifest) - allowed)
    missing_fields = sorted(allowed - set(manifest))
    if unknown or missing_fields:
        detail = []
        if unknown:
            detail.append("unknown fields: " + ", ".join(unknown))
        if missing_fields:
            detail.append("missing fields: " + ", ".join(missing_fields))
        raise PublisherTrustError("Release tree manifest fields are invalid (" + "; ".join(detail) + ").", code="tree_manifest_invalid")
    if manifest.get("schema") != TREE_SCHEMA:
        raise PublisherTrustError("Release tree manifest schema must be 2.", code="tree_manifest_invalid")
    algorithm = str(manifest.get("algorithm") or "")
    if algorithm.lower() != SUPPORTED_ALGORITHM.lower():
        raise PublisherTrustError("Release tree manifest algorithm must be Ed25519.", code="algorithm_mismatch")
    component = str(manifest.get("component") or "").strip()
    if component not in {"framework", "ui"}:
        raise PublisherTrustError("Release tree manifest component must be framework or ui.", code="tree_component_invalid")
    if expected_component and component != expected_component:
        raise PublisherTrustError(
            f"Signed release component mismatch: expected {expected_component}, manifest declares {component}.",
            code="tree_component_mismatch",
        )
    version = str(manifest.get("version") or "").strip()
    if not version or len(version) > 80 or not re.fullmatch(r"[A-Za-z0-9._-]+", version):
        raise PublisherTrustError("Release tree manifest version is invalid.", code="tree_version_invalid")
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_TREE_FILES:
        raise PublisherTrustError("Release tree file list is invalid.", code="tree_file_count_invalid")

    publisher_id = str(manifest.get("publisher_id") or "").strip()
    key_id = str(manifest.get("key_id") or "").strip()
    policy, key_record, public_key_path = _publisher_policy(publisher_id, key_id, trust_root=trust_root)
    effective_environment = str(server_environment or _server_environment()).strip().lower()
    policy_environment = str(policy.get("environment") or "production").strip().lower()
    if policy_environment != effective_environment:
        raise PublisherTrustError(
            f"Publisher environment mismatch: server={effective_environment}, publisher={policy_environment}.",
            code="environment_mismatch",
        )
    granted = _permissions(policy, key_record)
    required = {str(v).strip() for v in required_permissions if str(v).strip()}
    missing_permissions = sorted(required - granted)
    if missing_permissions:
        raise PublisherTrustError(
            "Publisher policy does not grant required permission(s): " + ", ".join(missing_permissions),
            code="publisher_permission_denied",
        )
    try:
        public_key = _decode_public_key(public_key_path.read_bytes())
    except OSError as exc:
        raise PublisherTrustError(f"Trusted publisher public key is unavailable: {exc}", code="trust_material_missing") from exc
    signature = _decode_signature(signature_bytes)
    try:
        public_key.verify(signature, manifest_bytes)
    except InvalidSignature as exc:
        raise PublisherTrustError("Release tree Ed25519 signature is invalid.", code="tree_signature_invalid") from exc

    return {
        "signed": True,
        "verified": False,
        "manifest_verified": True,
        "tree_verified": False,
        "trusted": True,
        "state": "signed",
        "schema": TREE_SCHEMA,
        "component": component,
        "version": version,
        "publisher_id": publisher_id,
        "publisher_display_name": str(policy.get("display_name") or publisher_id),
        "key_id": key_id,
        "algorithm": SUPPORTED_ALGORITHM,
        "file_count": len(files),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
        "server_environment": effective_environment,
        "details": "Trusted manifest signature verified. Full source-tree verification occurs after download and inspection.",
    }

def verify_release_tree(
    *,
    root: Path,
    expected_component: str | None = None,
    required_permissions: Iterable[str] = (),
    trust_root: Path | None = None,
    server_environment: str | None = None,
) -> dict:
    """Verify a publisher-tool v0.2.0 schema-2 signed source tree.

    The detached Ed25519 signature covers the exact manifest bytes. The signed
    manifest then covers every release file by canonical relative path, byte
    size, and SHA-256. Only root ``.git`` and the two root signing files are
    excluded from the tree comparison.
    """
    root = Path(root).resolve()
    manifest_path = root / TREE_MANIFEST
    signature_path = root / TREE_SIGNATURE
    manifest_exists = manifest_path.exists()
    signature_exists = signature_path.exists()
    if not manifest_exists and not signature_exists:
        return {
            "signed": False,
            "verified": False,
            "trusted": False,
            "state": "unsigned",
            "schema": None,
            "required_permissions": sorted({str(v).strip() for v in required_permissions if str(v).strip()}),
            "approved_permissions": [],
            "server_environment": str(server_environment or _server_environment()).strip().lower(),
        }
    if manifest_exists != signature_exists:
        raise PublisherTrustError(
            "Signed source releases require both tec-tac-release.json and tec-tac-release.json.sig.",
            code="tree_signature_material_incomplete",
        )
    for path, label, limit in (
        (manifest_path, "release tree manifest", MAX_TREE_MANIFEST_BYTES),
        (signature_path, "release tree signature", 256),
    ):
        try:
            info = path.lstat()
        except OSError as exc:
            raise PublisherTrustError(f"Unable to inspect {label}: {exc}", code="tree_signature_material_invalid") from exc
        if not stat.S_ISREG(info.st_mode):
            raise PublisherTrustError(f"{label.title()} must be a regular file.", code="tree_signature_material_invalid")
        if info.st_size > limit:
            raise PublisherTrustError(f"{label.title()} exceeds its size limit.", code="tree_signature_material_invalid")

    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise PublisherTrustError(f"Release tree manifest is invalid: {exc}", code="tree_manifest_invalid") from exc
    if not isinstance(manifest, dict):
        raise PublisherTrustError("Release tree manifest must contain a JSON object.", code="tree_manifest_invalid")
    allowed = {"schema", "component", "version", "publisher_id", "key_id", "algorithm", "files"}
    unknown = sorted(set(manifest) - allowed)
    missing_fields = sorted(allowed - set(manifest))
    if unknown or missing_fields:
        detail = []
        if unknown:
            detail.append("unknown fields: " + ", ".join(unknown))
        if missing_fields:
            detail.append("missing fields: " + ", ".join(missing_fields))
        raise PublisherTrustError("Release tree manifest fields are invalid (" + "; ".join(detail) + ").", code="tree_manifest_invalid")
    if manifest.get("schema") != TREE_SCHEMA:
        raise PublisherTrustError("Release tree manifest schema must be 2.", code="tree_manifest_invalid")
    algorithm = str(manifest.get("algorithm") or "")
    if algorithm.lower() != SUPPORTED_ALGORITHM.lower():
        raise PublisherTrustError("Release tree manifest algorithm must be Ed25519.", code="algorithm_mismatch")
    component = str(manifest.get("component") or "").strip()
    if component not in {"framework", "ui"}:
        raise PublisherTrustError("Release tree manifest component must be framework or ui.", code="tree_component_invalid")
    if expected_component and component != expected_component:
        raise PublisherTrustError(
            f"Signed release component mismatch: expected {expected_component}, manifest declares {component}.",
            code="tree_component_mismatch",
        )
    version = str(manifest.get("version") or "").strip()
    if not version or len(version) > 80 or not re.fullmatch(r"[A-Za-z0-9._-]+", version):
        raise PublisherTrustError("Release tree manifest version is invalid.", code="tree_version_invalid")
    try:
        version_file = (root / "VERSION").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PublisherTrustError("Signed release VERSION is missing.", code="tree_version_mismatch") from exc
    if version_file != version:
        raise PublisherTrustError(
            f"Signed release VERSION mismatch: manifest={version}, tree={version_file or 'missing'}.",
            code="tree_version_mismatch",
        )

    publisher_id = str(manifest.get("publisher_id") or "").strip()
    key_id = str(manifest.get("key_id") or "").strip()
    policy, key_record, public_key_path = _publisher_policy(publisher_id, key_id, trust_root=trust_root)
    effective_environment = str(server_environment or _server_environment()).strip().lower()
    policy_environment = str(policy.get("environment") or "production").strip().lower()
    if policy_environment != effective_environment:
        raise PublisherTrustError(
            f"Publisher environment mismatch: server={effective_environment}, publisher={policy_environment}.",
            code="environment_mismatch",
        )
    granted = _permissions(policy, key_record)
    required = {str(v).strip() for v in required_permissions if str(v).strip()}
    missing_permissions = sorted(required - granted)
    if missing_permissions:
        raise PublisherTrustError(
            "Publisher policy does not grant required permission(s): " + ", ".join(missing_permissions),
            code="publisher_permission_denied",
        )
    try:
        public_key = _decode_public_key(public_key_path.read_bytes())
    except OSError as exc:
        raise PublisherTrustError(f"Trusted publisher public key is unavailable: {exc}", code="trust_material_missing") from exc
    try:
        signature_bytes = signature_path.read_bytes()
        signature = _decode_signature(signature_bytes)
    except OSError as exc:
        raise PublisherTrustError(f"Release tree signature is unavailable: {exc}", code="tree_signature_material_incomplete") from exc
    try:
        public_key.verify(signature, manifest_bytes)
    except InvalidSignature as exc:
        raise PublisherTrustError("Release tree Ed25519 signature is invalid.", code="tree_signature_invalid") from exc

    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_TREE_FILES:
        raise PublisherTrustError("Release tree file list is invalid.", code="tree_file_count_invalid")
    declared: dict[str, tuple[int, str]] = {}
    previous_path = None
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise PublisherTrustError("Release tree file entry is invalid.", code="tree_manifest_invalid")
        rel = _tree_relative_path(entry.get("path"))
        if previous_path is not None and rel < previous_path:
            raise PublisherTrustError("Release tree file list must be sorted by path.", code="tree_manifest_invalid")
        previous_path = rel
        if rel in declared:
            raise PublisherTrustError(f"Duplicate signed release path: {rel}", code="tree_duplicate_path")
        size = entry.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise PublisherTrustError(f"Invalid signed byte size for {rel}.", code="tree_manifest_invalid")
        digest = str(entry.get("sha256") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PublisherTrustError(f"Invalid SHA-256 for signed release file {rel}.", code="tree_manifest_invalid")
        declared[rel] = (size, digest)

    actual = _actual_release_tree(root)
    if declared != actual:
        missing = sorted(set(declared) - set(actual))
        extra = sorted(set(actual) - set(declared))
        changed = sorted(path for path in set(declared) & set(actual) if declared[path] != actual[path])
        details = []
        if missing:
            details.append(f"missing={len(missing)}")
        if extra:
            details.append(f"extra={len(extra)}")
        if changed:
            details.append(f"changed={len(changed)}")
        raise PublisherTrustError(
            "Signed release tree does not match the manifest" + (" (" + ", ".join(details) + ")" if details else "") + ".",
            code="tree_mismatch",
        )

    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    signature_sha256 = hashlib.sha256(signature_bytes).hexdigest()
    logger.info(
        "Tec-Tac signed release tree verified component=%s version=%s publisher=%s key=%s files=%s manifest_sha256=%s environment=%s",
        component, version, publisher_id, key_id, len(actual), manifest_sha256, effective_environment,
    )
    return {
        "signed": True,
        "verified": True,
        "trusted": True,
        "state": "verified",
        "schema": TREE_SCHEMA,
        "component": component,
        "version": version,
        "publisher_id": publisher_id,
        "publisher_display_name": str(policy.get("display_name") or publisher_id),
        "key_id": key_id,
        "algorithm": SUPPORTED_ALGORITHM,
        "file_count": len(actual),
        "manifest_filename": TREE_MANIFEST,
        "signature_filename": TREE_SIGNATURE,
        "manifest_sha256": manifest_sha256,
        "signature_sha256": signature_sha256,
        "required_permissions": sorted(required),
        "approved_permissions": sorted(granted),
        "publisher_environment": policy_environment,
        "server_environment": effective_environment,
    }

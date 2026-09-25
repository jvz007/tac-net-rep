#!/usr/bin/env python3
"""Root-side Tec-Tac publisher verification.

This helper is deliberately independent of request/job trust metadata. It reads
only root-owned trust/configuration and verifies the bytes about to be executed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

CONFIG = Path('/opt/tec-tac/etc/tec-tac.conf')
TRUST_ROOT = Path('/etc/tec-tac/trusted-publishers')
POLICY_ROOT = Path('/etc/tec-tac/policy')
POLICY_FILE = POLICY_ROOT / 'update-trust-policy.json'
FRAMEWORK_ROOT = Path('/opt/tec-tac/framework')
LEVELS = ('unsigned', 'signed_development', 'signed_production', 'secure_signed')
LEVEL_RANK = {name: idx for idx, name in enumerate(LEVELS)}


def _config() -> dict[str, str]:
    values: dict[str, str] = {}
    if CONFIG.is_file():
        for raw in CONFIG.read_text(encoding='utf-8').splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
    return values


def _framework_root() -> Path:
    if FRAMEWORK_ROOT.is_dir():
        return FRAMEWORK_ROOT
    # Source-tree fallback is only for tests/development of this helper. The
    # installed helper under /usr/local/lib has no sibling framwork directory.
    candidate = Path(__file__).resolve().parents[1] / 'framwork'
    if candidate.is_dir():
        return candidate
    raise RuntimeError('root-owned Tec-Tac framework runtime is unavailable')


def _require_root_owned_nonwritable(path: Path, label: str) -> None:
    st = path.stat()
    if st.st_uid != 0 or (st.st_mode & 0o022):
        raise RuntimeError(f"{label} must be root-owned and not group/world writable: {path}")


def _imports():
    root = _framework_root().resolve()
    trust_module = root / "tec_tac" / "trusted_publishers.py"
    _require_root_owned_nonwritable(root, "Framework runtime root")
    _require_root_owned_nonwritable(root / "tec_tac", "Framework package root")
    _require_root_owned_nonwritable(trust_module, "Publisher verifier module")
    sys.path.insert(0, str(root))
    from tec_tac.trusted_publishers import (  # noqa: PLC0415
        PublisherTrustError, verify_release_files, verify_release_tree,
    )
    return PublisherTrustError, verify_release_files, verify_release_tree


def _environment(cfg: dict[str, str]) -> str:
    value = str(cfg.get('TEC_TAC_ENVIRONMENT') or 'production').strip().lower()
    if value not in {'production', 'development'}:
        raise RuntimeError('TEC_TAC_ENVIRONMENT in root-owned config must be production or development')
    return value


def _default_policy(environment: str) -> str:
    return 'signed_development' if environment == 'development' else 'signed_production'


def read_policy(cfg: dict[str, str] | None = None) -> dict:
    cfg = cfg or _config()
    environment = _environment(cfg)
    level = _default_policy(environment)
    updated_at = None
    updated_by = None
    if POLICY_FILE.is_file():
        payload = json.loads(POLICY_FILE.read_text(encoding='utf-8'))
        if not isinstance(payload, dict) or int(payload.get('schema', 0) or 0) != 1:
            raise RuntimeError('root trust policy schema is invalid')
        level = str(payload.get('minimum_level') or '').strip().lower()
        if level not in LEVEL_RANK:
            raise RuntimeError('root trust policy level is invalid')
        updated_at = payload.get('updated_at')
        updated_by = payload.get('updated_by')
    return {
        'schema': 1,
        'minimum_level': level,
        'environment': environment,
        'updated_at': updated_at,
        'updated_by': updated_by,
    }


def write_policy(level: str, *, updated_by: str = '', updated_at: str = '') -> dict:
    level = str(level or '').strip().lower()
    if level not in LEVEL_RANK:
        raise RuntimeError('invalid trust policy level')
    POLICY_ROOT.mkdir(parents=True, exist_ok=True)
    os.chown(POLICY_ROOT, 0, 0)
    os.chmod(POLICY_ROOT, 0o755)
    payload = {
        'schema': 1,
        'minimum_level': level,
        'updated_at': str(updated_at or '') or None,
        'updated_by': str(updated_by or '')[:150] or None,
    }
    tmp = POLICY_FILE.with_name(POLICY_FILE.name + '.tmp')
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    os.chown(tmp, 0, 0)
    os.chmod(tmp, 0o644)
    os.replace(tmp, POLICY_FILE)
    return read_policy()


def _classify(trust: dict) -> str:
    if not bool(trust.get('signed')):
        return 'unsigned'
    if not bool(trust.get('trusted')):
        raise RuntimeError('signed package is not trusted')
    env = str(trust.get('publisher_environment') or '').strip().lower()
    assurance = str(trust.get('assurance') or '').strip().lower().replace('-', '_')
    if assurance in {'secure', 'secure_signed', 'high_assurance'}:
        if env != 'production':
            raise RuntimeError('secure-signed package must use a production publisher')
        return 'secure_signed'
    if env == 'production':
        return 'signed_production'
    if env == 'development':
        return 'signed_development'
    raise RuntimeError('signed package environment is unsupported')


def _dev_override(cfg: dict[str, str], *, kind: str) -> bool:
    if _environment(cfg) != 'development':
        return False
    key = 'TEC_TAC_ALLOW_UNSIGNED_DEVELOPMENT_UPDATES' if kind == 'update' else 'TEC_TAC_ALLOW_UNSIGNED_DEVELOPMENT_PACKAGES'
    return str(cfg.get(key) or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def enforce_policy(trust: dict, *, kind: str) -> dict:
    cfg = _config()
    policy = read_policy(cfg)
    actual = _classify(trust)
    accepted = LEVEL_RANK[actual] >= LEVEL_RANK[policy['minimum_level']]
    override = False
    if not accepted and actual == 'unsigned' and _dev_override(cfg, kind=kind):
        accepted = True
        override = True
    if not accepted:
        raise RuntimeError(f"trust level {actual} is below root policy {policy['minimum_level']}")
    result = dict(trust)
    result['root_policy'] = {
        'minimum_level': policy['minimum_level'],
        'actual_level': actual,
        'accepted': True,
        'development_unsigned_override': override,
    }
    return result


def _safe_zip_name(name: str) -> PurePosixPath:
    p = PurePosixPath(str(name).replace('\\', '/'))
    if p.is_absolute() or '..' in p.parts or not p.parts:
        raise RuntimeError(f'unsafe ZIP path: {name!r}')
    return p


def _module_permissions_from_archive(path: Path) -> set[str]:
    """Derive signer permissions from package contents, never from a job file."""
    perms = {"module.install"}

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            for info in infos:
                _safe_zip_name(info.filename)
                mode = (info.external_attr >> 16) & 0xFFFF
                if mode and (mode & 0o170000) == 0o120000:
                    raise RuntimeError(f"module archive contains symlink: {info.filename}")
            module_manifests = [i for i in infos if PurePosixPath(i.filename).name == "tec_tac.json"]
            bundle_manifests = [i for i in infos if PurePosixPath(i.filename).name == "tec_tac_bundle.json"]
            if len(bundle_manifests) == 1:
                manifest = json.loads(zf.read(bundle_manifests[0]).decode("utf-8"))
                entries = manifest.get("packages") if isinstance(manifest, dict) else None
                if not isinstance(entries, list) or not entries:
                    raise RuntimeError("bundle manifest has no packages")
                base = PurePosixPath(bundle_manifests[0].filename).parent
                for entry in entries:
                    filename = entry if isinstance(entry, str) else (entry.get("file") if isinstance(entry, dict) else None)
                    if not filename:
                        raise RuntimeError("bundle package entry is invalid")
                    member = (base / str(filename)).as_posix()
                    try:
                        child_bytes = zf.read(member)
                    except KeyError as exc:
                        raise RuntimeError(f"bundle child package is missing: {filename}") from exc
                    suffix = ''.join(Path(str(filename)).suffixes) or '.zip'
                    with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
                        tmp.write(child_bytes); tmp.flush()
                        perms.update(_module_permissions_from_archive(Path(tmp.name)))
                return perms
            if len(bundle_manifests) > 1 or not module_manifests:
                raise RuntimeError("module archive must contain Tec-Tac module manifests, or one bundle manifest")
            parsed = []
            for item in module_manifests:
                payload = json.loads(zf.read(item).decode("utf-8"))
                if isinstance(payload, dict):
                    parsed.append(payload)
            extensions = [item for item in parsed if str(item.get("type") or "") == "extension"]
            if len(extensions) != 1:
                raise RuntimeError("module archive must contain exactly one extension manifest")
            manifest = extensions[0]
    elif tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as tf:
            manifests = []
            for member in tf.getmembers():
                rel = PurePosixPath(member.name.replace('\\', '/'))
                if rel.is_absolute() or '..' in rel.parts or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    raise RuntimeError(f"unsafe module archive member: {member.name}")
                if member.isfile() and rel.name == 'tec_tac.json':
                    handle = tf.extractfile(member)
                    if handle is None:
                        raise RuntimeError("module manifest is unreadable")
                    payload = json.loads(handle.read().decode('utf-8'))
                    if isinstance(payload, dict):
                        manifests.append(payload)
            extensions = [item for item in manifests if str(item.get("type") or "") == "extension"]
            if len(extensions) != 1:
                raise RuntimeError("module archive must contain exactly one extension manifest")
            manifest = extensions[0]
    else:
        raise RuntimeError('module package must be a ZIP or tar archive')

    if not isinstance(manifest, dict):
        raise RuntimeError("module manifest is invalid")
    requested = manifest.get("publisher_permissions") or []
    if not isinstance(requested, list) or any(not isinstance(v, str) or not v.strip() for v in requested):
        raise RuntimeError("module publisher_permissions is invalid")
    perms.update(v.strip() for v in requested)
    return perms



def _artifact_modules_from_archive(path: Path) -> list[dict]:
    """Return signed module identities/version/migration facts from archive bytes."""
    modules: list[dict] = []

    def row_from_manifest(manifest: dict) -> dict:
        module_id = str(manifest.get("id") or "").strip()
        version = str(manifest.get("version") or "").strip()
        if not module_id or not version:
            raise RuntimeError("module manifest identity/version is missing")
        migration = manifest.get("migration") if isinstance(manifest.get("migration"), dict) else {}
        previous = migration.get("previous_module_ids") or []
        if not isinstance(previous, list) or any(not isinstance(v, str) or not v.strip() for v in previous):
            raise RuntimeError("module migration.previous_module_ids is invalid")
        return {
            "id": module_id,
            "version": version,
            "previous_module_ids": sorted(set(v.strip() for v in previous)),
        }

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            for info in infos:
                _safe_zip_name(info.filename)
                mode = (info.external_attr >> 16) & 0xFFFF
                if mode and (mode & 0o170000) == 0o120000:
                    raise RuntimeError(f"module archive contains symlink: {info.filename}")
            bundle_manifests = [i for i in infos if PurePosixPath(i.filename).name == "tec_tac_bundle.json"]
            if len(bundle_manifests) == 1:
                manifest = json.loads(zf.read(bundle_manifests[0]).decode("utf-8"))
                entries = manifest.get("packages") if isinstance(manifest, dict) else None
                if not isinstance(entries, list) or not entries:
                    raise RuntimeError("bundle manifest has no packages")
                base = PurePosixPath(bundle_manifests[0].filename).parent
                for entry in entries:
                    filename = entry if isinstance(entry, str) else (entry.get("file") if isinstance(entry, dict) else None)
                    if not filename:
                        raise RuntimeError("bundle package entry is invalid")
                    member = (base / str(filename)).as_posix()
                    try:
                        child_bytes = zf.read(member)
                    except KeyError as exc:
                        raise RuntimeError(f"bundle child package is missing: {filename}") from exc
                    suffix = ''.join(Path(str(filename)).suffixes) or '.zip'
                    with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
                        tmp.write(child_bytes); tmp.flush()
                        modules.extend(_artifact_modules_from_archive(Path(tmp.name)))
                return modules
            if len(bundle_manifests) > 1:
                raise RuntimeError("module archive contains multiple bundle manifests")
            manifests = []
            for info in infos:
                if PurePosixPath(info.filename).name != "tec_tac.json":
                    continue
                payload = json.loads(zf.read(info).decode("utf-8"))
                if isinstance(payload, dict) and str(payload.get("type") or "") == "extension":
                    manifests.append(payload)
            if len(manifests) != 1:
                raise RuntimeError("module archive must contain exactly one extension manifest")
            modules.append(row_from_manifest(manifests[0]))
            return modules
    if tarfile.is_tarfile(path):
        manifests = []
        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                rel = PurePosixPath(member.name.replace('\\', '/'))
                if rel.is_absolute() or '..' in rel.parts or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    raise RuntimeError(f"unsafe module archive member: {member.name}")
                if member.isfile() and rel.name == 'tec_tac.json':
                    handle = tf.extractfile(member)
                    if handle is None:
                        raise RuntimeError("module manifest is unreadable")
                    payload = json.loads(handle.read().decode('utf-8'))
                    if isinstance(payload, dict) and str(payload.get("type") or "") == "extension":
                        manifests.append(payload)
        if len(manifests) != 1:
            raise RuntimeError("module archive must contain exactly one extension manifest")
        modules.append(row_from_manifest(manifests[0]))
        return modules
    raise RuntimeError('module package must be a ZIP or tar archive')

def verify_tree(root: Path, component: str) -> dict:
    _, _, verify_release_tree = _imports()
    cfg = _config()
    required = (f'{component}.update',)
    trust = verify_release_tree(
        root=Path(root), expected_component=component, required_permissions=required,
        trust_root=TRUST_ROOT, server_environment=_environment(cfg),
    )
    trust = enforce_policy(trust, kind='update')
    # Production/offline/branch unsigned execution is prohibited even if an
    # administrator somehow configured an unsigned trust floor.
    if not trust.get('signed') and not _dev_override(cfg, kind='update'):
        raise RuntimeError('unsigned system updates require root-owned development override')
    return trust


def verify_package(package: Path, signature: Path | None, metadata: Path | None) -> dict:
    _, verify_release_files, _ = _imports()
    cfg = _config()
    required = tuple(sorted(_module_permissions_from_archive(Path(package))))
    release_meta = {}
    if metadata:
        try:
            release_meta = json.loads(Path(metadata).read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError(f"release metadata is unreadable: {exc}") from exc
        if not isinstance(release_meta, dict):
            raise RuntimeError("release metadata must contain an object")
    package_filename = str(release_meta.get("filename") or Path(package).name)
    signature_filename = str(release_meta.get("signature") or (Path(signature).name if signature else "")) or None
    trust = verify_release_files(
        package_path=Path(package), package_filename=package_filename,
        signature_path=Path(signature) if signature else None,
        signature_filename=signature_filename,
        metadata_path=Path(metadata) if metadata else None,
        required_permissions=required, require_signed=False,
        trust_root=TRUST_ROOT, server_environment=_environment(cfg),
    )
    trust = enforce_policy(trust, kind='package')
    trust['artifact_modules'] = _artifact_modules_from_archive(Path(package))
    return trust


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('verify-tree')
    p.add_argument('root'); p.add_argument('component', choices=('framework', 'ui'))
    p = sub.add_parser('verify-package')
    p.add_argument('package'); p.add_argument('--signature'); p.add_argument('--metadata')
    sub.add_parser('get-policy')
    p = sub.add_parser('set-policy')
    p.add_argument('level', choices=LEVELS); p.add_argument('--updated-by', default=''); p.add_argument('--updated-at', default='')
    args = parser.parse_args()
    if os.geteuid() != 0 and os.environ.get('TEC_TAC_TEST_ALLOW_NONROOT') != '1':
        raise SystemExit('privileged trust verifier must run as root')
    if args.command == 'verify-tree':
        result = verify_tree(Path(args.root), args.component)
    elif args.command == 'verify-package':
        result = verify_package(Path(args.package), Path(args.signature) if args.signature else None, Path(args.metadata) if args.metadata else None)
    elif args.command == 'get-policy':
        result = read_policy()
    else:
        result = write_policy(args.level, updated_by=args.updated_by, updated_at=args.updated_at)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

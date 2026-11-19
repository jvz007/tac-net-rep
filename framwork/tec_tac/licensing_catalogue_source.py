"""The licensed module catalogue and its downloads (1.17.103, AD-56, AD-58).

This is the one Core file that calls ``licensing.catalogue`` (the provider answers Core only, and it checks that the first frame
outside Licensing is a file inside the ``tec_tac`` package, so Licensing can allow exactly this file). Nothing a module controls reaches
the provider from here: every call passes plain keyword arguments, and the provider object is looked up fresh for each call and not kept.

What it does:

* ``fetch_catalogue``: asks the provider for the list of releases this licence may install, on a channel, and answers a plain state. A
  provider that is missing, disabled, unhealthy or refuses Core is ``licensing_unavailable``. It is never an unrestricted list.
* ``map_catalogue``: turns the answer into the cache shape every other repository uses (dependency lists become objects).
* ``download_release``: asks for a short-lived download grant, fetches the three files from the pinned Licensing Server address with the
  bearer in memory only, checks the file names and the SHA-256, and verifies the Ed25519 signature with Core's own trusted publisher keys.
  The catalogue's SHA-256 is a cross-check, never proof. An expired grant (HTTP 401) gets one new grant, then stops.

The bearer is held in one local variable. It is never logged, cached, audited, returned or put in an exception. The module imports no
Django, so it can be read and tested on its own.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("tec_tac.licensing_catalogue_source")

CAPABILITY_ID = "licensing.catalogue"
CAPABILITY_RANGE = ">=1.0.0,<2.0.0"
KIND = "licensing"

CHANNEL_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_MODULE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{8,2048}")
_TEXT_ID_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}")
_ZIP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.zip")
_SIG_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,124}\.sig")
_ARTIFACT_PATH_RE = re.compile(r"/api/v1/servers/modules/artifacts/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*")
_DEP_ID_RE = re.compile(r"([A-Za-z0-9_-]+)\s*(.*)")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
ARTIFACT_PREFIX = "/api/v1/servers/modules/artifacts/"

MAX_RELEASES = 5000
MAX_METADATA_BYTES = 256 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
SMALL_FILE_TIMEOUT = 20
PACKAGE_TIMEOUT = 60
MAX_GRANT_SECONDS = 300  # the Licensing Server's grant lasts about this long; Core never works past it

TEXT = {
    "ok": "Done.",
    "not_registered": "This server is not registered with the Licensing Server. Register it on the Licensing page first, then sync again.",
    "licence_revoked": "The licence was revoked, so the licensed catalogue and new module installs are stopped. Check the Licensing page.",
    "licence_expired": "The licence has expired, so the licensed catalogue and new module installs are stopped. Check the Licensing page.",
    "licence_grace_expired": "Licensing has no recent verified licence (the 7 day offline grace has ended, or none was checked yet). Use Refresh now on the Licensing page, then sync again.",
    "licence_refused": "The Licensing Server refused this server's licence, so new module installs are stopped. Check the Licensing page.",
    "licence_policy_unreadable": "This Licensing version cannot read the licence's module policy. Update Licensing, then use Refresh now.",
    "channel_not_permitted": "This licence does not allow the release channel set for this repository. Pick another channel, or leave it empty to use the licence's own. Core does not switch channels for you.",
    "licensing_unavailable": "Core could not get an answer from the Licensing module or the Licensing Server. Check that the Licensing module is installed, enabled and healthy, then try again.",
    "invalid_response": "The Licensing answer was not in the expected form, so Core did not use it. Try again later.",
    "bad_request": "The request was not valid. Check the channel name set for this repository.",
    "release_not_found": "The Licensing Server does not have this release for your licence and channel. Sync the repository again.",
    "audit_unavailable": "Licensing could not write its audit record, so it did nothing. Try again.",
    "grant_expired": "The download permission ran out before the files arrived, and a second one ran out too. Try again in a moment.",
    "download_refused": "The Licensing Server refused the download. The licence, the module or the publisher may have changed. Check the Licensing page, then sync again.",
    "download_failed": "The files could not be downloaded from the Licensing Server. Try again later.",
    "verification_failed": "The downloaded files failed Core's own checks, so nothing was staged.",
    "release_mismatch": "The downloaded files do not match what the catalogue listed for this release, so nothing was staged.",
    "not_in_licence": "This licence does not include this module, so it cannot be downloaded.",
    "audit_not_saved": "The download did not start because its audit record could not be saved. Try again.",
}
KNOWN_STATES = frozenset({
    "ok", "not_registered", "licence_revoked", "licence_expired", "licence_grace_expired", "licence_refused", "channel_not_permitted",
    "licensing_unavailable", "invalid_response", "bad_request", "release_not_found", "audit_unavailable",
    "licence_policy_unreadable",  # 1.17.108: Licensing 0.10.2 cannot read the licence's module policy (fails closed like grace_expired)
})
# A temporary fault keeps the last good list (installs still need a fresh grant). Every other state empties the list: nothing is offered.
TRANSIENT_STATES = frozenset({"licensing_unavailable", "invalid_response", "audit_unavailable"})
# States that need an administrator's attention but are not a failure of the sync itself (the daily run does not count them as failed).
ATTENTION_STATES = frozenset({
    "not_registered", "licence_revoked", "licence_expired", "licence_grace_expired", "licence_refused", "channel_not_permitted",
    "licence_policy_unreadable",
})
AVAILABILITY_STATES = tuple(sorted(KNOWN_STATES - {"ok"}))

# 1.17.108: the state of one licensed release, read from the Licensing Server's entitled, availability and category (handoff v0.1.44,
# section 4 item 4). Only "available" is offered for staging. Every other state is listed with its reason and never offered.
CATEGORIES = frozenset({"core", "server", "premium"})
ROW_AVAILABLE = "available"
ROW_TEXT = {
    "entitled_unavailable": "Your licence includes this module, but the Licensing Server says this release is not available now. Sync again later.",
    "blocked_by_channel": "This release is not offered on the release channel set for this repository. Pick another channel, or leave it empty to use the licence's own.",
    "missing_or_dependency": "This release is missing on the Licensing Server, or a module it needs is not available. Sync again later, or install what it needs first.",
    "not_in_licence": TEXT["not_in_licence"],
    "unclassified": "The Licensing Server lists this module with no category. Core treats it as test: offered only on a development server, in the development channel.",
}
# 1.17.109 (AD-21, handoff v0.1.44 section 2): a release with no category is treated as test. On a development server, in the
# development channel only, it is offered with this warning; anywhere else it stays unclassified and is never offered. The category
# used at install is always the signed manifest's (Core's install-time AD-21 check); this one is for display and filtering only.
UNCLASSIFIED_TEST_CHANNEL = "development"
UNCLASSIFIED_TEST_WARNING = "Unclassified on the Licensing Server: treated as test"
ROW_STATES = (ROW_AVAILABLE, *sorted(ROW_TEXT))


class LicensingSourceError(RuntimeError):
    """A plain state and Core's own sentence. It never carries a bearer, a token or text from the Licensing Server."""

    def __init__(self, state: str):
        self.state = state if state in TEXT else "licensing_unavailable"
        self.message = TEXT[self.state]
        super().__init__(self.message)


class _GrantExpired(Exception):
    pass


def message_for(state: str) -> str:
    return TEXT.get(state, TEXT["licensing_unavailable"])


def clean_channel(value: Any) -> str:
    """The channel as stored: empty (the licence's own preferred channel) or a valid name. Anything else raises ValueError."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("channel")
    text = value.strip()
    if not text:
        return ""
    if not CHANNEL_RE.fullmatch(text):
        raise ValueError("channel")
    return text


# --- the provider ---------------------------------------------------------------------------------------------------------------


def _provider():
    """The provider object, or None when it is missing, disabled, unhealthy or the wrong version. Never kept between calls."""
    try:
        from .capabilities import get_capability

        return get_capability(CAPABILITY_ID, version=CAPABILITY_RANGE)
    except Exception as exc:
        logger.warning("The licensing.catalogue provider is not available (%s).", exc.__class__.__name__)
        return None


def _call(operation: str, **kwargs) -> tuple[str, dict | None]:
    provider = _provider()
    if provider is None:
        return "licensing_unavailable", None
    try:
        answer = getattr(provider, operation)(**kwargs)
    except Exception as exc:
        # A refused caller (caller_not_allowed), a bug or a crash: all read as "no answer". Only the class name is logged.
        logger.warning("licensing.catalogue.%s failed (%s).", operation, exc.__class__.__name__)
        return "licensing_unavailable", None
    if not isinstance(answer, dict) or not isinstance(answer.get("state"), str):
        return "invalid_response", None
    state = answer["state"]
    if state not in KNOWN_STATES:
        return "invalid_response", None
    if state != "ok":
        return state, None
    return "ok", answer


def fetch_catalogue(channel: str | None) -> tuple[str, dict | None]:
    """(state, answer). The answer is the provider's dict only when the state is ok and its list is a list."""
    state, answer = _call("module_catalogue", channel=channel or None)
    if state != "ok":
        return state, None
    if answer.get("ok") is not True or not isinstance(answer.get("modules"), list):
        return "invalid_response", None
    return "ok", answer


def request_grant(release_id: str, channel: str | None) -> tuple[str, dict | None]:
    """(state, grant). The grant holds the bearer: the caller keeps it in one local variable and drops it."""
    state, answer = _call("download_grant", release_id=release_id, channel=channel or None)
    if state != "ok":
        return state, None
    token = answer.get("artifact_access_token")
    expires = answer.get("expires_in_seconds")
    artifacts = answer.get("artifacts")
    if (answer.get("ok") is not True or not isinstance(token, str) or not _TOKEN_RE.fullmatch(token)
            or isinstance(expires, bool) or not isinstance(expires, int) or not 1 <= expires <= 3600
            or not isinstance(artifacts, dict)):
        return "invalid_response", None
    paths = {}
    prefix = f"{ARTIFACT_PREFIX}{release_id}/"
    for name in ("package", "signature", "release_metadata"):
        path = artifacts.get(name)
        if (not isinstance(path, str) or len(path) > 300 or not _ARTIFACT_PATH_RE.fullmatch(path) or not path.startswith(prefix)
                or any(part in ("", ".", "..") for part in path.split("/")[1:])):
            return "invalid_response", None
        paths[name] = path
    return "ok", {"artifact_access_token": token, "expires_in_seconds": expires, "artifacts": paths}


# --- the listing ---------------------------------------------------------------------------------------------------------------


def _text(value: Any, limit: int = 120) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = _CONTROL.sub("", value).strip()
    return cleaned[:limit] or None


def _skipped(index: int, module_id: Any, version: Any, reason: str) -> dict:
    return {"index": index, "id": _text(module_id, 100), "version": _text(version, 100), "reason": reason[:300]}


def _constraint_ok(constraint: str) -> bool:
    from .module_state import ModuleStateError, version_satisfies

    try:
        version_satisfies("0.0.0", constraint)
        return True
    except ModuleStateError:
        return False


def _dependency_object(value: Any) -> dict[str, str]:
    """A dependency list (or object) as {module id: constraint}. Raises ValueError on a shape it cannot read, so the release is skipped
    and a dependency is never dropped silently."""
    if value is None or value == [] or value == {}:
        return {}
    pairs: list[tuple[str, str]] = []
    if isinstance(value, dict):
        pairs = [(str(k), str(v if v not in (None, "") else "*")) for k, v in value.items()]
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                match = _DEP_ID_RE.fullmatch(item.strip())
                if not match:
                    raise ValueError("a dependency is not readable")
                pairs.append((match.group(1), match.group(2).strip() or "*"))
            elif isinstance(item, dict):
                dep_id = item.get("id") or item.get("module_id") or item.get("module")
                constraint = item.get("constraint") or item.get("version") or item.get("requires") or item.get("range") or "*"
                if not isinstance(dep_id, str) or not isinstance(constraint, str):
                    raise ValueError("a dependency is not readable")
                pairs.append((dep_id.strip(), constraint.strip() or "*"))
            else:
                raise ValueError("a dependency is not readable")
    else:
        raise ValueError("dependencies must be a list or an object")
    result: dict[str, str] = {}
    for dep_id, constraint in pairs:
        if not _MODULE_ID_RE.fullmatch(dep_id) or not _constraint_ok(constraint):
            raise ValueError("a dependency is not valid")
        result[dep_id] = constraint
    return result


def _release_row(module: dict, release: dict) -> dict:
    from .module_state import ModuleStateError, version_satisfies

    module_id = str(module.get("id") or "").strip()
    if not _MODULE_ID_RE.fullmatch(module_id):
        raise ValueError("the module id is not valid")
    version = str(release.get("version") or "").strip()
    if not version:
        raise ValueError("the version is missing")
    try:
        version_satisfies(version, "*")
    except ModuleStateError as exc:
        raise ValueError("the version is not valid") from exc
    try:
        release_id = str(uuid.UUID(str(release.get("release_id"))))
    except ValueError as exc:
        raise ValueError("the release id is not valid") from exc
    sha256 = str(release.get("sha256") or "").strip().lower()
    if not _SHA256_RE.fullmatch(sha256):
        raise ValueError("the SHA-256 is not valid")
    channel = release.get("channel")
    if channel is not None and not (isinstance(channel, str) and CHANNEL_RE.fullmatch(channel)):
        raise ValueError("the channel is not valid")
    publisher_id, key_id = release.get("publisher_id"), release.get("key_id")
    for label, value in (("publisher_id", publisher_id), ("key_id", key_id)):
        if value is not None and not (isinstance(value, str) and _TEXT_ID_RE.fullmatch(value)):
            raise ValueError(f"the {label} is not valid")
    requires = release.get("requires") or {}
    if not isinstance(requires, dict):
        raise ValueError("requires must be an object")
    requires = {str(k): str(v if v not in (None, "") else "*") for k, v in requires.items()}
    if not all(_constraint_ok(v) for v in requires.values()):
        raise ValueError("a requirement is not valid")
    row = {
        "id": module_id,
        "name": _text(module.get("name"), 120) or module_id,
        "description": "",
        "version": version,
        "download": "",
        "download_url": None,
        "sha256": sha256,
        "signature_url": None,
        "release_metadata_url": None,
        "dependencies": _dependency_object(release.get("dependencies")),
        "optional_dependencies": _dependency_object(release.get("optional_dependencies")),
        "requires": requires,
        "channel": channel,
        "lifecycle": None,
        "recommended": release.get("recommended") if isinstance(release.get("recommended"), bool) else None,
        "downgrade_policy": None,
        "signing_environment": _text(release.get("environment"), 64),
        "release_id": release_id,
        "publisher_id": publisher_id,
        "key_id": key_id,
        "entitled": module.get("entitled") is True,
        "category": _category(module.get("category")),
        "entitlement_source": _text(module.get("entitlement_source"), 32),
        "availability": _text(module.get("availability"), 32),
    }
    return apply_availability(row)


def category_of(value: Any) -> str | None:
    """The public name of _category (1.17.109): core, server or premium, else None."""
    return _category(value)


def _category(value: Any) -> str | None:
    """core, server or premium; anything else (None, missing, unclassified or an unknown word) is None (AD-21)."""
    text = _text(value, 32)
    return text.lower() if text and text.lower() in CATEGORIES else None


def _unclassified_offered(row: dict, development: bool) -> bool:
    """1.17.109: a release with no category is treated as test, so it is offered on a development server in the development channel only."""
    channel = row.get("channel")
    return development is True and isinstance(channel, str) and channel.strip().lower() == UNCLASSIFIED_TEST_CHANNEL


def row_availability(row: dict, *, development: bool = False) -> str:
    """One state per licensed release (1.17.108). Order: not in the licence, no category, then the server's availability word.

    1.17.109: no category is unclassified unless development is True and the release is in the development channel (AD-21: treated as
    test). The caller passes Core's own development-server test (module_category.is_development_server); the default is not a dev server.

    The server's word is read loosely (it is free text up to 32 characters): no word or "available" is available; a word that names the
    channel is blocked_by_channel; a word that names a missing release or a dependency is missing_or_dependency; any other word is
    entitled_unavailable. An unknown word is never read as available."""
    if row.get("entitled") is not True:
        return "not_in_licence"
    if _category(row.get("category")) is None and not _unclassified_offered(row, development):
        return "unclassified"
    word = (row.get("availability") or "").strip().lower()
    if word in ("", ROW_AVAILABLE):
        return ROW_AVAILABLE
    if "channel" in word:
        return "blocked_by_channel"
    if "missing" in word or "dependen" in word:
        return "missing_or_dependency"
    return "entitled_unavailable"


def apply_availability(row: dict, *, development: bool = False) -> dict:
    """Set availability_state on a licensed row; a row that is not available is marked never offered, with its reason. Idempotent, and
    it never clears a mark another rule set (a retired or refused repository).

    1.17.109: a mark this function set earlier (a state of ROW_TEXT, for example in a cache written at sync) is worked out again, so the
    development-server answer of this request decides. A release with no category that is offered carries category_warning."""
    if row.get("download_unavailable") and row.get("download_unavailable_state") in ROW_TEXT:
        for key in ("download_unavailable", "download_unavailable_reason", "download_unavailable_state"):
            row.pop(key, None)
    state = row_availability(row, development=development)
    row["availability_state"] = state
    if state == ROW_AVAILABLE and _category(row.get("category")) is None:
        row["category_warning"] = UNCLASSIFIED_TEST_WARNING
    else:
        row.pop("category_warning", None)
    if state != ROW_AVAILABLE and not row.get("download_unavailable"):
        row["download_unavailable"] = True
        row["download_unavailable_reason"] = ROW_TEXT[state]
        row["download_unavailable_state"] = state
    return row


def map_catalogue(answer: dict) -> tuple[list[dict], list[dict]]:
    """The provider's modules as cache rows plus the skipped records (a release that cannot be read is skipped with its reason).

    Both copies of a duplicate module id and version are skipped. A cache holds no credential and no URL: the provider's answer has
    neither, and this keeps only the fields named above."""
    rows: list[dict] = []
    skipped: list[dict] = []
    index = -1
    for module in answer.get("modules") or []:
        releases = module.get("available_releases") if isinstance(module, dict) else None
        if not isinstance(releases, list):
            index += 1
            skipped.append(_skipped(index, (module or {}).get("id") if isinstance(module, dict) else None, None, "the module entry is not readable"))
            continue
        for release in releases:
            index += 1
            if index >= MAX_RELEASES:
                skipped.append(_skipped(index, module.get("id"), None, "too many releases"))
                continue
            try:
                if not isinstance(release, dict):
                    raise ValueError("the release entry is not an object")
                rows.append(_release_row(module, release))
            except ValueError as exc:
                skipped.append(_skipped(index, module.get("id"), release.get("version") if isinstance(release, dict) else None, f"skipped: {exc}"))
    seen: dict[tuple[str, str], int] = {}
    for row in rows:
        seen[(row["id"], row["version"])] = seen.get((row["id"], row["version"]), 0) + 1
    kept = []
    for row in rows:
        if seen[(row["id"], row["version"])] > 1:
            skipped.append(_skipped(len(skipped), row["id"], row["version"], "duplicate"))
        else:
            kept.append(row)
    return kept, skipped


# --- the download ---------------------------------------------------------------------------------------------------------------


class DownloadedFiles:
    __slots__ = ("filename", "metadata", "metadata_name", "package", "sha256", "signature", "signature_name", "trust")

    def __init__(self, **kwargs):
        for key in self.__slots__:
            setattr(self, key, kwargs.get(key))


def _read_metadata(data: bytes) -> dict:
    try:
        metadata = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise LicensingSourceError("verification_failed") from None
    if not isinstance(metadata, dict):
        raise LicensingSourceError("verification_failed")
    return metadata


def _check_names_and_cross_checks(metadata: dict, release: dict) -> tuple[str, str]:
    """The file name comes from the validated release.json, never from a URL. The catalogue is a cross-check only."""
    filename = metadata.get("filename")
    signature_name = metadata.get("signature")
    if not isinstance(filename, str) or not _ZIP_NAME_RE.fullmatch(filename) or ".." in filename:
        raise LicensingSourceError("verification_failed")
    if not isinstance(signature_name, str) or not _SIG_NAME_RE.fullmatch(signature_name) or ".." in signature_name:
        raise LicensingSourceError("verification_failed")
    digest = str(metadata.get("sha256") or "").strip().lower()
    if digest != str(release.get("sha256") or ""):
        raise LicensingSourceError("release_mismatch")
    for key in ("publisher_id", "key_id"):
        listed = release.get(key)
        if listed and str(metadata.get(key) or "") != listed:
            raise LicensingSourceError("release_mismatch")
    return filename, signature_name


def _fetch_files(*, release: dict, grant: dict, origin: str, tmp: Path, fetch: Callable, clock: Callable[[], float], max_package_bytes: int) -> DownloadedFiles:
    """Fetch the three files with one grant. Raises _GrantExpired on HTTP 401 or when the grant's time is used up."""
    token = grant["artifact_access_token"]
    deadline = clock() + min(int(grant["expires_in_seconds"]), MAX_GRANT_SECONDS)
    base = str(origin or "").rstrip("/")
    paths = grant["artifacts"]

    def get(name: str, maximum: int, timeout: int) -> bytes:
        if clock() >= deadline:
            raise _GrantExpired()
        try:
            return fetch(base + paths[name], maximum, bearer=token, timeout=timeout)
        except Exception as exc:
            status = getattr(exc, "status", None)
            if status == 401:
                raise _GrantExpired() from None
            if status == 403:
                raise LicensingSourceError("download_refused") from None
            if status == 404:
                raise LicensingSourceError("release_not_found") from None
            raise LicensingSourceError("download_failed") from None

    try:
        metadata_bytes = get("release_metadata", MAX_METADATA_BYTES, SMALL_FILE_TIMEOUT)
        metadata = _read_metadata(metadata_bytes)
        filename, signature_name = _check_names_and_cross_checks(metadata, release)
        signature_bytes = get("signature", MAX_SIGNATURE_BYTES, SMALL_FILE_TIMEOUT)
        package_bytes = get("package", max_package_bytes, PACKAGE_TIMEOUT)
    finally:
        token = None  # the bearer goes out of scope here; grant keeps no copy (the caller popped it)
    digest = hashlib.sha256(package_bytes).hexdigest()
    if digest != release.get("sha256"):
        raise LicensingSourceError("release_mismatch")
    metadata_name = filename[: -len(".zip")] + ".release.json"
    files = DownloadedFiles(
        package=tmp / filename, signature=tmp / signature_name, metadata=tmp / metadata_name,
        filename=filename, signature_name=signature_name, metadata_name=metadata_name, sha256=digest,
    )
    files.package.write_bytes(package_bytes)
    files.signature.write_bytes(signature_bytes)
    files.metadata.write_bytes(metadata_bytes)
    return files


def _default_verify(**kwargs) -> dict:
    from .trusted_publishers import verify_release_files

    return verify_release_files(**kwargs)


def download_release(
    *, release: dict, channel: str | None, fetch: Callable, origin: str, tmp: Path, max_package_bytes: int,
    grant_fn: Callable = request_grant, verify: Callable = _default_verify, clock: Callable[[], float] = time.monotonic,
) -> DownloadedFiles:
    """Grant, three fetches, names, SHA-256 and signature. Returns the files on disk in ``tmp``, or raises LicensingSourceError.

    A grant that expires (HTTP 401, or its own time) is replaced once. A second expiry stops with grant_expired. A 403 or 404 stops at
    once. Nothing is written to ``tmp`` before every download finished, so a revoked grant half way leaves nothing behind."""
    release_id = str(release.get("release_id") or "")
    for attempt in (1, 2):
        state, grant = grant_fn(release_id, channel)
        if state != "ok" or grant is None:
            raise LicensingSourceError(state)
        try:
            files = _fetch_files(release=release, grant=grant, origin=origin, tmp=tmp, fetch=fetch, clock=clock, max_package_bytes=max_package_bytes)
            break
        except _GrantExpired:
            if attempt == 2:
                raise LicensingSourceError("grant_expired") from None
        finally:
            grant.pop("artifact_access_token", None)
    try:
        files.trust = verify(
            package_path=files.package, package_filename=files.filename,
            signature_path=files.signature, signature_filename=files.signature_name,
            metadata_path=files.metadata, require_signed=True,
        )
    except Exception as exc:
        # PublisherTrustError carries a plain code; log the class and code only, never file contents.
        logger.warning("A licensed release failed Core's signature check (%s, %s).", exc.__class__.__name__, getattr(exc, "code", "none"))
        raise LicensingSourceError("verification_failed") from None
    if not (isinstance(files.trust, dict) and files.trust.get("signed") and files.trust.get("verified") and files.trust.get("trusted")):
        raise LicensingSourceError("verification_failed")
    if files.trust.get("package_sha256") != release.get("sha256"):
        raise LicensingSourceError("release_mismatch")
    return files


# --- the allowed-module list (1.18.10) -----------------------------------------------------------------------------------------
#
# ``licensing.allowed_modules`` (1.1.0 or later since 1.18.18) is Core-only too (AD-56) and checks the same thing: the first frame outside Licensing must be this
# file. So every call below goes straight from this file to the provider method. Core's views never call the provider. What leaves this
# file is whitelisted and type-checked: no key, grant, token, Licensing Server address, SHA-256, publisher id or key id.

ALLOWED_CAPABILITY_ID = "licensing.allowed_modules"
# Since 1.18.18 Core needs 1.1.0, which publishes the Core-only ``set_selection`` operation (Licensing 0.10.7). A Licensing that registers
# only 1.0.0 reads as licensing_unavailable for the list, refresh and selection routes: never an unrestricted list, no fallback.
ALLOWED_CAPABILITY_RANGE = ">=1.1.0,<2.0.0"

_ALLOWED_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_CHANNEL_WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}")
PLAN_STATES = frozenset({"valid", "expired", "none", "invalid"})
# Every state Licensing's allowed_modules answers with (its TEXT keys). Any other word is an invalid answer.
ALLOWED_STATES = frozenset({
    "ok", "cached", "saved", "not_fetched", "not_registered", "licence_revoked", "licence_expired", "licence_grace_expired",
    "licence_refused", "licence_policy_unreadable", "channel_not_permitted", "licensing_unavailable", "invalid_response", "audit_unavailable",
    "plan_unavailable", "plan_invalid", "plan_expired", "plan_rollback", "plan_wrong_server", "plan_channel_not_permitted",
    "issuer_not_pinned", "caller_not_allowed", "plan_conflict", "category_unknown", "locked", "required_by", "bad_request",
})
# Core's own sentences for the selection route (they never come from Licensing).
CORE_ALLOWED_TEXT = {
    "unknown_module": "That module is not on the list of modules this licence allows, so nothing was changed.",
    "locked": "That module cannot be deselected. Only licensed premium modules can.",
    "bad_request": "The request was not valid. Send a module id and true or false.",
    "saved": "Saved.",
    "not_fetched": "Licensing has not asked the Licensing Server for the allowed modules yet. Use Refresh.",
    "cached": "The list was refreshed less than a minute ago, so Licensing used the saved list.",
}
_ALLOWED_TOP_DEFAULTS = {
    "plan_state": "none", "plan_revision": None, "channel": None, "plan_issued_at": None, "plan_expires_at": None, "fetched_at": None,
    "from_cache": True, "last_refresh_state": None,
}


class _BadAllowed(ValueError):
    pass


def _allowed_provider():
    """The licensing.allowed_modules provider, or None. Looked up fresh on each call and never kept."""
    try:
        from .capabilities import get_capability

        return get_capability(ALLOWED_CAPABILITY_ID, version=ALLOWED_CAPABILITY_RANGE)
    except Exception as exc:
        logger.warning("The licensing.allowed_modules provider is not available (%s).", exc.__class__.__name__)
        return None


def _call_allowed(operation: str, **kwargs) -> tuple[str, dict | None]:
    """(state, answer). Unlike ``_call`` this returns the answer for every state Licensing knows, because a list that is not fetched yet
    or a refresh that was cached still carries a message the administrator needs. The provider method is called from this function, so
    the first frame Licensing judges is this file."""
    provider = _allowed_provider()
    if provider is None:
        return "licensing_unavailable", None
    try:
        answer = getattr(provider, operation)(**kwargs)
    except Exception as exc:
        # A refused caller, a missing method, a bug or a crash: all read as "no answer". Only the class name is logged.
        logger.warning("licensing.allowed_modules.%s failed (%s).", operation, exc.__class__.__name__)
        return "licensing_unavailable", None
    if not isinstance(answer, dict) or not isinstance(answer.get("state"), str) or answer["state"] not in ALLOWED_STATES:
        return "invalid_response", None
    return answer["state"], answer


def _allowed_message(state: str, answer: dict | None = None) -> str:
    """Core's own sentence when it has one. Otherwise Licensing's sentence for its own state, stripped of control characters and cut to
    400 characters. It is shown as text and never read as anything else."""
    own = TEXT.get(state) or CORE_ALLOWED_TEXT.get(state)
    if own:
        return own
    return _text((answer or {}).get("message"), 400) or TEXT["licensing_unavailable"]


def _strict_bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise _BadAllowed("bool")
    return value


def _id_list(value: Any, limit: int = 200) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise _BadAllowed("list")
    out = []
    for item in value:
        if not isinstance(item, str) or not _ALLOWED_ID_RE.fullmatch(item):
            raise _BadAllowed("id")
        out.append(item)
    return out


def _release_dependencies(value: Any) -> dict[str, str]:
    """{module id: constraint}, for display. Core re-reads and checks the dependencies itself at install."""
    if value is None or value == [] or value == {}:
        return {}
    pairs: list[tuple[Any, Any]] = []
    if isinstance(value, dict):
        pairs = list(value.items())
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                match = _DEP_ID_RE.fullmatch(item.strip())
                if not match:
                    raise _BadAllowed("dependency")
                pairs.append((match.group(1), match.group(2).strip() or "*"))
            elif isinstance(item, dict):
                pairs.append((item.get("id") or item.get("module_id") or item.get("module"),
                              item.get("constraint") or item.get("version") or item.get("requires") or item.get("range") or "*"))
            else:
                raise _BadAllowed("dependency")
    else:
        raise _BadAllowed("dependency")
    if len(pairs) > 100:
        raise _BadAllowed("dependency")
    result: dict[str, str] = {}
    for dep_id, constraint in pairs:
        constraint = "*" if constraint in (None, "") else constraint
        if not isinstance(dep_id, str) or not _MODULE_ID_RE.fullmatch(dep_id) or not isinstance(constraint, str):
            raise _BadAllowed("dependency")
        cleaned = _text(constraint, 64)
        if cleaned is None:
            raise _BadAllowed("dependency")
        result[dep_id] = cleaned
    return result


def _trimmed_release(value: Any) -> dict | None:
    """release_id, version, channel and dependencies only. The SHA-256, publisher id and key id stay inside Core's later install check."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise _BadAllowed("release")
    try:
        release_id = str(uuid.UUID(str(value.get("release_id"))))
    except ValueError:
        raise _BadAllowed("release_id") from None
    version = _text(value.get("version"), 64)
    channel = value.get("channel")
    if version is None or (channel is not None and not (isinstance(channel, str) and _CHANNEL_WORD_RE.fullmatch(channel))):
        raise _BadAllowed("release")
    return {"release_id": release_id, "version": version, "channel": channel, "dependencies": _release_dependencies(value.get("dependencies"))}


def _allowed_row(item: Any) -> dict:
    if not isinstance(item, dict):
        raise _BadAllowed("row")
    module_id = item.get("id")
    if not isinstance(module_id, str) or not _ALLOWED_ID_RE.fullmatch(module_id):
        raise _BadAllowed("id")
    category = item.get("category")
    if category is not None and (not isinstance(category, str) or category not in CATEGORIES):
        raise _BadAllowed("category")
    notes = item.get("notes") if item.get("notes") is not None else []
    if not isinstance(notes, list) or len(notes) > 20:
        raise _BadAllowed("notes")
    for key in ("availability", "category_source", "name"):
        if item.get(key) is not None and not isinstance(item.get(key), str):
            raise _BadAllowed(key)
    return {
        "id": module_id,
        "name": _text(item.get("name"), 120) or module_id,
        "category": category,
        "entitled": _strict_bool(item.get("entitled")),
        "availability": _text(item.get("availability"), 32),
        "locked": _strict_bool(item.get("locked")),
        "optional": _strict_bool(item.get("optional")),
        "selected": _strict_bool(item.get("selected")),
        "in_plan": _strict_bool(item.get("in_plan")),
        "required_by": _id_list(item.get("required_by") if item.get("required_by") is not None else []),
        "notes": [t for t in (_text(n, 64) for n in notes if isinstance(n, str)) if t],
        "category_source": _text(item.get("category_source"), 32),
        "release": _trimmed_release(item.get("release")),
    }


def _allowed_top(answer: dict) -> dict:
    """The plan fields of an answer, best effort. A field that is not the expected type becomes its default (display only)."""
    top = dict(_ALLOWED_TOP_DEFAULTS)
    plan_state = answer.get("plan_state")
    if isinstance(plan_state, str) and plan_state in PLAN_STATES:
        top["plan_state"] = plan_state
    revision = answer.get("plan_revision")
    if isinstance(revision, int) and not isinstance(revision, bool):
        top["plan_revision"] = revision
    elif isinstance(revision, str):
        top["plan_revision"] = _text(revision, 64)
    for key, limit in (("channel", 32), ("plan_issued_at", 40), ("plan_expires_at", 40), ("fetched_at", 40), ("last_refresh_state", 64)):
        top[key] = _text(answer.get(key), limit)
    if isinstance(answer.get("from_cache"), bool):
        top["from_cache"] = answer["from_cache"]
    return top


def _allowed_body(state: str, answer: dict | None) -> dict:
    """One whitelisted body. Rows come out only for ok (and a cached refresh). A malformed answer is invalid_response with no rows."""
    body: dict[str, Any] = {"ok": False, "state": state, "message": _allowed_message(state, answer), **_ALLOWED_TOP_DEFAULTS, "count": 0, "modules": []}
    if answer is None:
        return body
    body.update(_allowed_top(answer))
    if state not in ("ok", "cached"):
        return body
    try:
        modules = answer.get("modules")
        if not isinstance(modules, list) or len(modules) > MAX_RELEASES:
            raise _BadAllowed("modules")
        rows = [_allowed_row(item) for item in modules]
        if len({row["id"] for row in rows}) != len(rows):
            raise _BadAllowed("duplicate")
    except _BadAllowed:
        return {**body, "ok": False, "state": "invalid_response", "message": TEXT["invalid_response"], "modules": [], "count": 0}
    body.update(ok=True, modules=rows, count=len(rows))
    return body


def read_allowed_modules() -> dict:
    """The allowed-module list for the browser: Licensing's ``list_modules`` through Core, whitelisted. A missing, disabled, unhealthy or
    refusing provider is ``licensing_unavailable`` with no rows, never an unrestricted list. No network call: Licensing reads saved state."""
    state, answer = _call_allowed("list_modules")
    return _allowed_body(state, answer)


def refresh_allowed_modules() -> dict:
    """Licensing's ``refresh`` through Core. Licensing asks the Licensing Server at most once a minute and answers ``cached`` inside it."""
    state, answer = _call_allowed("refresh")
    return _allowed_body(state, answer)


def _selection_body(state: str, module_id: str, selected: bool, answer: dict | None = None) -> dict:
    body: dict[str, Any] = {"ok": state == "saved", "state": state, "message": _allowed_message(state, answer), "module_id": module_id,
                            "selected": selected, "before": [], "after": [], "required_by": []}
    if answer is None:
        return body
    try:
        if state == "saved":
            body["before"] = _id_list(answer.get("before"), 5000)
            body["after"] = _id_list(answer.get("after"), 5000)
        elif state == "required_by":
            body["required_by"] = _id_list(answer.get("required_by") if answer.get("required_by") is not None else [])
    except _BadAllowed:
        return {**body, "ok": False, "state": "invalid_response", "message": TEXT["invalid_response"], "before": [], "after": [], "required_by": []}
    return body


def set_premium_selection(module_id: Any, selected: Any) -> dict:
    """Select or deselect one entitled, optional premium module (the administrator's own choice in Licensing's saved state).

    Core checks first, before it calls Licensing: the id's shape, a real bool, and that the id is on the list Licensing just gave as an
    entitled, optional premium row. A Core or Server row, an unentitled row and an id outside the list are refused here. Licensing's own
    ``set_selection`` (a published, gated Core-only operation of licensing.allowed_modules 1.1.0) then keeps the ``required_by`` refusal
    and the row-locked write. There is no fallback: a provider older than 1.1.0 is ``licensing_unavailable``. Nothing is installed or removed."""
    if not isinstance(module_id, str) or not _ALLOWED_ID_RE.fullmatch(module_id) or not isinstance(selected, bool):
        return _selection_body("bad_request", module_id if isinstance(module_id, str) and _ALLOWED_ID_RE.fullmatch(module_id) else "", False)
    current = read_allowed_modules()
    if current["state"] != "ok":
        return _selection_body(current["state"], module_id, selected)
    row = next((r for r in current["modules"] if r["id"] == module_id), None)
    if row is None:
        return _selection_body("unknown_module", module_id, selected)
    if row["category"] != "premium" or not row["optional"] or row["locked"] or not row["entitled"]:
        return _selection_body("locked", module_id, selected)
    state, answer = _call_allowed("set_selection", module_id=module_id, selected=selected)
    if state not in ("saved", "locked", "required_by", "bad_request"):
        return _selection_body(state if state in ("licensing_unavailable", "invalid_response") else "licensing_unavailable", module_id, selected)
    return _selection_body(state, module_id, selected, answer)

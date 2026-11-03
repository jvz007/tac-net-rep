#!/usr/bin/env python3
"""1.17.103 (AD-56, AD-58, C4): a licensed release installs again.

Covered, with REAL Ed25519 signatures and Core's real trusted-publisher check: grant, then three RELATIVE paths on the pinned origin with
the bearer; the file name comes from the validated release.json (filename binding), never from a URL; SHA-256 and signature verified
independently (the catalogue is only a cross-check); an expired grant (HTTP 401, or its own time) gets one new grant, then stops;
403 and 404 and other faults are plain states; a grant revoked in the middle of a download leaves nothing behind; a changed package, a
changed release.json, a signature by the wrong or an unknown key, a publisher that differs from the catalogue and an unsigned release
are refused; a grant that names another host, another release, a dot segment or a bad token is refused; a redirect is never followed
(the bearer is never sent to another host) and a plain-http address is refused; the audit row is written first and strict; the token
is not in any log line, audit row, cache, answer or exception; an unsigned or mismatching staged result is discarded.

module_repository.py imports Django, so its real functions (_fetch_authorized, _stage_licensing_release) are read with ast and run with
stubs (the method of tests/repository-retired-1.17.99.py). licensing_catalogue_source.py and trusted_publishers.py are loaded as they are.
Fakes keep the real keyword-only signatures. Nothing touches the network.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import logging
import re
import ssl
import sys
import tempfile
import types
import urllib.parse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "framwork" / "tec_tac"
REPO_PATH = APP / "module_repository.py"
REPO_TREE = ast.parse(REPO_PATH.read_text(encoding="utf-8"))
SENTINEL = "SENTINEL-BEARER-0123456789abcdef"
ORIGIN = "https://lic.example.test"
REL = "11111111-1111-4111-8111-111111111111"
OTHER_REL = "99999999-9999-4999-8999-999999999999"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def extract(tree, names):
    picked = []
    for node in tree.body:
        is_def = isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
        is_assign = isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets)
        if is_def or is_assign:
            picked.append(node)
    found = {getattr(n, "name", None) or n.targets[0].id for n in picked}
    must(not (set(names) - found), f"not found in source: {sorted(set(names) - found)}")
    return picked


class ModuleStateError(RuntimeError):
    pass


def version_satisfies(version, constraint):
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(version)):
        raise ModuleStateError("bad version")
    return True


class CapabilityOperationError(RuntimeError):
    pass


PROVIDER = {"obj": None}
LOGS: list[str] = []


class _Capture(logging.Handler):
    def emit(self, record):
        LOGS.append(record.getMessage())


logging.getLogger().addHandler(_Capture())
logging.getLogger().setLevel(logging.DEBUG)


def make_package():
    pkg = types.ModuleType("tec_tac")
    pkg.__path__ = [str(APP)]
    sys.modules["tec_tac"] = pkg
    state = types.ModuleType("tec_tac.module_state")
    state.ModuleStateError, state.version_satisfies, state.strip_repository_url = ModuleStateError, version_satisfies, (lambda url: url)
    sys.modules["tec_tac.module_state"] = state
    caps = types.ModuleType("tec_tac.capabilities")
    caps.get_capability = lambda capability_id, *, version=None, required=True, module_id=None: PROVIDER["obj"]
    sys.modules["tec_tac.capabilities"] = caps
    audit = types.ModuleType("tec_tac.audit")
    audit.ROWS, audit.FAIL = [], {"strict": False}

    def record(*, actor, module_id, action, object_type, object_id=None, message=None, before=None, after=None, metadata=None,
               operation_context=None, request=None, correlation_id=None, strict=False, verified_run=None):
        if audit.FAIL["strict"] and strict:
            raise RuntimeError("audit down")
        audit.ROWS.append({"actor": actor, "action": action, "object_type": object_type, "object_id": object_id, "message": message,
                           "metadata": metadata, "strict": strict})
        return {"recorded": True}

    audit.record = record
    audit.service_audit_actor = lambda *, module_id, service, identity=None: f"service:{module_id}:{service}"
    sys.modules["tec_tac.audit"] = audit
    lsu = types.ModuleType("tec_tac.licensing_server_url")
    lsu.get_licensing_server_url = lambda: {"url": ORIGIN, "source": "config", "configured": True, "reason": None}
    sys.modules["tec_tac.licensing_server_url"] = lsu
    loaded = {}
    for name in ("licensing_catalogue_source", "trusted_publishers"):
        spec = importlib.util.spec_from_file_location(f"tec_tac.{name}", APP / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[f"tec_tac.{name}"] = mod
        spec.loader.exec_module(mod)
        loaded[name] = mod
    return loaded["licensing_catalogue_source"], loaded["trusted_publishers"], audit


lcs, tp, AUDIT = make_package()

# ---------------------------------------------------------------------------------------------- real keys, a real trust root, real signatures
TMP = Path(tempfile.mkdtemp(prefix="tectac-licensing-dl-"))
TRUST = TMP / "trust"
KEY = Ed25519PrivateKey.generate()
EVIL_KEY = Ed25519PrivateKey.generate()


def raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


(TRUST / "tech_dev").mkdir(parents=True)
(TRUST / "tech_dev" / "publisher.json").write_text(json.dumps({
    "schema": 1, "publisher_id": "tech_dev", "display_name": "Tech Dev", "status": "trusted", "environment": "development",
    "permissions": ["module.install"], "keys": [{"key_id": "key-1", "status": "active", "algorithm": "Ed25519", "public_key_file": "key-1.pub"}],
}), encoding="utf-8")
(TRUST / "tech_dev" / "key-1.pub").write_text("ed25519:" + base64.b64encode(raw_public(KEY)).decode(), encoding="utf-8")

PACKAGE = b"PK\x03\x04 pretend zip bytes " + b"x" * 200
SHA = hashlib.sha256(PACKAGE).hexdigest()
FILENAME, SIGNAME, METANAME = "welcome-1.2.11.zip", "welcome-1.2.11.zip.sig", "welcome-1.2.11.release.json"


def sign(data, key=KEY):
    return ("ed25519:" + base64.b64encode(key.sign(data)).decode()).encode()


def metadata(**over):
    value = {"schema": 1, "algorithm": "Ed25519", "filename": FILENAME, "signature": SIGNAME, "sha256": SHA, "publisher_id": "tech_dev",
             "key_id": "key-1", "environment": "development"}
    value.update(over)
    return json.dumps(value).encode()


def verify(**kwargs):
    return tp.verify_release_files(**kwargs, trust_root=TRUST, server_environment="development")


RELEASE = {"id": "welcome", "version": "1.2.11", "release_id": REL, "sha256": SHA, "publisher_id": "tech_dev", "key_id": "key-1", "channel": "development"}
PATHS = {"package": f"/api/v1/servers/modules/artifacts/{REL}/{FILENAME}", "signature": f"/api/v1/servers/modules/artifacts/{REL}/{SIGNAME}",
         "release_metadata": f"/api/v1/servers/modules/artifacts/{REL}/{METANAME}"}


class HttpErr(RuntimeError):
    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status = status


class Net:
    """The fake Licensing Server: per-path answers (bytes, or an exception), a log of every request."""

    def __init__(self, answers=None, grants=None):
        self.answers = dict(answers if answers is not None else self.good())
        self.requests, self.grants_asked = [], 0
        self.grants = grants

    @staticmethod
    def good():
        return {PATHS["release_metadata"]: metadata(), PATHS["signature"]: sign(PACKAGE), PATHS["package"]: PACKAGE}

    def fetch(self, url, maximum, *, bearer, timeout):
        self.requests.append({"url": url, "bearer": bearer, "maximum": maximum, "timeout": timeout})
        path = url[len(ORIGIN):]
        answer = self.answers.get(path)
        if isinstance(answer, list):                    # a sequence: one answer per call
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        if isinstance(answer, BaseException):
            raise answer
        if answer is None:
            raise HttpErr(404)
        must(len(answer) <= maximum, "size cap")
        return answer

    def grant(self, release_id, channel):
        self.grants_asked += 1
        return "ok", {"artifact_access_token": SENTINEL, "expires_in_seconds": 300, "artifacts": dict(PATHS)}


def run(net, *, release=RELEASE, verify_fn=verify, clock=None, channel="development"):
    tmp = Path(tempfile.mkdtemp(dir=TMP, prefix="job-"))
    kwargs = {"clock": clock} if clock else {}
    files = lcs.download_release(release=release, channel=channel, fetch=net.fetch, origin=ORIGIN, tmp=tmp, max_package_bytes=1024 * 1024,
                                 grant_fn=net.grant, verify=verify_fn, **kwargs)
    return files, tmp


def refused(net, state, **kw):
    try:
        run(net, **kw)
    except lcs.LicensingSourceError as exc:
        must(exc.state == state, (exc.state, state))
        must(SENTINEL not in str(exc) and SENTINEL not in repr(exc.args), "the bearer is in an exception")
        return exc
    raise AssertionError(f"expected {state}")


# ---------------------------------------------------------------------------------------------- 1. the good path
net = Net()
files, tmp = run(net)
must(files.filename == FILENAME and files.signature_name == SIGNAME and files.metadata_name == METANAME, (files.filename, files.signature_name))
must(files.package.read_bytes() == PACKAGE and files.sha256 == SHA, "package bytes")
must(files.trust["signed"] and files.trust["verified"] and files.trust["trusted"] and files.trust["publisher_id"] == "tech_dev", files.trust)
must([r["url"] for r in net.requests] == [ORIGIN + PATHS["release_metadata"], ORIGIN + PATHS["signature"], ORIGIN + PATHS["package"]], net.requests)
must(all(r["bearer"] == SENTINEL and r["url"].startswith(ORIGIN + "/api/v1/servers/modules/artifacts/") for r in net.requests), "every fetch is on the pinned origin with the bearer")
must(net.requests[0]["maximum"] <= 256 * 1024 and net.requests[1]["maximum"] <= 16 * 1024 and net.requests[2]["maximum"] == 1024 * 1024, "size caps")
must(all(0 < r["timeout"] <= 60 for r in net.requests), "time limits")
must(net.grants_asked == 1, "one grant")
print("       good path: grant, three relative paths on the pinned origin with the bearer, size caps, time limits, real signature verified")

# the file name comes from release.json, never from the URL
alt = {k: v.replace(FILENAME, "x.zip").replace(SIGNAME, "x.zip.sig").replace(METANAME, "x.release.json") for k, v in PATHS.items()}


class AltNet(Net):
    def grant(self, release_id, channel):
        self.grants_asked += 1
        return "ok", {"artifact_access_token": SENTINEL, "expires_in_seconds": 300, "artifacts": dict(alt)}


net = AltNet({alt["release_metadata"]: metadata(), alt["signature"]: sign(PACKAGE), alt["package"]: PACKAGE})
files, _ = run(net)
must(files.filename == FILENAME and files.package.name == FILENAME and not (files.package.parent / "x.zip").exists(), "the name is bound to release.json")
print("       filename binding: the staged name is release.json's filename, whatever the URL says")

# ---------------------------------------------------------------------------------------------- 2. expiry: one new grant, then stop
net = Net({**Net.good(), PATHS["release_metadata"]: [HttpErr(401), metadata()]})
files, _ = run(net)
must(net.grants_asked == 2 and files.package.read_bytes() == PACKAGE, "one new grant after a 401")
net = Net({**Net.good(), PATHS["signature"]: HttpErr(401)})
refused(net, "grant_expired")
must(net.grants_asked == 2, f"a second 401 stops after the second grant (asked {net.grants_asked})")
tick = [0.0]
net = Net()


def clock():
    tick[0] += 200.0       # every look at the clock is 200 s later: the 300 s grant is used up between two fetches
    return tick[0]


refused(net, "grant_expired", clock=clock)
must(net.grants_asked == 2, "a grant that ran out by its own time is replaced once, then stops")
print("       expiry: HTTP 401 or the grant's own time gets one new grant, a second expiry stops (grant_expired)")

# ---------------------------------------------------------------------------------------------- 3. 401/403/404 and other faults
for status, state in ((403, "download_refused"), (404, "release_not_found"), (500, "download_failed"), (429, "download_failed")):
    net = Net({**Net.good(), PATHS["release_metadata"]: HttpErr(status)})
    refused(net, state)
    must(net.grants_asked == 1, f"{status} is not retried")
net = Net({**Net.good(), PATHS["package"]: OSError("connection reset")})
refused(net, "download_failed")
# a grant refused by the provider is that state
for st in ("not_registered", "licence_revoked", "licence_refused", "channel_not_permitted", "release_not_found", "licensing_unavailable"):
    net = Net()
    net.grant = lambda release_id, channel, st=st: (st, None)
    refused(net, st)
    must(not net.requests, f"{st}: nothing was fetched")
print("       mapping: 403 refused, 404 not found, other faults download_failed (no retry); a provider state stops before any fetch")

# ---------------------------------------------------------------------------------------------- 4. a grant revoked half way leaves nothing behind
net = Net({**Net.good(), PATHS["package"]: HttpErr(403)})
tmp = Path(tempfile.mkdtemp(dir=TMP, prefix="job-"))
try:
    lcs.download_release(release=RELEASE, channel="development", fetch=net.fetch, origin=ORIGIN, tmp=tmp, max_package_bytes=1024 * 1024, grant_fn=net.grant, verify=verify)
    raise AssertionError("must refuse")
except lcs.LicensingSourceError as exc:
    must(exc.state == "download_refused", exc.state)
must(list(tmp.iterdir()) == [], "a revoked grant mid-download leaves no file")
must(len(net.requests) == 3, "metadata and signature were fetched, the package was refused")
print("       revoked grant mid-download: download_refused, nothing written")

# ---------------------------------------------------------------------------------------------- 5. tampering
# a changed package (the catalogue SHA no longer matches)
bad = PACKAGE + b"!"
refused(Net({**Net.good(), PATHS["package"]: bad}), "release_mismatch")
# a changed release.json SHA (differs from the catalogue)
refused(Net({**Net.good(), PATHS["release_metadata"]: metadata(sha256="b" * 64)}), "release_mismatch")
# the catalogue SHA and release.json agree with a swapped package, but the signature was made over the real one: Core's own check fails
swapped_sha = hashlib.sha256(bad).hexdigest()
swapped_release = {**RELEASE, "sha256": swapped_sha}
refused(Net({**Net.good(), PATHS["package"]: bad, PATHS["release_metadata"]: metadata(sha256=swapped_sha)}), "verification_failed", release=swapped_release)
# signed by a key that is not the trusted one
refused(Net({**Net.good(), PATHS["signature"]: sign(PACKAGE, EVIL_KEY)}), "verification_failed")
# an unknown publisher, an unknown key, a revoked key
refused(Net({**Net.good(), PATHS["release_metadata"]: metadata(publisher_id="stranger")}), "release_mismatch")
refused(Net({**Net.good(), PATHS["release_metadata"]: metadata(key_id="key-2")}), "release_mismatch")
unknown_release = {**RELEASE, "publisher_id": "stranger"}
refused(Net({**Net.good(), PATHS["release_metadata"]: metadata(publisher_id="stranger")}), "verification_failed", release=unknown_release)
# unsigned: release.json without a signature name, a signature that is not ed25519, an unsigned verdict
refused(Net({**Net.good(), PATHS["release_metadata"]: json.dumps({"schema": 1, "filename": FILENAME, "sha256": SHA}).encode()}), "verification_failed")
refused(Net({**Net.good(), PATHS["signature"]: b"not a signature"}), "verification_failed")
refused(Net(), "verification_failed", verify_fn=lambda **kw: {"signed": False, "verified": False, "trusted": False, "state": "unsigned"})
refused(Net(), "release_mismatch", verify_fn=lambda **kw: {"signed": True, "verified": True, "trusted": True, "package_sha256": "c" * 64})
calls = []
refused(Net(), "verification_failed", verify_fn=lambda **kw: calls.append(kw) or (_ for _ in ()).throw(tp.PublisherTrustError("no", code="signature_required")))
must(calls and calls[0]["require_signed"] is True, "require_signed=True is always passed")
# release.json that is not JSON, not an object, or has an unusable file name
for body in (b"\xff\xfe", b"[]", b"{}"):
    refused(Net({**Net.good(), PATHS["release_metadata"]: body}), "verification_failed")
print("       tampering: changed package, changed release.json, wrong or unknown key, publisher differing from the catalogue, unsigned: all refused; require_signed=True")

# ---------------------------------------------------------------------------------------------- 6. filename binding
for evil in ("../evil.zip", "evil.exe", "a/b.zip", "a\\b.zip", "..zip", ".zip", "x" * 200 + ".zip", "evil.zip ", ""):
    refused(Net({**Net.good(), PATHS["release_metadata"]: metadata(filename=evil)}), "verification_failed")
for evil in ("../s.sig", "s.exe", "a/b.sig", ""):
    refused(Net({**Net.good(), PATHS["release_metadata"]: metadata(signature=evil)}), "verification_failed")
print("       filename binding: a path, a dot segment, a wrong suffix or an over-long name is refused")

# ---------------------------------------------------------------------------------------------- 7. the grant itself
class GrantProvider:
    def __init__(self, answer):
        self.answer = answer

    def module_catalogue(self, *, channel=None):
        raise AssertionError("not here")

    def download_grant(self, *, release_id, channel=None):
        return self.answer


def grant_answer(**over):
    value = {"ok": True, "state": "ok", "message": "Done.", "release_id": REL, "channel": "development", "expires_in_seconds": 300,
             "artifact_access_token": SENTINEL, "artifacts": dict(PATHS)}
    value.update(over)
    return value


PROVIDER["obj"] = GrantProvider(grant_answer())
state, grant = lcs.request_grant(REL, "development")
must(state == "ok" and grant["artifacts"] == PATHS and grant["expires_in_seconds"] == 300, (state, grant))
for label, answer in (
    ("an absolute address", grant_answer(artifacts={**PATHS, "package": "https://evil.example.test/p.zip"})),
    ("a scheme-relative address", grant_answer(artifacts={**PATHS, "package": "//evil.example.test/api/v1/servers/modules/artifacts/x"})),
    ("another release", grant_answer(artifacts={**PATHS, "package": f"/api/v1/servers/modules/artifacts/{OTHER_REL}/{FILENAME}"})),
    ("a dot segment", grant_answer(artifacts={**PATHS, "package": f"/api/v1/servers/modules/artifacts/{REL}/../x.zip"})),
    ("a query", grant_answer(artifacts={**PATHS, "package": PATHS["package"] + "?a=b"})),
    ("a missing path", grant_answer(artifacts={"package": PATHS["package"]})),
    ("a short token", grant_answer(artifact_access_token="short")),
    ("a token with a line break", grant_answer(artifact_access_token="abcdefgh\r\nX-Evil: 1")),
    ("no token", grant_answer(artifact_access_token=None)),
    ("a bad lifetime", grant_answer(expires_in_seconds=0)),
    ("a text lifetime", grant_answer(expires_in_seconds="300")),
    ("not ok", grant_answer(ok=False)),
    ("garbage", ["x"]),
):
    PROVIDER["obj"] = GrantProvider(answer)
    state, grant = lcs.request_grant(REL, "development")
    must(state == "invalid_response" and grant is None, (label, state))
PROVIDER["obj"] = GrantProvider({"ok": False, "state": "licence_revoked", "message": "x"})
must(lcs.request_grant(REL, None) == ("licence_revoked", None), "a provider state passes through")
print("       grant: another host, another release, a dot segment, a query, a bad token or lifetime is refused before any fetch")

# ---------------------------------------------------------------------------------------------- 8. _fetch_authorized: pinned, no redirect, no leak
class ModuleRepositoryError(RuntimeError):
    pass


class RepositoryHttpError(ModuleRepositoryError):
    def __init__(self, message, status):
        super().__init__(message)
        self.status = int(status)


SEEN = []
NEXT = {"answer": (200, None, b"body")}


def fake_pinned_get(url, address, *, maximum, timeout, extra_headers=None):
    SEEN.append({"url": url, "address": str(address), "headers": dict(extra_headers or {}), "maximum": maximum, "timeout": timeout})
    answer = NEXT["answer"]
    if isinstance(answer, BaseException):
        raise answer
    return answer


def fake_resolve(value, *, trust="custom"):
    parsed = urllib.parse.urlparse(value)
    if parsed.hostname in ("localhost", "127.0.0.1"):
        raise ModuleRepositoryError("prohibited")
    return value, parsed, (ipaddress.ip_address("203.0.113.10"),)


ns = {"ipaddress": ipaddress, "urllib": urllib, "ssl": ssl, "http": http, "ModuleRepositoryError": ModuleRepositoryError,
      "RepositoryHttpError": RepositoryHttpError, "_pinned_get": fake_pinned_get, "_resolve_remote_url": fake_resolve,
      "_proxy_url_for": lambda parsed: None, "_pinned_proxy_get": lambda *a, **k: (_ for _ in ()).throw(AssertionError("no proxy here"))}
exec(compile(ast.Module(body=extract(REPO_TREE, {"_fetch_authorized"}), type_ignores=[]), str(REPO_PATH), "exec"), ns)  # noqa: S102 - test only
fetch = ns["_fetch_authorized"]
URL = ORIGIN + PATHS["package"]
NEXT["answer"] = (200, None, b"hello")
must(fetch(URL, 100, bearer=SENTINEL, timeout=30) == b"hello", "a 200 returns the body")
must(SEEN[-1]["headers"] == {"Authorization": f"Bearer {SENTINEL}"} and SEEN[-1]["address"] == "203.0.113.10" and SEEN[-1]["maximum"] == 100, SEEN[-1])
for status in (301, 302, 303, 307, 308):
    SEEN.clear()
    NEXT["answer"] = (status, "https://evil.example.test/steal", b"")
    try:
        fetch(URL, 100, bearer=SENTINEL, timeout=30)
        raise AssertionError("a redirect was followed or ignored")
    except RepositoryHttpError as exc:
        must(exc.status == status and "redirect" in str(exc) and SENTINEL not in str(exc), exc)
    must(len(SEEN) == 1 and "evil" not in SEEN[0]["url"], "the redirect target was never contacted")
for status in (401, 403, 404, 500):
    NEXT["answer"] = (status, None, b"")
    try:
        fetch(URL, 100, bearer=SENTINEL, timeout=30)
        raise AssertionError(status)
    except RepositoryHttpError as exc:
        must(exc.status == status and SENTINEL not in str(exc), exc)
for fault in (OSError("reset"), ssl.SSLError("tls"), http.client.HTTPException("bad")):
    NEXT["answer"] = fault
    try:
        fetch(URL, 100, bearer=SENTINEL, timeout=30)
        raise AssertionError("a network fault must raise")
    except ModuleRepositoryError as exc:
        must(not isinstance(exc, RepositoryHttpError) and SENTINEL not in str(exc) and SENTINEL not in repr(exc.__context__) and SENTINEL not in repr(exc.__cause__), exc)
SEEN.clear()
try:
    fetch("http://lic.example.test/api/v1/servers/modules/artifacts/x", 100, bearer=SENTINEL, timeout=30)
    raise AssertionError("plain http must be refused")
except ModuleRepositoryError:
    must(SEEN == [], "nothing was sent over plain http")
try:
    fetch("https://127.0.0.1/x", 100, bearer=SENTINEL, timeout=30)
    raise AssertionError("a local address must be refused")
except ModuleRepositoryError:
    must(SEEN == [], "nothing was sent to a local address")
SRC = REPO_PATH.read_text(encoding="utf-8")
must("urlopen" not in SRC and "allow_redirects" not in SRC.replace("# ", ""), "the fetch is the pinned one; redirects are not followed by any library")
must(SRC.count("Bearer {") == 1, "the bearer header is built in one place")
print("       fetch: pinned address, bearer in the header only, a redirect to another host is refused and never contacted, plain http and local addresses refused, no bearer in any error")

# ---------------------------------------------------------------------------------------------- 9. _stage_licensing_release end to end
STAGE_CALLS = {"stage": [], "discard": [], "provenance": []}
TRUST_RESULT = {"value": None}


def stage_uploaded_artifact(upload, signature_upload=None, metadata_upload=None):
    STAGE_CALLS["stage"].append({"name": upload.name, "signature": signature_upload.name, "metadata": metadata_upload.name,
                                 "size": upload.size, "bytes": Path(upload.path).read_bytes()})
    return {"upload_id": "up-1", "kind": "package", "preview": {"id": "welcome", "extension_version": "1.2.11"},
            "publisher_trust": TRUST_RESULT["value"] or {"signed": True, "verified": True, "trusted": True, "publisher_id": "tech_dev"}}


class StubLog:
    def warning(self, message, *args, **kwargs):
        LOGS.append(message % args if args else message)


class LicensingRequirementError(RuntimeError):
    pass


ns2 = {
    "__name__": "tec_tac.module_repository", "__package__": "tec_tac", "Path": Path, "tempfile": tempfile, "json": json,
    "ModuleRepositoryError": ModuleRepositoryError, "LicensingRequirementError": LicensingRequirementError, "_lcs": lcs,
    "MAX_PACKAGE_BYTES": 1024 * 1024, "stage_uploaded_artifact": stage_uploaded_artifact,
    "discard_v2_stage": lambda upload_id: STAGE_CALLS["discard"].append(upload_id),
    "attach_source_provenance": lambda upload_id, source: STAGE_CALLS["provenance"].append((upload_id, source)),
    "strip_repository_url": lambda url: url, "_utcnow": lambda: "2026-11-03T00:00:00+00:00", "logger": StubLog(),
    "_fetch_authorized": lambda url, maximum, *, bearer, timeout=30: NETREF["net"].fetch(url, maximum, bearer=bearer, timeout=timeout),
}
NETREF = {"net": None}
exec(compile(ast.Module(body=extract(REPO_TREE, {"_PathUpload", "_licensing_audit", "_stage_licensing_release"}), type_ignores=[]), str(REPO_PATH), "exec"), ns2)  # noqa: S102 - test only
# the real default verify is replaced by one that uses the test's trust root; everything else is the real code path
real_download = lcs.download_release
lcs.download_release = lambda **kw: real_download(**kw, verify=verify) if "verify" not in kw else real_download(**kw)
stage = ns2["_stage_licensing_release"]
REPO = {"id": "tec-tac-licensing", "name": "Licensed", "trust": "official", "kind": "licensing", "channel": "development"}
request = types.SimpleNamespace(user="a-person")


class FullProvider:
    def __init__(self, net):
        self.net = net
        self.grants = 0

    def module_catalogue(self, *, channel=None):
        raise AssertionError("not here")

    def download_grant(self, *, release_id, channel=None):
        self.grants += 1
        return grant_answer(release_id=release_id)


def staging(net, **kw):
    NETREF["net"] = net
    provider = FullProvider(net)
    PROVIDER["obj"] = provider
    for key in STAGE_CALLS:
        STAGE_CALLS[key].clear()
    AUDIT.ROWS.clear()
    LOGS.clear()
    return provider, stage(REPO, "tec-tac-licensing", "welcome", dict(RELEASE), request=request, **kw)


provider, staged = staging(Net())
call = STAGE_CALLS["stage"][0]
must(call["name"] == FILENAME and call["signature"] == SIGNAME and call["metadata"] == METANAME and call["bytes"] == PACKAGE, call)
must(staged["source"]["licensed"] is True and staged["source"]["release_id"] == REL and staged["source"]["package_sha256"] == SHA, staged["source"])
must(STAGE_CALLS["provenance"][0][0] == "up-1" and STAGE_CALLS["discard"] == [], "provenance attached, nothing discarded")
rows = AUDIT.ROWS
must([r["metadata"]["result"] for r in rows] == ["started", "staged"] and rows[0]["strict"] is True and rows[1]["strict"] is False, rows)
must(all(r["actor"] == "a-person" and r["action"] == "run" and r["object_type"] == "licensed_module_release" and r["object_id"] == REL for r in rows), rows)
must(provider.grants == 1, "one grant")
everything = json.dumps([rows, staged, LOGS], default=str)
must(SENTINEL not in everything, "the bearer is in an audit row, a log line or the answer")
print("       staging: the existing staging gets the release.json file name and both sidecars; provenance names the release; two audit rows, the first strict; no bearer anywhere")

# the audit row is first: no row, no grant, no fetch
AUDIT.FAIL["strict"] = True
net = Net()
NETREF["net"] = net
PROVIDER["obj"] = provider = FullProvider(net)
try:
    stage(REPO, "tec-tac-licensing", "welcome", dict(RELEASE), request=request)
    raise AssertionError("must fail closed")
except ModuleRepositoryError as exc:
    must("audit record" in str(exc), str(exc))
must(provider.grants == 0 and net.requests == [], "no audit row, no grant, no fetch")
AUDIT.FAIL["strict"] = False
print("       audit first: when the strict row cannot be written nothing is asked or fetched")

# an unsigned or unverified staged result is discarded and refused; so is a different module or version
for label, trust, preview, state in (
    ("unsigned", {"signed": False, "verified": False}, None, "verification_failed"),
    ("not verified", {"signed": True, "verified": False}, None, "verification_failed"),
    ("no trust at all", {}, None, "verification_failed"),
):
    TRUST_RESULT["value"] = trust or {"x": 1}
    try:
        staging(Net())
        raise AssertionError(label)
    except ModuleRepositoryError as exc:
        must(str(exc) == lcs.message_for(state), (label, str(exc)))
    must(STAGE_CALLS["discard"] == ["up-1"] and STAGE_CALLS["provenance"] == [], f"{label}: the staged copy was not discarded")
    must(AUDIT.ROWS[-1]["metadata"]["result"] == state and SENTINEL not in json.dumps(AUDIT.ROWS), label)
TRUST_RESULT["value"] = None


def wrong_identity(upload, signature_upload=None, metadata_upload=None):
    return {"upload_id": "up-2", "kind": "package", "preview": {"id": "welcome", "extension_version": "9.9.9"},
            "publisher_trust": {"signed": True, "verified": True, "trusted": True}}


ns2["stage_uploaded_artifact"] = wrong_identity
try:
    staging(Net())
    raise AssertionError("a different version must be refused")
except ModuleRepositoryError as exc:
    must(str(exc) == lcs.message_for("release_mismatch"), str(exc))
must(STAGE_CALLS["discard"] == ["up-2"], "the mismatching copy was discarded")
ns2["stage_uploaded_artifact"] = stage_uploaded_artifact
# a download that fails leaves nothing staged and ends with a state row, never a token
for status, state in ((403, "download_refused"), (404, "release_not_found")):
    try:
        staging(Net({**Net.good(), PATHS["package"]: HttpErr(status)}))
        raise AssertionError(status)
    except ModuleRepositoryError as exc:
        must(str(exc) == lcs.message_for(state), str(exc))
    must(STAGE_CALLS["stage"] == [] and AUDIT.ROWS[-1]["metadata"]["result"] == state, (status, AUDIT.ROWS))
    must(SENTINEL not in json.dumps([AUDIT.ROWS, LOGS], default=str), "the bearer is in a row or a log line after a failure")
print("       staging: an unsigned, unverified or mismatching result is discarded and refused; a failed download stages nothing and records the state only")

# ---------------------------------------------------------------------------------------------- 10. static: one bearer variable, no logging of it, nothing slow in a request path, docs
SOURCE = (APP / "licensing_catalogue_source.py").read_text(encoding="utf-8")
must(not re.search(r"(logger|log|print)\w*\.?\w*\([^)]*(token|bearer)", SOURCE, re.IGNORECASE), "the source logs a token or bearer")
must("exc_info" not in SOURCE and "logger.exception" not in SOURCE, "no traceback logging in the source")
must(not re.search(r'f"[^"]*\{token\}', SOURCE) and "str(exc)" not in SOURCE, "the source puts a token or an exception text in a message")
must('"artifact_access_token"' not in SRC and "access_token" not in SRC, "module_repository.py never touches the token (only licensing_catalogue_source.py does)")
must(SOURCE.count("grant.pop(\"artifact_access_token\"") == 1, "the bearer is removed from the grant object")
VIEWS = (APP / "module_repository_views.py").read_text(encoding="utf-8")
must("online_catalog()" in VIEWS and "licensing_catalogue_source" not in VIEWS and "get_capability" not in VIEWS, "the catalogue GET reads the cache only")
CAT = ast.get_source_segment(SRC, next(n for n in REPO_TREE.body if isinstance(n, ast.FunctionDef) and n.name == "online_catalog"))
must("_lcs" not in CAT and "fetch" not in CAT and "sync_" not in CAT, "online_catalog makes no provider call, no fetch and no sync")
print("       static: the bearer lives in one variable, is popped from the grant, never reaches module_repository.py, a log line or a message; the catalogue GET reads the cache only")
print("[TEST] PASS licensing download 1.17.103")

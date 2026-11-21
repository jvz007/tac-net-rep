#!/usr/bin/env python3
"""1.18.37 regression: core.agent_downloads 1.0.0 (grant_download, revoke_download) and the route GET /api/tfd/agent-downloads/<token>/.

No Django, no sockets, no Redis: the harness of the endpoint transport tests stubs the cache, the caller identity, Tactical's token model and
the audit writer, and this file adds stubs for the module registry, the layout, the settings and Django's response classes. The REAL
agent_downloads.py, agent_download_views.py and endpoint_transport.py run. Covered: the caller rule, every invalid reason, the ttl clamp, the
hash-only cache, one grant per device and file, cache, host and audit faults, the audit rows, revoke, the download route (identity, other
device, expiry, changed file, symlink, load cap, strict audit, no redirect, no token in any log, key, row or header), and the catalog.
"""
from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.util
import json
import logging
import os
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
must, CACHE, AUDITS, WALL, ROOT, APP = H.must, H.CACHE, H.AUDITS, H.WALL, H.ROOT, H.APP

# ------------------------------------------------------------------------------------------------ extra stubs
H.FakeCache.decr = lambda self, key: (self._check(), self.data.__setitem__(key, self.data[key] - 1), self.data[key])[2] if key in self.data else (_ for _ in ()).throw(ValueError("missing"))

SETTINGS = SimpleNamespace(ALLOWED_HOSTS=["rmm-api.example.com"])
H.stub("django")
H.stub("django.conf", settings=SETTINGS)


class FakeHttpResponse:
    def __init__(self, content=b"", status=200, **kw):
        self.content, self.status_code, self.headers = content, status, {}

    def __setitem__(self, key, value):
        self.headers[key] = value

    def __getitem__(self, key):
        return self.headers[key]

    def __contains__(self, key):
        return key in self.headers

    def close(self):
        pass


class FakeFileResponse(FakeHttpResponse):
    def __init__(self, handle, *args, content_type=None, **kw):
        super().__init__(b"", 200)
        self.handle, self.headers["Content-Type"] = handle, content_type

    def read(self):
        return self.handle.read()

    def close(self):
        self.handle.close()


H.stub("django.http", HttpResponse=FakeHttpResponse, FileResponse=FakeFileResponse)
H.stub("rest_framework.views", APIView=type("APIView", (), {}))
H.stub("rest_framework.permissions", AllowAny=type("AllowAny", (), {}))

TMP = os.path.realpath(tempfile.mkdtemp(prefix="agentdl-"))
PLUGIN_ROOT = os.path.join(TMP, "plugins", "endpoint-agent-management")
STATE_ROOT = os.path.join(TMP, "state")
os.makedirs(os.path.join(PLUGIN_ROOT, "files"))
os.makedirs(os.path.join(STATE_ROOT, "endpoint-agent-management"))
PLUGINS = [SimpleNamespace(plugin_id="endpoint-agent-management", plugin_type="extension", legacy=False, root=Path(PLUGIN_ROOT)),
           SimpleNamespace(plugin_id="halopsa", plugin_type="extension", legacy=False, root=Path(os.path.join(TMP, "plugins", "halopsa")))]
registry_stub = H.stub("tec_tac.registry", discover_plugins=lambda: list(PLUGINS))
config_stub = H.stub("tec_tac.config", load_layout=lambda path=None: {"TEC_TAC_STATE_ROOT": STATE_ROOT})
H.package.registry, H.package.config = registry_stub, config_stub

AUD: list = []
AUD_FAIL = [False]


def record_agent_download(**kw):
    H.ORDER.append("audit:" + kw["action"])
    if AUD_FAIL[0] and kw.get("strict"):
        raise RuntimeError("audit down")
    AUD.append(kw)


H.audit_stub._record_agent_download = record_agent_download
ad = importlib.import_module("tec_tac.agent_downloads")
V = importlib.import_module("tec_tac.agent_download_views")
et = H.et
ad._now = lambda: WALL[0]
MODULE = "endpoint-agent-management"
LOG_RECORDS: list = []


class Capture(logging.Handler):
    def emit(self, record):
        LOG_RECORDS.append(record)


logging.getLogger().addHandler(Capture())
logging.getLogger().setLevel(logging.DEBUG)

MSI_BYTES = b"MSI-bytes-" * 5000
MSI = os.path.join(PLUGIN_ROOT, "files", "agent.msi")
SHA = hashlib.sha256(MSI_BYTES).hexdigest()


def put_file(path=MSI, data=MSI_BYTES):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def reset():
    H.reset()
    AUD.clear()
    AUD_FAIL[0] = False
    LOG_RECORDS.clear()
    SETTINGS.ALLOWED_HOSTS = ["rmm-api.example.com"]
    H.CALLER["module_id"] = MODULE
    ad._islink = os.path.islink
    ad._lstat = os.lstat
    ad._fstat = os.fstat
    et.authenticate_endpoint_agent = ORIGINAL_AUTH
    put_file()
    for path in (MSI, os.path.join(STATE_ROOT, MODULE, "other.msi")):
        if path != MSI and os.path.exists(path):
            os.remove(path)
    WALL[0] = 1_000_000.0


ORIGINAL_AUTH = et.authenticate_endpoint_agent


def grant(agent_id="agentone", path=MSI, sha=SHA, ttl=600, module_id=MODULE):
    return ad.grant_download(module_id, agent_id=agent_id, path=path, sha256=sha, ttl_seconds=ttl)


def token_of(result):
    return result["path"].rstrip("/").rsplit("/", 1)[1]


# ------------------------------------------------------------------------------------------------ grant: caller rule
reset()
for who in ("halopsa", "core", None):
    H.CALLER["module_id"] = who
    result = grant()
    must(result["outcome"] == "denied" and not CACHE.data and not AUD, f"caller {who} is denied and nothing is stored")
H.CALLER["module_id"] = MODULE
must(grant(module_id="halopsa")["outcome"] == "denied" and not CACHE.data, "a module_id that differs from the verified id is denied")
must(ad._PROVIDER.grant_download(module_id="halopsa", agent_id="agentone", path=MSI, sha256=SHA)["outcome"] == "denied", "provider path is verified too")

# ------------------------------------------------------------------------------------------------ grant: every invalid reason
reset()
OTHER_PLUGIN_FILE = os.path.join(TMP, "plugins", "halopsa", "x.msi")
put_file(OTHER_PLUGIN_FILE)
os.makedirs(os.path.join(PLUGIN_ROOT, "dir.msi"), exist_ok=True)
EMPTY = os.path.join(PLUGIN_ROOT, "files", "empty.msi")
put_file(EMPTY, b"")
CASES = [
    ("bad_agent_id", dict(agent_id="bad id!")),
    ("bad_agent_id", dict(agent_id=None)),
    ("bad_sha256", dict(sha="A" * 64)),
    ("bad_sha256", dict(sha="a" * 63)),
    ("bad_ttl", dict(ttl=True)),
    ("bad_ttl", dict(ttl="600")),
    ("bad_ttl", dict(ttl=1.5)),
    ("bad_path", dict(path="files/agent.msi")),
    ("bad_path", dict(path=os.path.join(PLUGIN_ROOT, "files", "..", "files", "agent.msi"))),
    ("bad_path", dict(path=None)),
    ("outside_module_folder", dict(path=OTHER_PLUGIN_FILE)),
    ("outside_module_folder", dict(path=os.path.join(TMP, "elsewhere.msi"))),
    ("not_a_file", dict(path=os.path.join(PLUGIN_ROOT, "dir.msi"))),
    ("not_a_file", dict(path=EMPTY)),
    ("not_a_file", dict(path=os.path.join(PLUGIN_ROOT, "files", "missing.msi"))),
    ("hash_mismatch", dict(sha="0" * 64)),
]
for reason, kwargs in CASES:
    result = grant(**kwargs)
    must(result["outcome"] == "invalid" and result["reason"] == reason, f"{kwargs} -> {reason}, got {result}")
    must(result["url"] is None and not CACHE.data and not AUD, f"{reason}: nothing stored, no row")

# a symlinked file and a symlinked parent (stubbed: symlink creation is restricted on Windows)
ad._islink = lambda p: os.path.normcase(p) == os.path.normcase(MSI)
must(grant()["reason"] == "symlink_refused", "a symlinked file is refused")
ad._islink = lambda p: os.path.normcase(p) == os.path.normcase(os.path.join(PLUGIN_ROOT, "files"))
must(grant()["reason"] == "symlink_refused", "a symlinked parent folder is refused")
ad._islink = os.path.islink
# a path that is not its own real path
ad_real = os.path.realpath
os.path.realpath = lambda p, *a, **k: ad_real(p) + "x" if os.path.normcase(p) == os.path.normcase(MSI) else ad_real(p, *a, **k)
try:
    must(grant()["reason"] == "symlink_refused", "a path that is not its real path is refused")
finally:
    os.path.realpath = ad_real
# size over the cap (stubbed stat)
real_lstat = os.lstat
ad._lstat = lambda p: SimpleNamespace(st_mode=real_lstat(p).st_mode, st_size=100_000_001)
must(grant()["reason"] == "too_large", "100 000 001 bytes is too large")
ad._lstat = real_lstat
# state-root folder is the second allowed root
STATE_FILE = os.path.join(STATE_ROOT, MODULE, "other.msi")
put_file(STATE_FILE)
state_result = grant(path=STATE_FILE)
must(state_result["outcome"] == "ok", f"the state folder is an allowed root: {state_result}")

# ------------------------------------------------------------------------------------------------ grant: success
reset()
result = grant(ttl=100000)
must(result["outcome"] == "ok" and result["expires_in"] == 900, "ttl is clamped to 900")
token = token_of(result)
must(len(token) == 43 and re.fullmatch(r"[A-Za-z0-9_-]{43}", token), "the link token is 43 URL-safe characters")
must(result["url"] == f"https://rmm-api.example.com/api/tfd/agent-downloads/{token}/" and result["path"] == f"/api/tfd/agent-downloads/{token}/", "url and path shape")
must(result["expires"] == "1970-01-12T14:01:40Z" and result["reason"] is None, "expires is ISO 8601 UTC (clock 1000000 + 900 s)")
must(grant(ttl=1)["expires_in"] == 30, "ttl is clamped to 30")
must(grant(ttl=-5)["expires_in"] == 30, "a negative ttl is clamped to 30")
reset()
result = grant()
token = token_of(result)
must(result["expires_in"] == 600, "default ttl is 600")
for key, value in CACHE.data.items():
    must(token not in key and token not in repr(value), "the cache holds the token neither as key nor as value")
must(ad.grant_key(token) in CACHE.data and CACHE.timeouts[ad.grant_key(token)] == 600, "the grant is keyed by the hash of the token with the ttl")
must(ad.grant_key(token) == ad.GRANT_PREFIX + hashlib.sha256(token.encode()).hexdigest(), "grant key is the SHA-256 of the token")
row = AUD[0]
must(len(AUD) == 1 and row["action"] == "custom:agent-download-granted" and row["strict"] is True and row["agent_id"] == "agentone", "one strict grant row")
meta = row["metadata"]
must(meta["requested_by_module"] == MODULE and meta["file"] == "agent.msi" and meta["size"] == len(MSI_BYTES) and meta["sha256"] == SHA, "row names module, file, size, sha")
must(meta["ttl_seconds"] == 600 and meta["replaced"] is False and "expires" in meta, "row names ttl, replaced and expiry")
blob = repr(AUD)
must(token not in blob and "/api/tfd/agent-downloads" not in blob and PLUGIN_ROOT not in blob and TMP not in blob, "row holds no token, link or full path")

# one grant per device and file
second = grant()
must(second["outcome"] == "ok" and token_of(second) != token, "second grant is a new token")
must(ad.grant_key(token) not in CACHE.data, "the first grant is gone")
must(ad.grant_key(token_of(second)) in CACHE.data and AUD[-1]["metadata"]["replaced"] is True, "the second is live and the row says replaced")
other_device = grant(agent_id="agenttwo")
put_file(STATE_FILE)
other_file = grant(path=STATE_FILE)
must(ad.grant_key(token_of(second)) in CACHE.data and ad.grant_key(token_of(other_device)) in CACHE.data and ad.grant_key(token_of(other_file)) in CACHE.data,
     "a different device or file keeps its own grant")

# faults
reset()
CACHE.down = True
must(grant()["outcome"] == "unavailable" and not AUD, "cache down -> unavailable")
CACHE.down = False
must(not CACHE.data, "nothing stored after a cache fault")
for hosts in (["*"], [], [".example.com"], ["bad host"], [None]):
    SETTINGS.ALLOWED_HOSTS = hosts
    result = grant()
    must(result["outcome"] == "unavailable" and result["reason"] == "host_unavailable" and not CACHE.data and not AUD, f"hosts {hosts} -> unavailable")
SETTINGS.ALLOWED_HOSTS = ["rmm-api.example.com:8443"]
must(grant()["url"].startswith("https://rmm-api.example.com:8443/"), "a host with a port is kept")
reset()
AUD_FAIL[0] = True
result = grant()
must(result["outcome"] == "unavailable" and result["reason"] == "audit_unavailable" and not CACHE.data, "strict audit failure -> unavailable and nothing stored")
AUD_FAIL[0] = False
first = grant()
AUD_FAIL[0] = True
must(grant()["outcome"] == "unavailable", "audit failure on a replacement")
must(ad.grant_key(token_of(first)) in CACHE.data and len([k for k in CACHE.data if k.startswith(ad.GRANT_PREFIX)]) == 1, "the earlier grant survives a failed replacement")

# ------------------------------------------------------------------------------------------------ revoke
reset()
must(ad.revoke_download(MODULE, agent_id="agentone", path=MSI) == {"outcome": "ok", "revoked": False} and not AUD, "nothing to revoke: no row")
live = grant()
for who in ("halopsa", "core", None):
    H.CALLER["module_id"] = who
    must(ad.revoke_download(MODULE, agent_id="agentone", path=MSI)["outcome"] == "denied", f"revoke denied for {who}")
H.CALLER["module_id"] = "halopsa"
must(ad.revoke_download("halopsa", agent_id="agentone", path=MSI) == {"outcome": "ok", "revoked": False}, "another module cannot revoke the grant of this one")
H.CALLER["module_id"] = MODULE
must(ad.grant_key(token_of(live)) in CACHE.data, "the grant survived the others")
must(ad.revoke_download(MODULE, agent_id="bad id", path=MSI)["outcome"] == "invalid", "invalid agent id")
count = len(AUD)
must(ad._PROVIDER.revoke_download(module_id=MODULE, agent_id="agentone", path=MSI) == {"outcome": "ok", "revoked": True}, "revoke works through the provider")
must(len(AUD) == count + 1 and AUD[-1]["action"] == "custom:agent-download-revoked" and token_of(live) not in repr(AUD[-1]), "one revoke row, no token")
must(not [k for k in CACHE.data if k.startswith((ad.GRANT_PREFIX, ad.SLOT_PREFIX))], "the grant and its slot are gone")
must(ad.revoke_download(MODULE, agent_id="agentone", path=MSI)["revoked"] is False and len(AUD) == count + 1, "a second revoke writes no row")

# ------------------------------------------------------------------------------------------------ the route
TOK = H.TOKEN


def request(token_value=TOK, agent_id="agentone", auth="default", real_ip="203.0.113.9", proto=None, extra=None):
    meta = {"REMOTE_ADDR": real_ip or "10.0.0.1"}
    if auth == "default":
        auth = None if token_value is None else f"Token {token_value}"
    if auth:
        meta["HTTP_AUTHORIZATION"] = auth
    if agent_id is not None:
        meta["HTTP_X_AGENT_ID"] = agent_id
    if proto:
        meta["HTTP_X_FORWARDED_PROTO"] = proto
    meta.update(extra or {})
    return SimpleNamespace(META=meta, method="GET")


def fetch(link_token, **kw):
    return V.AgentDownloadView().get(request(**kw), link_token)


def served_rows():
    return [r for r in AUD if r["action"] == "custom:agent-download-served"]


def ready():
    reset()
    H.add_agent("agentone", TOK, 1)
    H.add_agent("agenttwo", H.TOKEN2, 2)
    return token_of(grant())


link = ready()
response = fetch(link)
body = response.read()
must(response.status_code == 200 and body == MSI_BYTES, "a good request gets the file bytes")
must(response["Content-Length"] == str(len(MSI_BYTES)) and response["Cache-Control"] == "no-store" and response["X-Content-Type-Options"] == "nosniff", "headers")
must("Location" not in response and response["Content-Type"] == "application/octet-stream", "no Location, octet-stream")
must(response["Content-Disposition"] == 'attachment; filename="agent.msi"', "sanitised file name")
must(CACHE.data[ad.INFLIGHT_KEY] == 1, "the slot is held while the response is open")
response.close()
response.close()
must(CACHE.data[ad.INFLIGHT_KEY] == 0, "closing the response releases the slot, once")
rows = served_rows()
must(len(rows) == 1 and rows[0]["strict"] is True and rows[0]["actor"] == "device" and rows[0]["agent_id"] == "agentone", "one strict served row naming the device")
must(rows[0]["metadata"] == {"granting_module": MODULE, "file": "agent.msi", "size": len(MSI_BYTES), "sha256": SHA, "ip": "203.0.113.9"}, "served row metadata")
must(H.ORDER.index("audit:custom:agent-download-served") < len(H.ORDER), "row written")
retry = fetch(link)
must(retry.status_code == 200 and len(served_rows()) == 2, "a retry inside the window works and writes a second row")
retry.close()

# order of the served row against the first byte: the row exists before the response is built
link = ready()
seen = []
real_file_response = V._SlotFileResponse
V._SlotFileResponse = lambda *a, **k: (seen.append(len(served_rows())), real_file_response(*a, **k))[1]
fetch(link).close()
V._SlotFileResponse = real_file_response
must(seen == [1], "the served row is written before the response is built")

# expiry
link = ready()
WALL[0] += 601
r = fetch(link)
must(r.status_code == 404 and r.content == b"" and not served_rows(), "an expired link is 404 and empty")
# unknown and malformed tokens
link = ready()
for bad in ("A" * 43, "short", "x" * 44, "../etc/passwd"):
    r = fetch(bad)
    must(r.status_code == 404 and r.content == b"", f"unknown or malformed link {bad!r} is 404 and empty")
# device B with the grant of device A
r = fetch(link, token_value=H.TOKEN2, agent_id="agenttwo")
must(r.status_code == 404 and r.content == b"" and not served_rows(), "another device's link is 404 and leaks nothing")
must(fetch(link).status_code == 200, "the owner can still use it")

# identity refusals
link = ready()
H.add_agent("agentinactive", "c" * 40, 3, active=False)
H.TOKENS["d" * 40] = H.FakeTokenRow("d" * 40, H.FakeUser("dashboard-user", None))
before = len(AUD)
refusals = [
    request(auth=None, token_value=None),
    request(agent_id=None),
    request(auth="Bearer " + TOK),
    request(auth=f"Token {TOK}, Token {H.TOKEN2}"),
    request(token_value="d" * 40),
    request(token_value="e" * 40),
    request(token_value=H.TOKEN2, agent_id="agentone"),
    request(token_value="c" * 40, agent_id="agentinactive"),
]
for number, req in enumerate(refusals):
    r = V.AgentDownloadView().get(req, link)
    must(r.status_code == 401 and r.content == b"", f"identity refusal {number} is 401 and empty, got {r.status_code}")
must(not served_rows(), "no served row for a refusal")
refused_rows = [r for r in AUD if r["action"] == "custom:agent-download-refused"]
must(len(refused_rows) == 8 and all(r["strict"] is False and r["refusal"] is True for r in refused_rows), "each refusal wrote one non-strict row")
must(all(TOK not in repr(r) and link not in repr(r) for r in refused_rows), "refusal rows hold no token or link")
must(any(k.startswith(et.FAILURE_PREFIX) for k in CACHE.data), "refusals are counted")
# unknown or expired links write no row
before = len(AUD)
fetch("A" * 43)
must(len(AUD) == before, "an unknown link writes no row")

# the failure limit and the plaintext rule
ready()
for _ in range(10):
    must(V.AgentDownloadView().get(request(real_ip="198.51.100.7", agent_id="nobody", token_value="f" * 40), "A" * 43).status_code == 401, "failure")
r = V.AgentDownloadView().get(request(real_ip="198.51.100.7"), "A" * 43)
must(r.status_code == 429 and r.headers["Retry-After"] == "60" and r.content == b"", "the 11th failure from one address is 429")
# a client-chosen X-Real-IP never changes the counted address
ready()
for i in range(10):
    must(V.AgentDownloadView().get(request(real_ip="198.51.100.20", agent_id="nobody", token_value="f" * 40, extra={"HTTP_X_REAL_IP": f"192.0.2.{i + 1}"}), "A" * 43).status_code == 401, "spoofed failure")
r = V.AgentDownloadView().get(request(real_ip="198.51.100.20", agent_id="nobody", token_value="f" * 40, extra={"HTTP_X_REAL_IP": "192.0.2.200"}), "A" * 43)
must(r.status_code == 429, "rotating X-Real-IP does not dodge the failure limit")
must(et.client_ip(V._scope(request(real_ip="198.51.100.21", extra={"HTTP_X_REAL_IP": "192.0.2.5"}))) == "198.51.100.21", "the counted address is REMOTE_ADDR")
link = ready()
r = fetch(link, proto="http")
must(r.status_code == 403 and r.content == b"" and not served_rows(), "plaintext proxy header is 403")
must(fetch(link, proto="https").status_code == 200, "https is fine")

# a transient fault of the identity check
link = ready()
et.authenticate_endpoint_agent = lambda token, agent_id: et._transient()
r = fetch(link)
must(r.status_code == 503 and r.headers["Retry-After"] == "30" and r.content == b"", "a transient identity fault is 503")
must(not any(k.startswith((et.FAILURE_PREFIX, et.AGENT_FAILURE_PREFIX)) for k in CACHE.data), "a transient fault is not counted")
et.authenticate_endpoint_agent = ORIGINAL_AUTH

# the file changes after the grant
link = ready()
put_file(MSI, MSI_BYTES + b"x")
r = fetch(link)
must(r.status_code == 404 and r.content == b"", "a size change is 404")
must(not [k for k in CACHE.data if k.startswith((ad.GRANT_PREFIX, ad.SLOT_PREFIX))] and CACHE.data[ad.INFLIGHT_KEY] == 0, "the grant is gone and the slot is free")
link = ready()
put_file(MSI, bytes(reversed(MSI_BYTES)))
must(fetch(link).status_code == 404 and ad.grant_key(link) not in CACHE.data, "changed bytes: 404 and the grant is gone")
link = ready()
ad._islink = lambda p: os.path.normcase(p) == os.path.normcase(MSI)
must(fetch(link).status_code == 404 and ad.grant_key(link) not in CACHE.data, "a file replaced by a symlink: 404 and the grant is gone")
ad._islink = os.path.islink
link = ready()
os.remove(MSI)
must(fetch(link).status_code == 404, "a removed file is 404")
put_file()

# the load cap
link = ready()
open_responses = []
for _ in range(8):
    r = fetch(link)
    must(r.status_code == 200, "the first 8 are served")
    open_responses.append(r)
r = fetch(link)
must(r.status_code == 503 and r.headers["Retry-After"] == "30" and r.content == b"", "the 9th gets 503")
must(CACHE.data[ad.INFLIGHT_KEY] == 8, "the refused one gave its slot back")
open_responses[0].read()
open_responses[0].close()
must(fetch(link).status_code == 200, "a closed response frees a slot")
must(len(served_rows()) == 9, "served rows only for served downloads")
for r in open_responses[1:]:
    def broken(*args):
        raise OSError("client went away")
    r.handle.read = broken
    try:
        r.read()
    except OSError:
        pass
    r.close()  # a mid-stream failure still ends in close(), which frees the slot
must(CACHE.data[ad.INFLIGHT_KEY] == 1, "every slot of a failed stream came back (one download is still open)")
r = fetch(link)
must(r.status_code == 200, "and the cap is open again")
r.close()

# the cache is down at serve time
link = ready()
CACHE.down = True
r = fetch(link)
CACHE.down = False
must(r.status_code in (401, 503), "a cache fault never serves")

# strict audit failure
link = ready()
AUD_FAIL[0] = True
r = fetch(link)
must(r.status_code == 503 and r.content == b"" and not served_rows() and CACHE.data[ad.INFLIGHT_KEY] == 0, "audit failure: 503, no body, slot free")
AUD_FAIL[0] = False
must(fetch(link).status_code == 200, "the grant survives an audit fault")

# methods, auth classes and source scan
view_src = (APP / "agent_download_views.py").read_text(encoding="utf-8")
must(V.AgentDownloadView.http_method_names == ["get"], "only GET (HEAD, POST and the rest are 405)")
must(V.AgentDownloadView.authentication_classes == [] and V.AgentDownloadView.throttle_classes == [], "no authenticator and no throttle class")
must(V.AgentDownloadView.permission_classes[0].__name__ == "AllowAny", "AllowAny")
must("HttpResponseRedirect" not in view_src and "redirect" not in view_src.lower().replace("never a redirect", "").replace("no redirect", "") and '"Location"' not in view_src,
     "the view has no redirect and sets no Location")
for line in view_src.splitlines():
    if "logger." in line:
        must("token" not in line.lower().replace("agent token", "") and "%s" not in line.replace("(%s)", ""), f"a log call must not take the token: {line.strip()}")
mod_src = (APP / "agent_downloads.py").read_text(encoding="utf-8")
must(not re.search(r"^(import|from)\s+django", mod_src, re.MULTILINE), "no Django import at the top of agent_downloads.py")

# nothing leaked anywhere
SECRETS = (TOK, H.TOKEN2, "Token " + TOK, "Token " + H.TOKEN2)
links = [k[len(ad.GRANT_PREFIX):] for k in CACHE.data if k.startswith(ad.GRANT_PREFIX)]
for record in LOG_RECORDS:
    text = record.getMessage() + (record.exc_text or "") + str(record.args)
    must(not any(s in text for s in SECRETS), "no agent token in any log record")
    must(not re.search(r"[A-Za-z0-9_-]{43}", text), "no link-token-shaped value in any log record")
for row in AUD:
    must(not any(s in repr(row) for s in SECRETS), "no agent token in any audit row")

# ------------------------------------------------------------------------------------------------ catalog, docs and style
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
values = {}
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ("CORE_CONTRACTS", "RULES", "HTTP_CONTRACT_DETAILS"):
        values[node.targets[0].id] = ast.literal_eval(node.value)
rows, rules, http = values["CORE_CONTRACTS"], values["RULES"], values["HTTP_CONTRACT_DETAILS"]
index = {(r["import_path"], r["name"]): r for r in rows}
must(len(index) == len(rows), "no row is listed twice")
NEEDLES = ("1.18.37", "core.agent_downloads", "900", "100 000 000", "symlink", "verified", ">=1.18.37")
for name in ("grant_download", "revoke_download"):
    row = index[("tec_tac.agent_downloads", name)]
    must(row["area"] == "agent-downloads" and row["kind"] == "python" and row["audience"] == "module/backend", f"{name} row fields")
    must(callable(getattr(ad, name)), f"{name} is a real callable")
    for needle in NEEDLES if name == "grant_download" else ("1.18.37", "core.agent_downloads", "verified", ">=1.18.37"):
        must(needle in row["purpose"], f"{name} purpose lacks {needle!r}")
must("Core does not know the file's meaning" in index[("tec_tac.agent_downloads", "grant_download")]["purpose"], "purpose says Core does not know the file's meaning")
urls_src = (APP / "urls.py").read_text(encoding="utf-8")
must('path("agent-downloads/<str:token>/", AgentDownloadView.as_view()' in urls_src, "the route is in urls.py")
detail = http["/api/tfd/agent-downloads/<str:token>/"]["GET"]
must(set(detail["errors"]) >= {"401", "403", "404", "429", "503"} and "agent token" in detail["authorization"] and "redirect" in detail["response"].lower(), "HTTP detail")
must(any("100 000 000" in n for n in detail["notes"]) and any("never logged" in n for n in detail["notes"]), "HTTP detail notes")
must(any(r.startswith("Agent downloads (core.agent_downloads 1.0.0, Core 1.18.37)") for r in rules), "the rule sentence exists")
meta = ad.agent_downloads_contract_metadata()
json.dumps(meta)
must(meta["id"] == "core.agent_downloads" and meta["version"] == "1.0.0" and meta["operations"] == ["grant_download", "revoke_download"] and meta["requires_framework"] == ">=1.18.37", "metadata")
must(meta["limits"]["file_bytes"] == 100_000_000 and meta["limits"]["ttl_seconds"]["max"] == 900 and meta["route"]["path"] == "/api/tfd/agent-downloads/<str:token>/", "metadata limits and route")
for key in ("caller", "roots", "identity", "audit", "errors", "added_in"):
    must(meta.get(key), f"metadata has {key}")
doc = (ROOT / "docs" / "agent-downloads.md").read_text(encoding="utf-8")
for name in ("grant_download", "revoke_download", "core.agent_downloads", "/api/tfd/agent-downloads/<token>/", "100 000 000", "custom:agent-download-granted", "custom:agent-download-served"):
    must(name in doc, f"docs name {name}")
must("core.agent_downloads" in (ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8"), "capabilities.md has a row")
apps_src = (APP / "apps.py").read_text(encoding="utf-8")
block = apps_src[apps_src.index("from .agent_downloads import"):]
must("try:" in apps_src[apps_src.rindex("try:", 0, apps_src.index("from .agent_downloads import")):apps_src.index("from .agent_downloads import")] and "except Exception:" in block[:400], "apps.py registers inside its own try/except")
must("agent_downloads" not in (ROOT / "install.sh").read_text(encoding="utf-8"), "install.sh does not mention it")
must("SERVER_PROVENANCE_AGENT_DOWNLOADS = \"agent-downloads\"" in (APP / "audit.py").read_text(encoding="utf-8") and "def _record_agent_download(" in (APP / "audit.py").read_text(encoding="utf-8"), "audit.py writer")
must("agent_downloads" not in (APP / "endpoint_transport.py").read_text(encoding="utf-8"), "endpoint_transport.py is not edited")

for name in ("framwork/tec_tac/apps.py", "framwork/tec_tac/audit.py", "framwork/tec_tac/contracts.py", "docs/capabilities.md"):
    data = (ROOT / name).read_bytes()
    must(b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings")
for name in ("framwork/tec_tac/agent_downloads.py", "framwork/tec_tac/agent_download_views.py", "framwork/tec_tac/urls.py", "docs/agent-downloads.md", "tests/agent-downloads-1.18.37.py"):
    must(b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings")

print("agent downloads 1.18.37 regression: PASS")

#!/usr/bin/env python3
"""1.18.39 regression: core.agent_downloads 1.1.0 (publish_installer, unpublish_installer) and the public route GET /api/tfd/endpoint-agent/installer.msi.

No Django, no sockets, no Redis: the harness of the endpoint transport tests stubs the cache, the caller identity, Tactical's token model and
the audit writer, and this file adds stubs for the module registry, the layout, Django's response classes, a one-row model manager and a
transaction that rolls the store back. The REAL agent_downloads.py, agent_download_views.py and endpoint_transport.py run. Covered: the
capability version and operations, the publisher rule, every invalid reason, the strict audit row in one transaction with the store, replace,
unpublish, the route (no headers, 404, bytes and headers, tamper, symlink, module removed, own in-flight counter, faults, methods, no audit row
per download) and a static check that the model, migration 0046, urls.py and openapi.py agree.
"""
from __future__ import annotations

import ast
import copy
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
must, CACHE, WALL, ROOT, APP = H.must, H.CACHE, H.WALL, H.ROOT, H.APP

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

# the one-row store and the transaction that restores it when the block raises
STORE: dict = {}
STORE_FAIL = {"read": False, "write": False}
ATOMIC_COUNT = [0]


class FakeRow:
    def __init__(self, data):
        self.__dict__.update(data)


class FakeQuerySet:
    def __init__(self, slot, path=None, sha256=None):
        self.slot, self.path, self.sha256 = slot, path, sha256

    def update(self, **kw):  # 1.18.40: the heal write, filtered on path and sha256 as the real one is
        row = STORE.get(self.slot)
        if row is None or (self.path is not None and row["path"] != self.path) or (self.sha256 is not None and row["sha256"] != self.sha256):
            return 0
        row.update(kw)
        return 1

    def first(self):
        if STORE_FAIL["read"]:
            raise RuntimeError("database down")
        return FakeRow(STORE[self.slot]) if self.slot in STORE else None

    def delete(self):
        STORE.pop(self.slot, None)


class FakeManager:
    @staticmethod
    def filter(slot, path=None, sha256=None):
        return FakeQuerySet(slot, path, sha256)

    @staticmethod
    def update_or_create(slot, defaults):
        if STORE_FAIL["write"]:
            raise RuntimeError("database write failed")
        STORE[slot] = dict(defaults, slot=slot)


class FakeInstallerModel:
    objects = FakeManager()


class FakeAtomic:
    def __enter__(self):
        ATOMIC_COUNT[0] += 1
        self.snapshot = copy.deepcopy(STORE)

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            STORE.clear()
            STORE.update(self.snapshot)
        return False


H.stub("tec_tac.models", TecTacPublishedInstaller=FakeInstallerModel)
sys_django_db = importlib.import_module("django.db")
sys_django_db.transaction = SimpleNamespace(atomic=lambda: FakeAtomic())

TMP = os.path.realpath(tempfile.mkdtemp(prefix="installer-"))
PLUGIN_ROOT = os.path.join(TMP, "plugins", "endpoint-agent-management")
STATE_ROOT = os.path.join(TMP, "state")
os.makedirs(os.path.join(PLUGIN_ROOT, "files"))
os.makedirs(os.path.join(STATE_ROOT, "endpoint-agent-management"))
EAM = SimpleNamespace(plugin_id="endpoint-agent-management", plugin_type="extension", legacy=False, root=Path(PLUGIN_ROOT))
HALO = SimpleNamespace(plugin_id="halopsa", plugin_type="extension", legacy=False, root=Path(os.path.join(TMP, "plugins", "halopsa")))
PLUGINS = [EAM, HALO]
registry_stub = H.stub("tec_tac.registry", discover_plugins=lambda: list(PLUGINS))
config_stub = H.stub("tec_tac.config", load_layout=lambda path=None: {"TEC_TAC_STATE_ROOT": STATE_ROOT})
H.package.registry, H.package.config = registry_stub, config_stub
# 1.18.40: the route asks module_state whether the publisher is enabled; here every module is (the default of the real one)
module_state_stub = H.stub("tec_tac.module_state", load_state=lambda: {}, is_enabled=lambda module_id, state=None: True)
H.package.module_state = module_state_stub

AUD: list = []
AUD_FAIL = [False]


def record_agent_installer(**kw):
    H.ORDER.append("audit:" + kw["action"])
    if AUD_FAIL[0] and kw.get("strict"):
        raise RuntimeError("audit down")
    AUD.append(kw)


def record_agent_download(**kw):
    H.ORDER.append("audit:" + kw["action"])
    AUD.append(kw)


H.audit_stub._record_agent_installer = record_agent_installer
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
MSI = os.path.join(PLUGIN_ROOT, "files", "TecTacAgent-0.1.2.msi")
STATE_MSI = os.path.join(STATE_ROOT, MODULE, "TecTacAgent-0.1.3.MSI")
SHA = hashlib.sha256(MSI_BYTES).hexdigest()
VERSION = "0.1.2"


def put_file(path=MSI, data=MSI_BYTES):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def reset():
    H.reset()
    AUD.clear()
    AUD_FAIL[0] = False
    LOG_RECORDS.clear()
    STORE.clear()
    STORE_FAIL.update(read=False, write=False)
    ATOMIC_COUNT[0] = 0
    PLUGINS[:] = [EAM, HALO]
    H.CALLER["module_id"] = MODULE
    ad._islink = os.path.islink
    ad._lstat = os.lstat
    ad._fstat = os.fstat
    put_file()
    if os.path.exists(STATE_MSI):
        os.remove(STATE_MSI)
    WALL[0] = 1_000_000.0


def publish(path=MSI, sha=SHA, version=VERSION, module_id=MODULE):
    return ad.publish_installer(module_id, path=path, sha256=sha, version=version)


def installer_rows():
    return [r for r in AUD if r["action"].startswith("custom:agent-installer-")]


def request(real_ip="203.0.113.9", proto=None, extra=None):
    meta = {"REMOTE_ADDR": real_ip}
    if proto:
        meta["HTTP_X_FORWARDED_PROTO"] = proto
    meta.update(extra or {})
    return SimpleNamespace(META=meta, method="GET")


def fetch(**kw):
    return V.InstallerDownloadView().get(request(**kw))


# ------------------------------------------------------------------------------------------------ capability version and operations
meta = ad.agent_downloads_contract_metadata()
json.dumps(meta)
must(ad.CAPABILITY_VERSION == "1.1.0" and meta["version"] == "1.1.0", "capability version is 1.1.0")
must(meta["operations"] == ["grant_download", "revoke_download", "publish_installer", "unpublish_installer"], "four operations, the 1.0.0 ones first and unchanged")
must(meta["requires_framework"] == ">=1.18.37", "the top level requirement stays for the old operations")
for name in ("grant_download", "revoke_download"):
    must(meta["operation_versions"][name] == {"added_in": "1.0.0", "requires_framework": ">=1.18.37"}, f"{name} version info")
for name in ("publish_installer", "unpublish_installer"):
    must(meta["operation_versions"][name] == {"added_in": "1.1.0", "requires_framework": ">=1.18.39"}, f"{name} version info")
    must(name in meta["operations_detail"], f"{name} has a detail")
must(meta["installer"]["publishers"] == ["endpoint-agent-management"] and meta["installer"]["route"]["path"] == "/api/tfd/endpoint-agent/installer.msi", "installer block")
must(meta["route"]["path"] == "/api/tfd/agent-downloads/<str:token>/", "the 1.0.0 route entry is unchanged")
must(ad.INSTALLER_PUBLISHERS == ("endpoint-agent-management",), "Core names exactly one publisher")
for op in ("publish_installer", "unpublish_installer"):
    must(callable(getattr(ad._PROVIDER, op)), f"provider has {op}")

# ------------------------------------------------------------------------------------------------ publish: the caller rule
reset()
for who in ("halopsa", "core", None, "nats-comms", "endpoint-comms"):
    H.CALLER["module_id"] = who
    result = publish()
    must(result == {"outcome": "denied", "reason": None} and not STORE and not AUD, f"caller {who} is denied, nothing is stored")
H.CALLER["module_id"] = MODULE
must(publish(module_id="halopsa")["outcome"] == "denied" and not STORE, "a module_id that differs from the verified id is denied")
H.CALLER["module_id"] = "halopsa"
must(publish(module_id="halopsa")["outcome"] == "denied" and not STORE, "a verified module that is not the publisher is denied even for itself")
must(ad._PROVIDER.publish_installer(module_id="halopsa", path=MSI, sha256=SHA, version=VERSION)["outcome"] == "denied", "provider path is verified too")
must(ad._PROVIDER.unpublish_installer(module_id="halopsa")["outcome"] == "denied", "unpublish through the provider is verified too")

# ------------------------------------------------------------------------------------------------ publish: every invalid reason
reset()
OTHER_PLUGIN_FILE = os.path.join(TMP, "plugins", "halopsa", "x.msi")
put_file(OTHER_PLUGIN_FILE)
os.makedirs(os.path.join(PLUGIN_ROOT, "dir.msi"), exist_ok=True)
EMPTY = os.path.join(PLUGIN_ROOT, "files", "empty.msi")
put_file(EMPTY, b"")
EXE = os.path.join(PLUGIN_ROOT, "files", "setup.exe")
put_file(EXE)
BARE = os.path.join(PLUGIN_ROOT, "files", ".msi")
put_file(BARE)
CASES = [
    ("bad_sha256", dict(sha="A" * 64)),
    ("bad_sha256", dict(sha="a" * 63)),
    ("bad_sha256", dict(sha=None)),
    ("bad_version", dict(version="1.2")),
    ("bad_version", dict(version="v1.2.3")),
    ("bad_version", dict(version="1.2.3 ")),
    ("bad_version", dict(version="1.2.3-" + "a" * 40)),
    ("bad_version", dict(version=None)),
    ("bad_version", dict(version=123)),
    ("bad_path", dict(path="files/agent.msi")),
    ("bad_path", dict(path=os.path.join(PLUGIN_ROOT, "files", "..", "files", "TecTacAgent-0.1.2.msi"))),
    ("bad_path", dict(path=None)),
    ("not_msi", dict(path=EXE)),
    ("not_msi", dict(path=BARE)),
    ("outside_module_folder", dict(path=OTHER_PLUGIN_FILE)),
    ("outside_module_folder", dict(path=os.path.join(TMP, "elsewhere.msi"))),
    ("not_a_file", dict(path=os.path.join(PLUGIN_ROOT, "dir.msi"))),
    ("not_a_file", dict(path=EMPTY)),
    ("not_a_file", dict(path=os.path.join(PLUGIN_ROOT, "files", "missing.msi"))),
    ("hash_mismatch", dict(sha="0" * 64)),
]
for reason, kwargs in CASES:
    result = publish(**kwargs)
    must(result == {"outcome": "invalid", "reason": reason}, f"{kwargs} -> {reason}, got {result}")
    must(not STORE and not AUD, f"{reason}: nothing stored, no row")
# a lower-case compare of the extension: .MSI is accepted
put_file(STATE_MSI)
upper = publish(path=STATE_MSI, sha=SHA, version="0.1.3")
must(upper["outcome"] == "ok", f"an upper-case .MSI in the state folder is accepted: {upper}")
reset()
ad._islink = lambda p: os.path.normcase(p) == os.path.normcase(MSI)
must(publish()["reason"] == "symlink_refused" and not STORE, "a symlinked file is refused")
ad._islink = lambda p: os.path.normcase(p) == os.path.normcase(os.path.join(PLUGIN_ROOT, "files"))
must(publish()["reason"] == "symlink_refused" and not STORE, "a symlinked parent folder is refused")
ad._islink = os.path.islink
real_lstat = os.lstat
ad._lstat = lambda p: SimpleNamespace(st_mode=real_lstat(p).st_mode, st_size=100_000_001)
must(publish()["reason"] == "too_large" and not STORE, "100 000 001 bytes is too large")
ad._lstat = real_lstat
PLUGINS[:] = [HALO]
must(publish()["reason"] == "outside_module_folder" and not STORE, "a module that is not installed has no folder")
PLUGINS[:] = [EAM, HALO]

# ------------------------------------------------------------------------------------------------ publish: success and the audit row
reset()
result = publish()
must(result == {"outcome": "ok", "reason": None}, f"publish ok: {result}")
must(STORE["endpoint-agent"]["module_id"] == MODULE and STORE["endpoint-agent"]["path"] == MSI and STORE["endpoint-agent"]["sha256"] == SHA, "the store holds module, path and hash")
must(STORE["endpoint-agent"]["size"] == len(MSI_BYTES) and STORE["endpoint-agent"]["version"] == VERSION, "the store holds size and version")
must(ATOMIC_COUNT[0] == 1, "store and row run inside one transaction")
rows = installer_rows()
must(len(rows) == 1 and rows[0]["action"] == "custom:agent-installer-published" and rows[0]["strict"] is True, "one strict published row")
must(rows[0]["metadata"] == {"published_by_module": MODULE, "file": "TecTacAgent-0.1.2.msi", "size": len(MSI_BYTES), "sha256": SHA, "version": VERSION, "replaced_version": None}, "row metadata")
must(PLUGIN_ROOT not in repr(AUD) and TMP not in repr(AUD) and "installer.msi" not in repr(AUD), "the row holds no full path and no address")
# a second publish replaces the first
put_file(STATE_MSI, b"second-msi" * 3000)
second_sha = hashlib.sha256(b"second-msi" * 3000).hexdigest()
result = publish(path=STATE_MSI, sha=second_sha, version="0.1.3")
must(result["outcome"] == "ok" and len(STORE) == 1 and STORE["endpoint-agent"]["version"] == "0.1.3" and STORE["endpoint-agent"]["path"] == STATE_MSI, "a second publish replaces the first")
must(installer_rows()[-1]["metadata"]["replaced_version"] == "0.1.2" and len(installer_rows()) == 2, "the row names the replaced version")
# audit failure rolls the store back
reset()
publish()
before = copy.deepcopy(STORE)
AUD_FAIL[0] = True
put_file(STATE_MSI, b"third-msi" * 3000)
result = publish(path=STATE_MSI, sha=hashlib.sha256(b"third-msi" * 3000).hexdigest(), version="0.1.4")
must(result == {"outcome": "unavailable", "reason": "audit_unavailable"}, f"a failed strict row is unavailable: {result}")
must(STORE == before, "the earlier installer survives a failed replacement")
AUD_FAIL[0] = False
reset()
AUD_FAIL[0] = True
must(publish()["reason"] == "audit_unavailable" and not STORE, "nothing is stored when the first row cannot be written")
must(fetch().status_code == 404, "and nothing is served afterwards")
AUD_FAIL[0] = False
# store faults
reset()
STORE_FAIL["write"] = True
must(publish() == {"outcome": "unavailable", "reason": "store_unavailable"} and not STORE and not installer_rows(), "a store write fault is unavailable and writes no row")
STORE_FAIL["write"] = False
STORE_FAIL["read"] = True
must(publish()["reason"] == "store_unavailable", "a store read fault is unavailable")
STORE_FAIL["read"] = False

# ------------------------------------------------------------------------------------------------ unpublish
reset()
publish()
count = len(AUD)
for who in ("halopsa", "core", None):
    H.CALLER["module_id"] = who
    must(ad.unpublish_installer(MODULE) == {"outcome": "denied", "unpublished": False}, f"unpublish denied for {who}")
H.CALLER["module_id"] = MODULE
must(ad.unpublish_installer("halopsa")["outcome"] == "denied", "a module_id that differs is denied")
must(STORE and len(AUD) == count, "denied calls changed nothing and wrote no row")
STORE["endpoint-agent"]["module_id"] = "halopsa"
must(ad.unpublish_installer(MODULE) == {"outcome": "ok", "unpublished": False} and STORE and len(AUD) == count, "a file another module published is not removed and writes no row")
STORE["endpoint-agent"]["module_id"] = MODULE
result = ad.unpublish_installer(MODULE)
must(result == {"outcome": "ok", "unpublished": True} and not STORE, f"the owner removes it: {result}")
must(len(AUD) == count + 1 and AUD[-1]["action"] == "custom:agent-installer-unpublished" and AUD[-1]["strict"] is True, "one strict unpublished row")
must(AUD[-1]["metadata"] == {"unpublished_by_module": MODULE, "file": "TecTacAgent-0.1.2.msi", "size": len(MSI_BYTES), "sha256": SHA, "version": VERSION}, "unpublished row metadata")
must(PLUGIN_ROOT not in repr(AUD[-1]), "no full path in the unpublished row")
must(ad.unpublish_installer(MODULE) == {"outcome": "ok", "unpublished": False} and len(AUD) == count + 1, "nothing to remove: ok, unpublished False, no row")
must(fetch().status_code == 404, "after unpublish the route answers 404")
publish()
AUD_FAIL[0] = True
before = copy.deepcopy(STORE)
must(ad.unpublish_installer(MODULE) == {"outcome": "unavailable", "unpublished": False} and STORE == before, "a failed strict row keeps the installer published")
AUD_FAIL[0] = False
STORE_FAIL["read"] = True
must(ad.unpublish_installer(MODULE)["outcome"] == "unavailable", "a store fault is unavailable")
STORE_FAIL["read"] = False

# ------------------------------------------------------------------------------------------------ the route
reset()
r = fetch()
must(r.status_code == 404 and r.content == b"" and "Retry-After" not in r.headers, "nothing published: 404, empty, no Retry-After")
must(publish()["outcome"] == "ok", "published")
count = len(AUD)
r = fetch()  # no Authorization, no X-Agent-Id: none is needed
body = r.read()
must(r.status_code == 200 and body == MSI_BYTES, "a request with no headers gets the exact bytes")
must(r["Content-Length"] == str(len(MSI_BYTES)) and r["Content-Disposition"] == 'attachment; filename="TecTacAgent-0.1.2.msi"', "length and file name")
must(r["X-Content-SHA256"] == SHA and r["Cache-Control"] == "no-store" and r["X-Content-Type-Options"] == "nosniff" and r["Content-Type"] == "application/octet-stream", "hash, cache and type headers")
must("Location" not in r and "Retry-After" not in r, "no redirect and no Retry-After")
must(CACHE.data[ad.INSTALLER_INFLIGHT_KEY] == 1 and ad.INFLIGHT_KEY not in CACHE.data, "the installer's own counter holds the slot")
r.close()
r.close()
must(CACHE.data[ad.INSTALLER_INFLIGHT_KEY] == 0, "closing releases the slot, once")
fetch().close()
fetch().close()
must(len(AUD) == count, "no audit row per download")
must(not any(k.startswith((et.FAILURE_PREFIX, et.AGENT_FAILURE_PREFIX)) for k in CACHE.data), "an anonymous download touches no identity failure counter")
must(fetch(proto="http").status_code == 403 and fetch(proto="http").content == b"", "plain-text proxy header is 403")
must(fetch(proto="https").status_code == 200, "https is fine")

# the file changes after the publish
reset()
publish()
put_file(MSI, MSI_BYTES + b"x")
r = fetch()
must(r.status_code == 404 and r.content == b"" and STORE and CACHE.data[ad.INSTALLER_INFLIGHT_KEY] == 0, "a size change is 404, the row is kept, the slot is free")
put_file(MSI, bytes(reversed(MSI_BYTES)))
os.utime(MSI, ns=(os.stat(MSI).st_mtime_ns + 3_000_000_000,) * 2)  # 1.18.40: a size and mtime match skips the hash, so make the time differ whatever the clock granularity
must(len(bytes(reversed(MSI_BYTES))) == len(MSI_BYTES) and fetch().status_code == 404, "the same size with different bytes is 404")
put_file(MSI)
must(fetch().status_code == 200, "the original bytes serve again (the row was kept)")
ad._islink = lambda p: os.path.normcase(p) == os.path.normcase(MSI)
must(fetch().status_code == 404, "a file replaced by a symlink is 404")
ad._islink = os.path.islink
os.remove(MSI)
must(fetch().status_code == 404, "a removed file is 404")
put_file(MSI)
PLUGINS[:] = [HALO]
must(fetch().status_code == 404, "a publisher that is no longer installed is 404")
PLUGINS[:] = [EAM, HALO]
must(fetch().status_code == 200, "and serves again when it is back")
warning_text = " ".join(rec.getMessage() for rec in LOG_RECORDS if rec.levelno >= logging.WARNING)
must("refused (" in warning_text and TMP not in warning_text and PLUGIN_ROOT not in warning_text, "the reason is logged as a code, never a path")

# the installer counter is separate from the device counter
reset()
publish()
held = []
for _ in range(2):
    r = fetch()
    must(r.status_code == 200, "the first 2 installer downloads are served")
    held.append(r)
r = fetch()
must(r.status_code == 503 and r.headers["Retry-After"] == "30" and r.content == b"", "the 3rd installer download gets 503 with Retry-After 30")
must(CACHE.data[ad.INSTALLER_INFLIGHT_KEY] == 2, "the refused one gave its slot back")
must(ad.acquire_slot() is True, "a device download still gets a slot while the installer is full")
ad.release_slot()
held[0].close()
must(fetch().status_code == 200, "a closed response frees an installer slot")
for r in held[1:]:
    r.close()
reset()
publish()
for _ in range(8):
    must(ad.acquire_slot() is True, "device slots")
must(ad.acquire_slot() is False, "the device counter is full")
r = fetch()
must(r.status_code == 200, "the installer still gets a slot while the device counter is full")
r.close()
for _ in range(8):
    ad.release_slot()
# the optional key leaves the default behaviour as it was
reset()
must(ad.acquire_slot() is True and CACHE.data[ad.INFLIGHT_KEY] == 1 and ad.INSTALLER_INFLIGHT_KEY not in CACHE.data, "the default key is the device counter")
ad.release_slot()
must(CACHE.data[ad.INFLIGHT_KEY] == 0, "release with the default key")

# faults
reset()
publish()
CACHE.down = True
r = fetch()
must(r.status_code == 503 and r.headers["Retry-After"] == "30" and r.content == b"", "a cache fault is 503")
CACHE.down = False
STORE_FAIL["read"] = True
r = fetch()
must(r.status_code == 503 and r.headers["Retry-After"] == "30" and r.content == b"", "a database fault is 503")
STORE_FAIL["read"] = False
real_open = ad.open_verified
ad.open_verified = lambda *a, **k: (_ for _ in ()).throw(OSError("no descriptors"))
r = fetch()
ad.open_verified = real_open
must(r.status_code == 503 and CACHE.data[ad.INSTALLER_INFLIGHT_KEY] == 0, "an unexpected OS error is 503 and frees the slot")
# a broken stream still frees the slot through close()
r = fetch()
r.handle.read = lambda *a: (_ for _ in ()).throw(OSError("client went away"))
try:
    r.read()
except OSError:
    pass
r.close()
must(CACHE.data[ad.INSTALLER_INFLIGHT_KEY] == 0, "a failed stream frees the slot")

# methods, authenticators and source scan
view_src = (APP / "agent_download_views.py").read_text(encoding="utf-8")
must(V.InstallerDownloadView.http_method_names == ["get"], "only GET (HEAD, POST and the rest are 405)")
must(V.InstallerDownloadView.authentication_classes == [] and V.InstallerDownloadView.throttle_classes == [], "no authenticator and no throttle class")
must(V.InstallerDownloadView.permission_classes[0].__name__ == "AllowAny", "AllowAny")
installer_part = view_src[view_src.index("class InstallerDownloadView"):]
must("HttpResponseRedirect" not in installer_part and '"Location"' not in installer_part and "record_served" not in installer_part and "_audit" not in installer_part, "no redirect, no Location, no audit call in the installer view")
for line in installer_part.splitlines():
    if "logger." in line:
        must("path" not in line.lower().replace("agent installer", "") and "%s" not in line.replace("(%s)", ""), f"a log call must not take a path: {line.strip()}")
must("Authorization" not in installer_part and "parse_endpoint_headers" not in installer_part, "the route reads no identity")
for record in LOG_RECORDS:
    must(TMP not in record.getMessage(), "no full path in any log record")

# ------------------------------------------------------------------------------------------------ static: model, migration, urls, openapi, docs, contracts
models_tree = ast.parse((APP / "models.py").read_text(encoding="utf-8"))
model_node = next(n for n in models_tree.body if isinstance(n, ast.ClassDef) and n.name == "TecTacPublishedInstaller")


def call_name(node):
    return node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id


def field_signature(call):
    kwargs = {k.arg: ast.literal_eval(k.value) for k in call.keywords}
    return call_name(call), kwargs


model_fields = {}
for stmt in model_node.body:
    if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
        model_fields[stmt.targets[0].id] = field_signature(stmt.value)
meta_node = next(n for n in model_node.body if isinstance(n, ast.ClassDef) and n.name == "Meta")
model_table = next(ast.literal_eval(s.value) for s in meta_node.body if isinstance(s, ast.Assign) and s.targets[0].id == "db_table")
mig_src = (APP / "migrations" / "0046_published_installer.py").read_text(encoding="utf-8")
mig_tree = ast.parse(mig_src)
mig_fields, mig_options, mig_deps = {}, None, None
for node in ast.walk(mig_tree):
    if isinstance(node, ast.Call) and call_name(node) == "CreateModel":
        must(ast.literal_eval(node.keywords[0].value) == "TecTacPublishedInstaller", "migration creates the model")
        for kw in node.keywords:
            if kw.arg == "fields":
                for tup in kw.value.elts:
                    mig_fields[ast.literal_eval(tup.elts[0])] = field_signature(tup.elts[1])
            if kw.arg == "options":
                mig_options = ast.literal_eval(kw.value)
    if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "dependencies":
        mig_deps = ast.literal_eval(node.value)
must(mig_deps == [("tec_tac", "0045_communicator_service_user_retry")], f"migration depends only on 0045, no floating dependency: {mig_deps}")
must(mig_options == {"db_table": "core_published_installer"} and model_table == "core_published_installer", "table name agrees")
must(mig_fields.pop("id")[0] == "BigAutoField", "the migration creates the default id")
must(mig_fields == {k: v for k, v in model_fields.items() if k != "mtime_ns"}, f"1.18.40: model and migration 0046 agree on the fields 0046 created (0047 adds mtime_ns):\n{model_fields}\n{mig_fields}")
must(model_fields["slot"] == ("CharField", {"max_length": 32, "unique": True}), "slot is unique")
must(set(model_fields) == {"slot", "module_id", "path", "sha256", "size", "version", "mtime_ns", "published_at"}, "the model has the documented fields")
must("auto_now" in model_fields["published_at"][1], "published_at is set on every save")
must(len(list((APP / "migrations").glob("0046_*.py"))) == 1 and len(list((APP / "migrations").glob("0047_*.py"))) == 1, "one 0046 and one 0047")  # 1.18.40: 0047 depends on 0046 (checked in installer-serve-cost-1.18.40.py)
urls_src = (APP / "urls.py").read_text(encoding="utf-8")
must('path("endpoint-agent/installer.msi", InstallerDownloadView.as_view()' in urls_src and "InstallerDownloadView" in urls_src.split("urlpatterns")[0], "the route is in urls.py")
openapi_src = (APP / "openapi.py").read_text(encoding="utf-8")
must('("/api/tfd/endpoint-agent/", "Tec-Tac · Agent Downloads")' in openapi_src, "the OpenAPI group carries the route")
tree = ast.parse((APP / "contracts.py").read_text(encoding="utf-8"))
values = {}
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ("CORE_CONTRACTS", "RULES", "HTTP_CONTRACT_DETAILS"):
        values[node.targets[0].id] = ast.literal_eval(node.value)
index = {(r["import_path"], r["name"]): r for r in values["CORE_CONTRACTS"]}
for name in ("publish_installer", "unpublish_installer"):
    row = index[("tec_tac.agent_downloads", name)]
    must(row["area"] == "agent-downloads" and row["kind"] == "python" and row["audience"] == "module/backend", f"{name} row fields")
    must(callable(getattr(ad, name)), f"{name} is a real callable")
    for needle in ("1.18.39", "core.agent_downloads 1.1.0", ">=1.18.39", "custom:agent-installer-"):
        must(needle in row["purpose"], f"{name} purpose lacks {needle!r}")
must("endpoint-agent-management" in index[("tec_tac.agent_downloads", "publish_installer")]["purpose"], "publish names the one publisher")
detail = values["HTTP_CONTRACT_DETAILS"]["/api/tfd/endpoint-agent/installer.msi"]["GET"]
must(detail["authorization"].startswith("none") and set(detail["errors"]) == {"403", "404", "405", "503"} and "Added in 1.18.39" in " ".join(detail["notes"]), "HTTP detail")
must("X-Content-SHA256" in detail["response"] and "redirect" in detail["response"].lower(), "HTTP detail response")
must(any(r.startswith("Public Endpoint Agent installer (core.agent_downloads 1.1.0, Core 1.18.39, AD-74)") for r in values["RULES"]), "the rule sentence exists")
must(any(r.startswith("Agent downloads (core.agent_downloads 1.0.0, Core 1.18.37)") for r in values["RULES"]), "the 1.0.0 rule sentence is kept")
doc = (ROOT / "docs" / "agent-downloads.md").read_text(encoding="utf-8")
for name in ("publish_installer", "unpublish_installer", "/api/tfd/endpoint-agent/installer.msi", "X-Content-SHA256", "custom:agent-installer-published", "INSTALLER_PUBLISHERS", "0046", "no row"):
    must(name in doc, f"docs name {name}")
must("1.1.0" in (ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8") and "publish_installer" in (ROOT / "docs" / "capabilities.md").read_text(encoding="utf-8"), "capabilities.md has the 1.1.0 line")
apps_src = (APP / "apps.py").read_text(encoding="utf-8")
must("publish_installer" not in apps_src, "apps.py is not edited (the registration passes the four operations itself)")
audit_src = (APP / "audit.py").read_text(encoding="utf-8")
must("def _record_agent_installer(" in audit_src and "strict: bool = True" in audit_src.split("def _record_agent_installer(")[1].split(")")[0], "audit.py has the strict installer writer")
mod_src = (APP / "agent_downloads.py").read_text(encoding="utf-8")
must(not re.search(r"^(import|from)\s+django", mod_src, re.MULTILINE), "no Django import at the top of agent_downloads.py")
for name in ("framwork/tec_tac/audit.py", "framwork/tec_tac/models.py", "framwork/tec_tac/contracts.py", "docs/capabilities.md", "docs/module-audit.md"):
    data = (ROOT / name).read_bytes()
    must(b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings")
for name in ("framwork/tec_tac/agent_downloads.py", "framwork/tec_tac/agent_download_views.py", "framwork/tec_tac/urls.py", "framwork/tec_tac/migrations/0046_published_installer.py",
             "docs/agent-downloads.md", "tests/endpoint-agent-installer-1.18.39.py"):
    must(b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings")
must(b"\r" not in (APP / "openapi.py").read_bytes(), "openapi.py keeps its line endings (LF)")

print("endpoint agent installer 1.18.39 regression: PASS")

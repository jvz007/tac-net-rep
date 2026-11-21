#!/usr/bin/env python3
"""1.18.40 regression: the public installer route is cheap and honours the publisher's state.

Two held findings of the Core 1.18.39 review. (1) The SHA-256 is computed once, at publish, and stored with the size and modified time
(``mtime_ns``, migration 0047); a serve re-hashes only when either differs, heals a row published by 1.18.39, takes its slot BEFORE it reads
the store and has 2 slots (INSTALLER_MAX_INFLIGHT). (2) A disabled publisher module is 404 (the row stays); a state fault is 503.

No Django, no sockets, no Redis: the same stubs as endpoint-agent-installer-1.18.39.py (copied here so each file runs alone) plus a settable
module_state. The REAL agent_downloads.py and agent_download_views.py run.
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
# the route asks module_state whether the publisher is enabled: a settable map, a corrupt flag and a read fault
MS = {"enabled": {}, "corrupt": False, "raises": False, "calls": 0}


def ms_load_state():
    MS["calls"] += 1
    if MS["raises"]:
        raise OSError("state unreadable")
    return {"_corrupt": True} if MS["corrupt"] else {"modules": {}}


def ms_is_enabled(module_id, state=None):
    state = state or ms_load_state()
    if state.get("_corrupt"):
        return False
    return bool(MS["enabled"].get(module_id, True))


module_state_stub = H.stub("tec_tac.module_state", load_state=ms_load_state, is_enabled=ms_is_enabled)
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
    MS.update(enabled={}, corrupt=False, raises=False, calls=0)
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



def mtime_of(path=MSI):
    return os.stat(path).st_mtime_ns


class ReadCounter:
    """Counts os.read calls (the hashing pass) while it is active."""

    def __enter__(self):
        self.real, self.count = os.read, 0

        def counting(fd, n):
            self.count += 1
            return self.real(fd, n)

        os.read = counting
        return self

    def __exit__(self, *exc):
        os.read = self.real
        return False


def slots():
    return CACHE.data.get(ad.INSTALLER_INFLIGHT_KEY, 0)


def serve_ok(expect_reads=None):
    with ReadCounter() as counter:
        r = fetch()
        body = r.read() if r.status_code == 200 else b""
    must(r.status_code == 200 and body == MSI_BYTES, f"serves the exact bytes, got {r.status_code}")
    must(r["Content-Length"] == str(len(MSI_BYTES)) and r["X-Content-SHA256"] == SHA and r["Cache-Control"] == "no-store", "headers")
    if expect_reads == 0:
        must(counter.count == 0, f"no hashing pass, got {counter.count} os.read calls")
    elif expect_reads is not None:
        must(counter.count >= 1, "a hashing pass ran")
    r.close()
    must(slots() == 0, "the slot is free after close")
    return counter.count


# (a) publish stores size, sha256 and mtime_ns
reset()
must(publish()["outcome"] == "ok", "published")
row = STORE["endpoint-agent"]
st = os.stat(MSI)
must(row["size"] == st.st_size and row["sha256"] == SHA and row["mtime_ns"] == st.st_mtime_ns, "the row holds size, hash and the file's mtime_ns")
must(ad.load_installer()["mtime_ns"] == st.st_mtime_ns, "load_installer returns mtime_ns")
STORE["endpoint-agent"]["mtime_ns"] = None
must(ad.load_installer()["mtime_ns"] is None, "a 1.18.39 row loads with mtime_ns None")

# (b) matching size and mtime: no hashing, exact bytes and headers
reset()
publish()
serve_ok(expect_reads=0)
serve_ok(expect_reads=0)

# (c) touched (mtime moved, bytes same): one re-hash, 200, healed, then none
reset()
publish()
os.utime(MSI, ns=(mtime_of() + 5_000_000_000, mtime_of() + 5_000_000_000))
serve_ok(expect_reads=1)
must(STORE["endpoint-agent"]["mtime_ns"] == mtime_of(), "the row's mtime_ns was healed")
serve_ok(expect_reads=0)

# (d) same size, different bytes, mtime changed: re-hash, 404, row kept, slot free
reset()
publish()
put_file(MSI, bytes(reversed(MSI_BYTES)))
os.utime(MSI, ns=(mtime_of() + 7_000_000_000, mtime_of() + 7_000_000_000))
r = fetch()
must(r.status_code == 404 and r.content == b"" and STORE and slots() == 0, "tampered file with a new mtime: 404, row kept, slot free")
must(STORE["endpoint-agent"]["mtime_ns"] != mtime_of(), "a refused file is never healed")
put_file(MSI)  # original bytes again
os.utime(MSI, ns=(mtime_of() + 9_000_000_000, mtime_of() + 9_000_000_000))  # a new mtime, whatever the clock granularity
serve_ok(expect_reads=1)

# (e) accepted trade-off: same size, bytes changed, mtime restored: served without a re-hash
reset()
publish()
original = mtime_of()
put_file(MSI, bytes(reversed(MSI_BYTES)))
os.utime(MSI, ns=(original, original))
with ReadCounter() as counter:
    r = fetch()
    body = r.read()
must(r.status_code == 200 and body == bytes(reversed(MSI_BYTES)) and counter.count == 0, "documented trade-off: size and mtime restored means no re-hash")
r.close()

# (f) size changed: 404
reset()
publish()
put_file(MSI, MSI_BYTES + b"x")
must(fetch().status_code == 404 and slots() == 0 and STORE, "a size change is 404")

# (g) a row published by 1.18.39 (no mtime_ns): one re-hash, heal, then the fast path
reset()
publish()
STORE["endpoint-agent"]["mtime_ns"] = None
serve_ok(expect_reads=1)
must(STORE["endpoint-agent"]["mtime_ns"] == mtime_of(), "healed on the first serve")
serve_ok(expect_reads=0)

# (h) a heal fault still serves and logs only
reset()
publish()
STORE["endpoint-agent"]["mtime_ns"] = None


class RaisingUpdate(FakeQuerySet):
    def update(self, **kw):
        raise RuntimeError("database write failed")


real_filter = FakeManager.filter
FakeManager.filter = staticmethod(lambda slot, path=None, sha256=None: RaisingUpdate(slot, path, sha256) if path is not None else FakeQuerySet(slot))
LOG_RECORDS.clear()
serve_ok(expect_reads=1)
FakeManager.filter = staticmethod(real_filter)
must(STORE["endpoint-agent"]["mtime_ns"] is None, "nothing healed")
must(any("modified time could not be stored" in rec.getMessage() for rec in LOG_RECORDS) and all(TMP not in rec.getMessage() for rec in LOG_RECORDS), "the fault is logged without a path")

# (i) the heal filter leaves a republished row alone
reset()
publish()
STORE["endpoint-agent"]["mtime_ns"] = None
old_row = ad.load_installer()
handle, _size, _reason = ad.open_verified(MODULE, MSI, SHA, old_row["size"])
put_file(STATE_MSI, b"second-msi" * 3000)
publish(path=STATE_MSI, sha=hashlib.sha256(b"second-msi" * 3000).hexdigest(), version="0.1.3")
new_mtime = STORE["endpoint-agent"]["mtime_ns"]
V.InstallerDownloadView._heal(old_row, handle)
handle.close()
must(STORE["endpoint-agent"]["path"] == STATE_MSI and STORE["endpoint-agent"]["mtime_ns"] == new_mtime, "a republish between load and heal keeps its own mtime_ns")

# (j) the slot is taken before the store is read
reset()
publish()
reads = [0]
real_load = ad.load_installer
ad.load_installer = lambda: (reads.__setitem__(0, reads[0] + 1), real_load())[1]
held = [fetch(), fetch()]
must(all(r.status_code == 200 for r in held) and reads[0] == 2, "two served, two store reads")
STORE_FAIL["read"] = True
r = fetch()
must(r.status_code == 503 and r.headers["Retry-After"] == "30" and r.content == b"" and reads[0] == 2, "the 3rd is 503 and the store was never read")
must(slots() == 2, "the refused request gave its slot back")
STORE_FAIL["read"] = False
ad.load_installer = real_load
for r in held:
    r.close()

# (k) the cap is 2, the device counter is separate
reset()
publish()
must(ad.INSTALLER_MAX_INFLIGHT == 2 and ad.MAX_INFLIGHT == 8, "constants")
held = [fetch(), fetch()]
must(all(r.status_code == 200 for r in held), "two held downloads are served")
r = fetch()
must(r.status_code == 503 and r.content == b"" and r.headers["Retry-After"] == "30", "third: 503, empty, Retry-After 30")
must(slots() == 2, "counter back to 2 after the refusal")
held[0].close()
must(slots() == 1, "closing frees a slot")
held[0] = fetch()
must(held[0].status_code == 200, "and a new download gets it")
for _ in range(8):
    must(ad.acquire_slot() is True, "device acquire_slot still gets 8 slots")
must(ad.acquire_slot() is False, "the 9th device slot is refused")
must(fetch().status_code == 503, "installer still full")
for _ in range(8):
    ad.release_slot()
for r in held:
    r.close()
reset()
publish()
for _ in range(8):
    ad.acquire_slot()
r = fetch()
must(r.status_code == 200, "the installer gets a slot while the device counter is full")
r.close()
for _ in range(8):
    ad.release_slot()
reset()
must(ad.acquire_slot("tec-tac:test", limit=3) and ad.acquire_slot("tec-tac:test", limit=3) and ad.acquire_slot("tec-tac:test", limit=3) and not ad.acquire_slot("tec-tac:test", limit=3), "limit is honoured")

# (l) nothing published: 404, slot released
reset()
r = fetch()
must(r.status_code == 404 and r.content == b"" and slots() == 0, "nothing published: 404 and the slot is released")

# (m) every error exit frees the slot
reset()
publish()
STORE_FAIL["read"] = True
must(fetch().status_code == 503 and slots() == 0, "store fault: 503, slot free")
STORE_FAIL["read"] = False
real_open = ad.open_verified
ad.open_verified = lambda *a, **k: (_ for _ in ()).throw(OSError("no descriptors"))
must(fetch().status_code == 503 and slots() == 0, "OS fault: 503, slot free")
ad.open_verified = real_open
real_resp = V._SlotFileResponse
V._SlotFileResponse = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("cannot build"))
must(fetch().status_code == 503 and slots() == 0, "response build fault: 503, slot free")
V._SlotFileResponse = real_resp
put_file(MSI, MSI_BYTES + b"x")
must(fetch().status_code == 404 and slots() == 0, "file refusal: 404, slot free")
put_file(MSI)
MS["raises"] = True
must(fetch().status_code == 503 and slots() == 0, "enabled-check fault: 503, slot free")
MS["raises"] = False
CACHE.down = True
must(fetch().status_code == 503, "cache fault: 503")
CACHE.down = False

# ------------------------------------------------------------------------------------------------ the publisher must be enabled
reset()
publish()
count = len(AUD)
serve_ok()
MS["enabled"][MODULE] = False
LOG_RECORDS.clear()
r = fetch()
must(r.status_code == 404 and r.content == b"" and r["Cache-Control"] == "no-store" and "Retry-After" not in r.headers, "disabled publisher: 404, empty, no-store")
must(slots() == 0 and STORE["endpoint-agent"]["module_id"] == MODULE, "slot freed, row still in the store")
must(len(AUD) == count, "no audit row written")
text = " ".join(rec.getMessage() for rec in LOG_RECORDS)
must("publisher_disabled" in text and TMP not in text and PLUGIN_ROOT not in text and "installer.msi" not in text, "the reason code is logged, no path")
MS["enabled"][MODULE] = True
serve_ok()  # same bytes, no republish
must(len(installer_rows()) == 1, "no republish happened")
PLUGINS[:] = [HALO]
must(fetch().status_code == 404 and slots() == 0, "a module that is not installed stays 404")
PLUGINS[:] = [EAM, HALO]
MS["corrupt"] = True
must(fetch().status_code == 404 and slots() == 0, "a corrupt state file is 404 (fail closed)")
MS["corrupt"] = False
MS["raises"] = True
r = fetch()
must(r.status_code == 503 and r.headers["Retry-After"] == "30" and r.content == b"" and slots() == 0, "a state read fault is 503 with Retry-After 30")
MS["raises"] = False
MS["enabled"].clear()
r = fetch()
must(r.status_code == 200, "a module with no record is enabled by default")
r.close()

# the device route is unaffected by the flag
reset()
MS["enabled"][MODULE] = False
grant = ad.grant_download(MODULE, agent_id="agent-abcdefghijklmnop", path=MSI, sha256=SHA)
must(grant["outcome"] in ("ok", "invalid"), f"grant_download behaves as before: {grant}")
must(MS["calls"] == 0, "grant_download never asks module_state")
view_src = (APP / "agent_download_views.py").read_text(encoding="utf-8")
device_part = view_src[view_src.index("class AgentDownloadView"):view_src.index("class InstallerDownloadView")]
must("publisher_enabled" not in device_part and "module_state" not in device_part and "trusted_mtime_ns" not in device_part, "the device view is unchanged in this respect")

# call order: slot, then row, then enabled check, then the file
reset()
publish()
real = {n: getattr(ad, n) for n in ("acquire_slot", "load_installer", "installer_publisher_enabled", "open_verified")}
events = []


def recording(n, f):
    def wrapper(*a, **k):
        events.append(n)
        return f(*a, **k)

    return wrapper


for name, fn in real.items():
    setattr(ad, name, recording(name, fn))
r = fetch()
r.close()
for name, fn in real.items():
    setattr(ad, name, fn)
must(events == ["acquire_slot", "load_installer", "installer_publisher_enabled", "open_verified"], events)
agent_src = (APP / "agent_downloads.py").read_text(encoding="utf-8")
must(not re.search(r"^(import|from)\s+django", agent_src, re.MULTILINE), "no Django import at the top of agent_downloads.py")


# ------------------------------------------------------------------------------------------------ static: migration 0047 and the model agree
def call_name(node):
    return node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id


def field_signature(call):
    return call_name(call), {k.arg: ast.literal_eval(k.value) for k in call.keywords}


models_tree = ast.parse((APP / "models.py").read_text(encoding="utf-8"))
model_node = next(n for n in models_tree.body if isinstance(n, ast.ClassDef) and n.name == "TecTacPublishedInstaller")
model_field = next(field_signature(s.value) for s in model_node.body if isinstance(s, ast.Assign) and s.targets[0].id == "mtime_ns")
migs = sorted((APP / "migrations").glob("0047_*.py"))
must([m.name for m in migs] == ["0047_published_installer_mtime.py"], "exactly one 0047, with the planned name")
mig_tree = ast.parse(migs[0].read_text(encoding="utf-8"))
deps, ops = None, []
for node in ast.walk(mig_tree):
    if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "dependencies":
        deps = ast.literal_eval(node.value)
    if isinstance(node, ast.Call) and call_name(node) in ("AddField", "CreateModel", "AlterField", "RemoveField", "RunPython", "RunSQL", "DeleteModel"):
        ops.append(node)
must(deps == [("tec_tac", "0046_published_installer")], f"0047 depends only on 0046: {deps}")
must(len(ops) == 1 and call_name(ops[0]) == "AddField", "0047 is one AddField and nothing else")
kw = {k.arg: k.value for k in ops[0].keywords}
must(ast.literal_eval(kw["model_name"]) == "tectacpublishedinstaller" and ast.literal_eval(kw["name"]) == "mtime_ns", "AddField names the model and field")
must(field_signature(kw["field"]) == model_field == ("PositiveBigIntegerField", {"null": True}), f"field signature equals the model: {model_field}")
for name in ("framwork/tec_tac/migrations/0047_published_installer_mtime.py", "framwork/tec_tac/agent_downloads.py", "framwork/tec_tac/agent_download_views.py",
             "docs/agent-downloads.md", "tests/installer-serve-cost-1.18.40.py"):
    must(b"\r" not in (ROOT / name).read_bytes(), name + " must keep LF line endings")
for name in ("framwork/tec_tac/models.py", "framwork/tec_tac/contracts.py"):
    data = (ROOT / name).read_bytes()
    must(b"\r\n" in data and data.count(b"\n") == data.count(b"\r\n"), name + " must keep CRLF line endings")

# metadata and docs
meta = ad.agent_downloads_contract_metadata()
json.dumps(meta)
must(meta["version"] == "1.1.0" and meta["operations"] == ["grant_download", "revoke_download", "publish_installer", "unpublish_installer"], "capability version and operations unchanged")
must(meta["installer"]["limits"]["installer_in_flight"] == 2 and meta["installer"]["limits"]["downloads_in_flight"] == 8, "limits")
must("both installer slots are busy" in meta["installer"]["errors"]["503"] and "disabled" in meta["installer"]["errors"]["404"], "error text")
must("only when the size or modified time differ" in meta["installer"]["verification"], "verification text")
contracts_text = (APP / "contracts.py").read_text(encoding="utf-8")
must("both installer slots are busy" in contracts_text and "all 8 installer slots" not in contracts_text, "contracts.py text")
doc = (ROOT / "docs" / "agent-downloads.md").read_text(encoding="utf-8")
must("0047" in doc and "Both installer slots are busy" in doc and "disabled or no longer installed" in doc and "All 8 installer slots" not in doc, "docs")

print("installer serve cost 1.18.40 regression: PASS")

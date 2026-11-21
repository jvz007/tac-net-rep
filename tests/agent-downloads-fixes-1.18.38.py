#!/usr/bin/env python3
"""1.18.38 regression for three findings of the Core 1.18.37 review (agent downloads). Django-free.

Part 1: the link token never reaches a log handler (log_redaction.py, a filter on django.request).
Part 2: the new route has an OpenAPI group (tests/f11-openapi-final-1.15.178.py is the full coverage guard).
Part 3: the in-flight download counter keeps its lifetime while downloads run (cache.touch in acquire_slot and release_slot).
The real django.request log line, the real resolver and Redis run only on dev02."""
import ast
import importlib.util
import io
import logging
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PKG = ROOT / "framwork" / "tec_tac"


def must(condition, message=""):
    if not condition:
        raise AssertionError(message)


def read(rel):
    return (ROOT / rel).read_bytes().decode("utf-8").replace("\r\n", "\n")


def func_src(rel, name):
    text = read(rel)
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(text, node)
    raise AssertionError(name)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ============================================================================================ part 1: log redaction
lr = load("log_redaction_1_18_38", PKG / "log_redaction.py")
TOKEN = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"  # 43 url-safe characters, the shape of a real link token
PATH = f"/api/tfd/agent-downloads/{TOKEN}/"
must(len(TOKEN) == 43, "token shape")


class FakeRequest:
    def __init__(self, path):
        self.path, self.path_info, self.method = path, path, "GET"
        self.META = {"REMOTE_ADDR": "10.0.0.5"}

    def get_full_path(self):
        return self.path + "?x=1"

    def get_full_path_info(self):
        return self.path_info + "?x=1"

    def __repr__(self):
        return f"<WSGIRequest: GET '{self.path}'>"


def make_logger(name):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    target = logging.getLogger(name)
    target.handlers[:] = []
    target.filters[:] = []
    target.addHandler(handler)
    target.propagate = False
    target.setLevel(logging.DEBUG)
    return target, stream


# the record exactly as django.utils.log.log_response builds it: ('%s: %s', reason, path), request and status_code in extra
logger, stream = make_logger("test.django.request.a")
logger.addFilter(lr.AgentDownloadTokenFilter())
request = FakeRequest(PATH)
logger.warning("%s: %s", "Service Unavailable", request.path, extra={"status_code": 503, "request": request})
out = stream.getvalue()
must(TOKEN not in out and "Service Unavailable: /api/tfd/agent-downloads/<redacted>/" in out, out)
must(request.path == PATH and request.path_info == PATH and request.get_full_path() == PATH + "?x=1", "the real request is never changed")

# the same through a handler that formats the request (a formatter that reads record.request)
logger, stream = make_logger("test.django.request.b")
seen = []


class Spy(logging.Handler):
    def emit(self, record):
        req = record.request
        seen.append((record.getMessage(), req.path, req.path_info, req.get_full_path(), req.get_full_path_info(), repr(req), str(req), req.method, req.META["REMOTE_ADDR"]))


logger.addHandler(Spy())
logger.addFilter(lr.AgentDownloadTokenFilter())
logger.error("%s: %s", "Internal Server Error", request.path, extra={"status_code": 500, "request": request})
must(len(seen) == 1, "record reached the handler (never dropped)")
joined = "|".join(seen[0])
must(TOKEN not in joined and "<redacted>" in seen[0][1] and "<redacted>" in seen[0][3] and seen[0][7] == "GET" and seen[0][8] == "10.0.0.5", seen[0])
must(request.path == PATH and seen[0][1] != PATH, "wrapper redacts, original untouched")

# dict args, token in the msg itself, token in a tuple
logger, stream = make_logger("test.django.request.c")
logger.addFilter(lr.AgentDownloadTokenFilter())
logger.warning("%(why)s at %(path)s", {"why": "Not Found", "path": PATH})
logger.warning(f"direct {PATH} in the message")
logger.warning("%s then %s", PATH, ("nested", PATH + "?a=b"))
out = stream.getvalue()
must(TOKEN not in out and out.count("<redacted>") == 4, out)
for source in (f"{PATH}?a=b", f"https://rmm.example.com{PATH}", f"'{PATH}'", f'"{PATH}"'):
    must(TOKEN not in lr.redact(source) and "<redacted>" in lr.redact(source), source)
must(lr.redact("/api/tfd/agent-downloads/") == "/api/tfd/agent-downloads/", "the bare route is not a token")

# a record without a token is untouched: same object, same args, same request
logger, stream = make_logger("test.django.request.d")
captured = []


class Grab(logging.Handler):
    def emit(self, record):
        captured.append(record)


logger.addHandler(Grab())
logger.addFilter(lr.AgentDownloadTokenFilter())
plain = FakeRequest("/api/tfd/resources/clients/")
args = ("Not Found", plain.path)
logger.warning("%s: %s", *args, extra={"request": plain})
rec = captured[0]
must(rec.args == args and rec.args is not None and rec.msg == "%s: %s" and rec.request is plain, "a record without the route passes unchanged")
record = logging.LogRecord("x", logging.WARNING, __file__, 1, "%s: %s", args, None)
before = record.args
must(lr.AgentDownloadTokenFilter().filter(record) is True and record.args is before, "same args object when nothing was redacted")
record = logging.LogRecord("x", logging.WARNING, __file__, 1, "no args here", None, None)
must(lr.AgentDownloadTokenFilter().filter(record) is True and record.msg == "no args here", "no args")
broken = logging.LogRecord("x", logging.WARNING, __file__, 1, "%s", (PATH,), None)
broken.request = types.SimpleNamespace(path=PATH, get_full_path=lambda: 1 / 0)  # a request that raises while read must not lose the record
must(lr.AgentDownloadTokenFilter().filter(broken) is True, "a filter never drops or raises")

# a wrapped request cannot be changed
wrapped = lr._RedactedRequest(request)
try:
    wrapped.path = "x"
except AttributeError:
    pass
else:
    raise AssertionError("the redacted request is read-only")

# install_log_redaction is idempotent and uses the django.request logger
target = logging.getLogger("django.request")
target.filters[:] = []
lr.install_log_redaction()
lr.install_log_redaction()
must(len([f for f in target.filters if isinstance(f, lr.AgentDownloadTokenFilter)]) == 1, "a second install adds no second filter")
must(lr.LOGGER_NAME == "django.request", "logger name")
# end to end on the installed logger, through a real handler attached after the install
stream = io.StringIO()
handler = logging.StreamHandler(stream)
target.addHandler(handler)
target.propagate = False
target.warning("%s: %s", "Service Unavailable", PATH, extra={"status_code": 503, "request": FakeRequest(PATH)})
target.removeHandler(handler)
must(TOKEN not in stream.getvalue() and "Service Unavailable: /api/tfd/agent-downloads/<redacted>/" in stream.getvalue(), stream.getvalue())
target.filters[:] = []

# apps.py calls it inside a guarded block, and the view keeps its statuses
apps_src = read("framwork/tec_tac/apps.py")
block = apps_src[apps_src.index("install_log_redaction") - 400:apps_src.index("install_log_redaction") + 400]
must("try:" in block and "from .log_redaction import install_log_redaction" in block and "install_log_redaction()" in block and "logger.exception(" in block, "guarded call")
view_src = read("framwork/tec_tac/agent_download_views.py")
must("503" in view_src and "Retry-After" in view_src, "the view still answers 503 with Retry-After")
must("log_redaction.py" in read("docs/agent-downloads.md") and "<redacted>" in read("docs/agent-downloads.md"), "docs say where the redaction lives")

# ============================================================================================ part 2: OpenAPI group
openapi_src = read("framwork/tec_tac/openapi.py")
tree = ast.parse(openapi_src)
callbacks = paths = None
for node in tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
        if node.targets[0].id == "CORE_CALLBACK_GROUPS":
            callbacks = ast.literal_eval(node.value)
        if node.targets[0].id == "CORE_PATH_GROUPS":
            paths = ast.literal_eval(node.value)
GROUP = "Tec-Tac · Agent Downloads"
must(callbacks.get("tec_tac.agent_download_views") == GROUP, "callback group entry")
must(("/api/tfd/agent-downloads/", GROUP) in paths, "path group entry")
must(not any(prefix == "/api/tfd/" for prefix, _ in paths), "still no catch-all")
openapi = types.ModuleType("openapi_1_18_38")
exec(compile("import re\n" + "\n".join(
    ast.get_source_segment(openapi_src, n) for n in tree.body
    if (isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id in ("CORE_CALLBACK_GROUPS", "CORE_PATH_GROUPS", "CORE_VIEW_CLASS_GROUPS"))
    or (isinstance(n, ast.FunctionDef) and n.name in ("_callback_module", "_callback_name", "core_group_for_callback", "core_group_for_path"))), "openapi_part", "exec"), openapi.__dict__)
must(openapi.core_group_for_path("/api/tfd/agent-downloads/x/") == GROUP, "classify by path")
must(openapi.CORE_CALLBACK_GROUPS["tec_tac.agent_download_views"] == GROUP, "classify by callback module")
for doc in ("docs/openapi-grouping.md", "docs/developer-contracts.md"):
    must("Agent Downloads" in read(doc), doc)

# ============================================================================================ part 3: in-flight counter lifetime
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)


class ClockCache(H.FakeCache):
    """The harness FakeCache with a clock: a key lives for its timeout from its last set or touch."""

    def __init__(self):
        super().__init__()
        self.now, self.expires = 0.0, {}

    def _check(self):
        super()._check()
        for key in [k for k, at in self.expires.items() if at <= self.now]:
            self.expires.pop(key)
            self.data.pop(key, None)

    def set(self, key, value, timeout=None):
        super().set(key, value, timeout)
        self.expires[key] = self.now + timeout if timeout else float("inf")

    def touch(self, key, timeout=None):
        self._check()
        if key not in self.data:
            return False
        self.expires[key] = self.now + timeout if timeout else float("inf")
        return True

    def decr(self, key):
        self._check()
        if key not in self.data:
            raise ValueError("missing")
        self.data[key] -= 1
        return self.data[key]


cache = ClockCache()
warnings = []
namespace = {"INFLIGHT_KEY": "tec-tac:agentdl:inflight", "INFLIGHT_TTL_SECONDS": 120, "MAX_INFLIGHT": 8, "_cache": lambda: cache,
             "logger": types.SimpleNamespace(warning=lambda *a, **k: warnings.append(a))}
constants = read("framwork/tec_tac/agent_downloads.py")
must("MAX_INFLIGHT = 8" in constants and "INFLIGHT_TTL_SECONDS = 120" in constants, "the constants the test assumes")
for name in ("acquire_slot", "release_slot"):
    exec(func_src("framwork/tec_tac/agent_downloads.py", name), namespace)  # the repo's own source
acquire, release = namespace["acquire_slot"], namespace["release_slot"]
KEY = namespace["INFLIGHT_KEY"]

must(acquire() is True, "first slot")
cache.now = 100
must(acquire() is True and cache.data[KEY] == 2, "second slot after 100 s")
cache.now = 200  # 200 s after the first acquire: without the renewal the counter would have expired at 120 s
cache._check()
must(cache.data.get(KEY) == 2, "the counter is still 2 after 200 s of steady use: " + str(cache.data.get(KEY)))
release()
cache.now = 300
cache._check()
must(cache.data.get(KEY) == 1, "a release renews the lifetime for the download still running: " + str(cache.data.get(KEY)))
release()
cache._check()
must(cache.data.get(KEY) == 0, "both released: the counter reads 0")

# no activity for more than 120 s: the counter heals, a new acquire starts at 1
cache.now = 300 + 121
cache._check()
must(KEY not in cache.data, "idle for more than 120 s: the counter is gone")
must(acquire() is True and cache.data[KEY] == 1, "a new acquire starts at 1")
release()

# the cap: the 9th is refused and leaves the counter at 8
for _ in range(8):
    must(acquire() is True, "slots 1 to 8")
must(cache.data[KEY] == 8, "eight in flight")
must(acquire() is False and cache.data[KEY] == 8, "over the cap: False, counter back at 8")
# the over-limit path renewed the lifetime before it released
cache.now += 100
must(acquire() is False and cache.data[KEY] == 8, "still capped 100 s later")
cache.now += 100
cache._check()
must(cache.data.get(KEY) == 8, "refused attempts under load keep the counter alive too")

# a cache fault: release never raises, acquire raises so the view answers 503
cache.down = True
release()
must(warnings, "the release fault is logged as a warning")
try:
    acquire()
except ConnectionError:
    pass
else:
    raise AssertionError("acquire must raise on a cache fault")
cache.down = False

acquire_src = func_src("framwork/tec_tac/agent_downloads.py", "acquire_slot")
release_src = func_src("framwork/tec_tac/agent_downloads.py", "release_slot")
must("cache.touch(INFLIGHT_KEY, INFLIGHT_TTL_SECONDS)" in acquire_src and "cache.touch(INFLIGHT_KEY, INFLIGHT_TTL_SECONDS)" in release_src, "touch in both functions")
must(acquire_src.index("cache.touch") < acquire_src.index("release_slot()"), "touch comes before the over-limit release")
print("agent downloads fixes 1.18.38 regression: PASS")

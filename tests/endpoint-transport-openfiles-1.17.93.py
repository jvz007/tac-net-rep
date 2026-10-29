#!/usr/bin/env python3
"""1.17.93 regression: the open-file soft limit is raised once per process (load test of 29 October 2026: soft 1024, [Errno 24] near 968 agents).

A fake ``resource`` module stands in for the Linux one (a real setrlimit could not run on this PC). Covered: soft 1024 and hard 524288 give
setrlimit(65536, 524288) once and one info line naming 1024 and 65536; hard 4096 gives (4096, 4096); an infinite hard limit gives
(65536, infinite); a soft limit already high or infinite is never touched; the hard value passed is always the one read; a failing
getrlimit or setrlimit, or no ``resource`` module, gives no exception and at most one warning; a second call is a no-op; the route raises
it at the first socket, once; serves_asgi is true only with an ASGI server imported; apps.py and the docs carry it.
"""
from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must = H.et, H.must

INF = -1


class Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.rows = []

    def emit(self, record):
        self.rows.append((record.levelno, record.getMessage()))


LOG = Records()
logging.getLogger("tec_tac.endpoint_transport").addHandler(LOG)
logging.getLogger("tec_tac.endpoint_transport").setLevel(logging.DEBUG)


def fake_resource(soft, hard, get_raises=None, set_raises=None):
    mod = types.ModuleType("resource")
    mod.RLIM_INFINITY, mod.RLIMIT_NOFILE = INF, 7
    mod.calls = []

    def getrlimit(which):
        must(which == 7, "RLIMIT_NOFILE")
        if get_raises:
            raise get_raises
        return soft, hard

    def setrlimit(which, pair):
        mod.calls.append((which, pair))
        if set_raises:
            raise set_raises

    mod.getrlimit, mod.setrlimit = getrlimit, setrlimit
    return mod


def attempt(soft, hard, **kw):
    et.reset_open_files_for_tests()
    del LOG.rows[:]
    mod = fake_resource(soft, hard, **kw)
    sys.modules["resource"] = mod
    try:
        result = et.raise_open_file_limit()
    finally:
        sys.modules.pop("resource", None)
    return mod, result


def levels(minimum):
    return [m for lvl, m in LOG.rows if lvl >= minimum]


must(et.OPEN_FILES_TARGET == 65536, "the target")

mod, result = attempt(1024, 524288)
must(mod.calls == [(7, (65536, 524288))] and result == 65536, mod.calls)
infos = [m for lvl, m in LOG.rows if lvl == logging.INFO]
must(len(infos) == 1 and "1024" in infos[0] and "65536" in infos[0] and "524288" in infos[0], LOG.rows)
must(not levels(logging.WARNING), "no warning")

mod, _ = attempt(1024, 4096)
must(mod.calls == [(7, (4096, 4096))], mod.calls)
mod, _ = attempt(1024, INF)
must(mod.calls == [(7, (65536, INF))], mod.calls)
mod, result = attempt(100000, 524288)
must(not mod.calls and result is None and not LOG.rows, "a higher soft limit is never lowered")
mod, _ = attempt(INF, INF)
must(not mod.calls, "an infinite soft limit is never touched")
mod, _ = attempt(65536, 524288)
must(not mod.calls, "already at the target")
mod, _ = attempt(4096, 4096)
must(not mod.calls, "soft already equals a low hard limit")
for soft, hard in ((256, 1000), (1024, 99999), (1024, INF)):
    mod, _ = attempt(soft, hard)
    must(mod.calls and mod.calls[0][1][1] == hard, "the hard value passed is the one read")

for kw in ({"set_raises": OSError("no")}, {"set_raises": ValueError("no")}, {"get_raises": OSError("no")}):
    mod, result = attempt(1024, 524288, **kw)
    warnings = [m for lvl, m in LOG.rows if lvl == logging.WARNING]
    must(result is None and len(warnings) == 1 and not [1 for lvl, _ in LOG.rows if lvl == logging.INFO], (kw, LOG.rows))

# no resource module (Windows)
et.reset_open_files_for_tests()
del LOG.rows[:]
sys.modules["resource"] = None  # makes "import resource" raise ImportError
try:
    must(et.raise_open_file_limit() is None, "returns quietly")
finally:
    sys.modules.pop("resource", None)
must(not levels(logging.INFO), LOG.rows)

# a second call is a no-op
et.reset_open_files_for_tests()
mod = fake_resource(1024, 524288)
sys.modules["resource"] = mod
try:
    et.raise_open_file_limit()
    del LOG.rows[:]
    must(et.raise_open_file_limit() is None and len(mod.calls) == 1 and not LOG.rows, "once per process")
finally:
    sys.modules.pop("resource", None)

# the route raises it at the first socket, once
et.reset_open_files_for_tests()
mod = fake_resource(1024, 524288)
sys.modules["resource"] = mod


async def sockets():
    route = et.endpoint_agent_route()
    for _ in range(3):
        try:
            await route({"type": "websocket"}, None, None)
        except AssertionError:
            pass  # the harness consumer app is not driven here


try:
    asyncio.run(sockets())
    must(mod.calls == [(7, (65536, 524288))], "the first connection triggered it once: " + str(mod.calls))
finally:
    sys.modules.pop("resource", None)

# serves_asgi
for name in ("uvicorn", "daphne", "hypercorn"):
    sys.modules.pop(name, None)
must(et.serves_asgi() is False, "a Celery worker or manage.py command is left alone")
for name in ("uvicorn", "daphne", "hypercorn"):
    sys.modules[name] = types.ModuleType(name)
    must(et.serves_asgi() is True, name)
    sys.modules.pop(name)

# apps.py calls it only when serving ASGI, inside the guarded endpoint block
apps = (H.APP / "apps.py").read_text(encoding="utf-8")
must("if serves_asgi():" in apps and "raise_open_file_limit()" in apps.split("install_endpoint_agent_route()")[1], "apps.py wiring")

# the docs name the numbers and the check
doc = (H.ROOT / "docs" / "endpoint-transport.md").read_text(encoding="utf-8")
must("## Open files and the 2 000 agent target" in doc, "the docs section")
section = doc.split("## Open files and the 2 000 agent target")[1].split("\n## ")[0]
must("65536" in section and "2 000" in section and "/proc/$(pgrep -f uvicorn | head -1)/limits" in section, "section content")
print("PASS endpoint transport open files 1.17.93")

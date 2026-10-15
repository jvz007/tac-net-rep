#!/usr/bin/env python3
"""1.17.42 regression: a declared file answer whose stream fails part way is an outcome-unknown refusal, not a bare 500.

Covered: (a) a POST with file_response whose stream raises OSError after the first chunk gives status 502, code tactical_call_failed,
an audit verdict and exactly one custom:outcome-unknown row with no file name or bytes in it; (b) the same GET raises the same error with
no row; (c) close() is called once in both cases; (d) the stream that succeeds and the over-cap stream still behave as in 1.17.41
(tests/tactical-operation-file-response-1.17.41.py is re-run unchanged).

Uses the stubs of tests/tactical-operations-1.17.7.py, as the 1.17.41 test does.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent / "tactical-operations-1.17.7.py"
source = BASE.read_text(encoding="utf-8")
cut = source.index('PATH = f"/agents/{AGENT}/reboot/"\nroute(PATH)')
G = {"__name__": "stubs", "__file__": str(BASE)}
exec(compile(source[:cut], str(BASE), "exec"), G)  # noqa: S102 - test-only reuse of the 1.17.7 stubs
ops, declare, must, fresh = (G[k] for k in ("ops", "declare", "must", "fresh"))
CALLS, ROWS, AGENT, tech, Request, ROUTES = (G[k] for k in ("CALLS", "ROWS", "AGENT", "tech", "Request", "ROUTES"))
route = G["route"]


class BrokenStream:
    """A FileResponse-like answer whose stream breaks after the first chunk. close() is counted."""

    def __init__(self, status=200):
        self.status_code, self.streaming = status, True
        self.streaming_content = self._chunks()
        self._headers = {"Content-Type": "application/pdf", "Content-Disposition": 'attachment; filename="secret-name.pdf"'}
        self.closed = 0

    def _chunks(self):
        yield b"%PDF-1.7\nsecret-bytes"
        raise OSError("connection reset while reading secret-name.pdf")

    def get(self, name, default=None):
        return self._headers.get(name, default)

    def close(self):
        self.closed += 1


class GoodStream(BrokenStream):
    def _chunks(self):
        yield b"%PDF-1.7\n"
        yield b"end"


PATH = f"/agents/{AGENT}/export/"
PARAMS = {"agent_id": AGENT}


def declare_file(**over):
    spec = dict(id="export", route="agents/{agent_id:agent}/export/", method="POST", body_fields=["mode"], file_response=True,
                audit={"action": "export", "object_type": "agent", "audit_fields": ["mode"]})
    spec.update(over)
    return declare(**spec)


def run(body=None):
    del CALLS[:]
    del ROWS[:]
    return ops.run_tactical_operation(Request(tech), "agents", "export", PARAMS, body if body is not None else {"mode": "pdf"})


# (a) a POST whose stream breaks mid-way: 502, tactical_call_failed, one outcome-unknown row, nothing sensitive in it
fresh()
declare_file()
stream = BrokenStream()
route(PATH, stream)
try:
    run()
except ops.TacticalOperationError as error:
    must(error.status == 502 and error.code == "tactical_call_failed", (error.status, error.code))
    must(error.audit, "the refusal carries the audit verdict")
    must(str(error) == "Tactical failed while sending its answer.", str(error))
else:
    raise AssertionError("a stream that breaks mid-way must be refused")
must(len(ROWS) == 1 and ROWS[0]["action"] == "custom:outcome-unknown", ROWS)
dump = repr(ROWS)
must("secret-name" not in dump and "secret-bytes" not in dump and "%PDF" not in dump, "the row carries no file name and no bytes")
must(stream.closed == 1, ("closed exactly once", stream.closed))
print("       POST broken stream: 502 tactical_call_failed, one outcome-unknown row, closed once")

# (b) the same GET: the same error, no row, closed once
fresh()
declare_file(method="GET", body_fields=[], audit={"action": "export", "object_type": "agent"})
stream = BrokenStream()
route(PATH, stream)
try:
    ops.run_tactical_operation(Request(tech), "agents", "export", PARAMS)
except ops.TacticalOperationError as error:
    must(error.status == 502 and error.code == "tactical_call_failed", (error.status, error.code))
else:
    raise AssertionError("a GET stream that breaks must be refused")
must(ROWS == [], ROWS)
must(stream.closed == 1, ("closed exactly once", stream.closed))
print("       GET broken stream: 502 tactical_call_failed, no row, closed once")

# (c) the HTTP view turns the refusal into a JSON response, not a 500
fresh()
declare_file()
route(PATH, BrokenStream())
view = G["views"].TacticalOperationView()
reply = view.post(Request(tech, data={"params": PARAMS, "body": {"mode": "pdf"}}), "agents", "export")
must(reply.status_code == 502, reply.status_code)
must(b"secret" not in bytes(getattr(reply, "content", b"") or b""), "no bytes in the refusal body")
print("       HTTP view: JSON refusal with status 502")

# (d) the stream that succeeds still relays, and the 1.17.41 test passes unchanged
fresh()
declare_file()
good = GoodStream()
route(PATH, good)
result = run()
must(result.status == 200 and result.content == b"%PDF-1.7\nend", result.content)
must(good.closed == 1 and len(ROWS) == 1, (good.closed, ROWS))
print("       stream that succeeds: relayed as before")

rerun = subprocess.run(
    [sys.executable, "-I", str(Path(__file__).resolve().parent / "tactical-operation-file-response-1.17.41.py")],
    capture_output=True, text=True, timeout=120,
)
must(rerun.returncode == 0, ("1.17.41 file response test failed", rerun.stdout[-800:], rerun.stderr[-800:]))
print("       tests/tactical-operation-file-response-1.17.41.py re-run: passed")

# the code and the doc carry the fix
root = Path(__file__).resolve().parents[1]
code = (root / "framwork" / "tec_tac" / "tactical_operations.py").read_text(encoding="utf-8")
must("content = _read_stream(response)" in code and "tactical_call_failed\", \"Tactical failed while sending its answer." in code, "the stream read is wrapped")
docs = (root / "docs" / "tactical-operations.md").read_text(encoding="utf-8")
must("fails part way" in docs and "`tactical_call_failed`" in docs, "docs say a failing stream is outcome-unknown")
print("       code and docs carry the 1.17.42 fix")

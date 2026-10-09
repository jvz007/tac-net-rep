#!/usr/bin/env python3
"""1.17.7 regression: the browser-declared audit path is deprecated (CQ18 option a), nothing removed.

Reuses the stub harness of
tests/audit-declared-browser-events-1.17.0.py (everything before its first scenario), so the real audit.py and
audit_views.py run with only the Tactical ORM boundary faked. Django is not installed on the development PC.
"""
from __future__ import annotations

import ast
import logging
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "audit-declared-browser-events-1.17.0.py"
source = HARNESS.read_text(encoding="utf-8")
marker_line = "# === Q34: denials reach the audit log as Core-owned rows"
assert marker_line in source
H = {"__name__": "audit_harness", "__file__": str(HARNESS)}
exec(compile(source.split(marker_line)[0], "audit-declared-browser-events-1.17.0.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse
audit, audit_views, ROWS, reset, post, tech = H["audit"], H["audit_views"], H["ROWS"], H["reset"], H["post"], H["tech"]
ROOT, PKG = H["ROOT"], H["PKG"]
GRANTED = H["GRANTED"]


def must(cond, msg):
    if not cond:
        raise AssertionError(msg)


def refuses(fn, key):
    try:
        fn()
    except audit.AuditContractError as exc:
        must(key in str(exc) and "Core-owned" in str(exc), str(exc))
        return
    raise AssertionError(f"{key} was accepted")


# ------------------------------------------------------------------ 4. the declared browser path: unchanged answers, Deprecation header
reset()
ok = post(tech)
must(ok.status_code == 201 and ok.headers == {"Deprecation": "true"}, (ok.status_code, ok.headers))
must(ROWS[0]["debug_info"]["operation_context"] == {"browser_provenance": "module-declared-event"}, ROWS[0])
reset()
gone = post(tech, object_id="a-2")
must(gone.status_code == 404 and gone.headers == {"Deprecation": "true"} and gone.data["recorded"] is False, (gone.status_code, gone.headers))
must(len(ROWS) == 1 and ROWS[0]["action"] == "deny", ROWS)
must(ROWS[0]["debug_info"]["operation_context"] == {"browser_provenance": "module-declared-event", "core_refusal": True}, ROWS)
reset()
bad = post(tech, object_id=...)
must(bad.status_code == 400 and bad.headers == {"Deprecation": "true"}, (bad.status_code, bad.headers))
reset()
other = post(tech, module_id="licence-demo", object_type="licence_key", object_id="1")
must(other.status_code == 201 and other.headers == {"Deprecation": "true"}, other.status_code)
reset()
no_grant = post(tech, module_id="noevents-demo")
must(no_grant.status_code == 403 and not getattr(no_grant, "headers", {}), "an undeclared event has no Deprecation header")
core = post(tech, module_id="core")
must(core.status_code == 403 and not getattr(core, "headers", {}), "module core has no Deprecation header")
must(not ROWS, "refusals before the declared path write nothing")
# the permissioned path is not deprecated
GRANTED.add("both-demo.use")
reset()
GRANTED.add("both-demo.use")
perm = post(tech, module_id="both-demo", action="view", object_type="agent", object_id="a-1")
must(perm.status_code == 201 and not getattr(perm, "headers", {}), (perm.status_code, getattr(perm, "headers", None)))
must(ROWS[0]["debug_info"]["operation_context"] == {}, "the permissioned path sets no marker")
GRANTED.clear()

# ------------------------------------------------------------------ 5. one warning per module per process
audit_views._DEPRECATION_WARNED.clear()


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


cap = Capture()
log = logging.getLogger("tec_tac.audit")
log.addHandler(cap)
log.setLevel(logging.DEBUG)
try:
    reset()
    for _ in range(3):
        post(tech)
    post(tech, module_id="licence-demo", object_type="licence_key", object_id="1")
    post(tech, module_id="licence-demo", object_type="licence_key", object_id="2")
    post(tech, module_id="multi-demo", action="view")
    warns = [r.getMessage() for r in cap.records if r.levelno == logging.WARNING and "deprecated" in r.getMessage()]
    must(len(warns) == 3, warns)
    must(sum("declaring-demo" in w for w in warns) == 1 and sum("licence-demo" in w for w in warns) == 1 and sum("multi-demo" in w for w in warns) == 1, warns)
finally:
    log.removeHandler(cap)

# ------------------------------------------------------------------ 6. contract and docs text
tree = ast.parse((PKG / "contracts.py").read_text(encoding="utf-8"))


def literal(name):
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    return ast.literal_eval(node.value)


details = literal("HTTP_CONTRACT_DETAILS")["/api/tfd/audit/record/"]["POST"]
must("Deprecated since 1.17.7" in details["deprecated"] and "Deprecation: true" in details["deprecated"], details["deprecated"])
must("registered Tactical operation" in details["deprecated"] and "tec_tac.audit.record" in details["deprecated"] and "no replacement" in details["deprecated"], details["deprecated"])
must("exactly as in 1.17.6" in details["deprecated"] and "end date is not set" in details["deprecated"], details["deprecated"])
browser = next(row for row in literal("BROWSER_CONTRACTS") if row["id"] == "ui.authenticated.audit")
must("Deprecated since Core 1.17.7" in browser["purpose"] and "Deprecation: true" in browser["purpose"] and "registered Tactical operation" in browser["purpose"], browser["purpose"])
docs = (ROOT / "docs" / "module-audit.md").read_text(encoding="utf-8")
must("Deprecated since Core 1.17.7" in docs and "`Deprecation: true`" in docs, "docs name the deprecation")
must("a registered Tactical operation" in docs and "`tec_tac.audit.record` from the module's backend route" in docs and "nothing yet" in docs, "docs state the mapping")
must("first Core release after the last declaring module has switched" in docs, "docs state when the path ends")
print("[TEST] PASS audit declared browser events deprecation 1.17.7")

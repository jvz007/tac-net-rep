#!/usr/bin/env python3
"""Regression: Core 1.18.18 premium selection. Every selection attempt that does not end saved writes one deny audit row, and Core needs
licensing.allowed_modules 1.1.0. No Django needed: the view is driven with stub rest_framework, drf_spectacular, session_security, views
and audit modules; the source file is driven with a fake provider."""
import copy
import importlib
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG_DIR = ROOT / "framwork" / "tec_tac"
package_stub = types.ModuleType("tec_tac")
package_stub.__path__ = [str(PKG_DIR)]
sys.modules["tec_tac"] = package_stub

# --- stubs ----------------------------------------------------------------------------------------------------------------------
PROVIDER = {"version": "1.1.0", "object": None}
caps_stub = types.ModuleType("tec_tac.capabilities")


def get_capability(capability_id, version=None):
    assert capability_id == "licensing.allowed_modules" and version == ">=1.1.0,<2.0.0", (capability_id, version)
    if PROVIDER["version"] != "1.1.0":
        raise LookupError("no provider in range")
    return PROVIDER["object"]


caps_stub.get_capability = get_capability
sys.modules["tec_tac.capabilities"] = caps_stub

drf = types.ModuleType("drf_spectacular")
drf_utils = types.ModuleType("drf_spectacular.utils")
drf_utils.extend_schema = lambda **kw: (lambda f: f)
drf_utils.extend_schema_view = lambda **kw: (lambda c: c)
rest = types.ModuleType("rest_framework")
resp = types.ModuleType("rest_framework.response")
rviews = types.ModuleType("rest_framework.views")


class Response:
    def __init__(self, data=None, status=200):
        self.data, self.status = data, status


class APIView:
    pass


resp.Response, rviews.APIView = Response, APIView
sec = types.ModuleType("tec_tac.session_security")
sec.SessionAuthenticated = object
vws = types.ModuleType("tec_tac.views")
vws._require_module_manager = lambda user: None
for name, mod_ in (("drf_spectacular", drf), ("drf_spectacular.utils", drf_utils), ("rest_framework", rest), ("rest_framework.response", resp),
                   ("rest_framework.views", rviews), ("tec_tac.session_security", sec), ("tec_tac.views", vws)):
    sys.modules[name] = mod_

ROWS, AUDIT = [], {"raise": False}
audit_stub = types.ModuleType("tec_tac.audit")


def record(**kw):
    if AUDIT["raise"]:
        raise RuntimeError("audit down")
    assert kw["strict"] is False and kw["module_id"] == "core" and kw["object_type"] == "module_selection"
    ROWS.append(kw)


audit_stub.record = record
sys.modules["tec_tac.audit"] = audit_stub
package_stub.audit = audit_stub

src = importlib.import_module("tec_tac.licensing_catalogue_source")
package_stub.licensing_catalogue_source = src
mv = importlib.import_module("tec_tac.module_allowed_views")
REAL_SET = src.set_premium_selection

# --- range ----------------------------------------------------------------------------------------------------------------------
assert src.ALLOWED_CAPABILITY_RANGE == ">=1.1.0,<2.0.0", src.ALLOWED_CAPABILITY_RANGE
assert src.CAPABILITY_RANGE == ">=1.0.0,<2.0.0", src.CAPABILITY_RANGE


# --- view -----------------------------------------------------------------------------------------------------------------------
class Req:
    user = object()

    def __init__(self, data):
        self.data = data


def drive(state, module_id="halopsa", selected=False, **extra):
    ROWS.clear()
    body = {"ok": state == "saved", "state": state, "message": "Licensing says: SECRET-KEY \x1b[31m token=abc", "module_id": module_id,
            "selected": selected, "before": [], "after": [], "required_by": []}
    body.update(extra)
    src.set_premium_selection = lambda mid, sel: copy.deepcopy(body)
    out = mv.ModuleAllowedSelectionView().put(Req({"module_id": module_id, "selected": selected}))
    assert out.data["state"] == state and out.status == mv._allowed_http(state)
    return out


REFUSED = ("locked", "unknown_module", "bad_request", "required_by")
FAILED = ("licensing_unavailable", "invalid_response", "not_fetched", "licence_revoked", "licence_expired", "licence_grace_expired",
          "plan_expired", "plan_conflict", "plan_wrong_server", "caller_not_allowed", "audit_unavailable")
for state in REFUSED + FAILED:
    drive(state, required_by=["a", "b"] if state == "required_by" else [])
    assert len(ROWS) == 1, (state, ROWS)
    row = ROWS[0]
    assert row["action"] == "deny" and row["object_id"] == "halopsa", row
    assert row["metadata"]["result"] == state and row["metadata"]["outcome"] == ("refused" if state in REFUSED else "failed"), row
    assert state in row["message"] and "SECRET" not in repr(row) and "\x1b" not in repr(row) and "token" not in repr(row), row
    assert ("required_by" in row["metadata"]) == (state == "required_by")
    if state in FAILED:
        assert row["message"].endswith("Nothing was changed."), row["message"]
drive("required_by", required_by=[f"m{i}" for i in range(80)])
assert len(ROWS[0]["metadata"]["required_by"]) == 50

drive("saved", before=[], after=["halopsa"])
assert len(ROWS) == 1 and ROWS[0]["action"] == "modify", ROWS

# a malformed id: the shown id is None and the raw text reaches no row
ROWS.clear()
src.set_premium_selection = REAL_SET
out = mv.ModuleAllowedSelectionView().put(Req({"module_id": "BAD id <script>", "selected": "yes"}))
assert out.data["state"] == "bad_request" and len(ROWS) == 1 and ROWS[0]["object_id"] is None and ROWS[0]["action"] == "deny", ROWS
assert "script" not in repr(ROWS[0]) and "BAD" not in repr(ROWS[0]), ROWS[0]

# a raising audit write keeps the answer
AUDIT["raise"] = True
out = drive("licensing_unavailable")
assert out.status == 503 and out.data["state"] == "licensing_unavailable"
AUDIT["raise"] = False

# --- source-level ---------------------------------------------------------------------------------------------------------------
text = (PKG_DIR / "module_allowed_views.py").read_text(encoding="utf-8")
assert text.count('action="deny"') == 1 and text.count('action="modify"') == 1 and text.count('action="run"') == 1
assert not re.search(r'elif body\["state"\] in', text)


# --- range against the real source with a fake provider -------------------------------------------------------------------------
def mod(mid, category, **kw):
    r = {"id": mid, "name": mid, "category": category, "entitled": True, "availability": "available", "locked": category != "premium",
         "optional": category == "premium", "selected": True, "in_plan": False, "required_by": [], "notes": [], "category_source": "licensing",
         "release": None}
    r.update(kw)
    return r


LIST = {"ok": True, "state": "ok", "message": "x", "plan_revision": 1, "channel": "stable", "plan_issued_at": None, "plan_expires_at": None,
        "plan_state": "valid", "fetched_at": None, "from_cache": True, "count": 1, "modules": [mod("halopsa", "premium")], "last_refresh_state": None}


class Fake:
    def __init__(self):
        self.calls = []

    def list_modules(self):
        self.calls.append(("list",))
        return copy.deepcopy(LIST)

    def refresh(self):
        self.calls.append(("refresh",))
        return copy.deepcopy(LIST)

    def set_selection(self, *args, **kw):
        assert not args, "set_selection must be called with keywords"
        self.calls.append(("set_selection", kw))
        return {"ok": True, "state": "saved", "before": [], "after": ["halopsa"]}


fake = PROVIDER["object"] = Fake()
PROVIDER["version"] = "1.0.0"
assert src.read_allowed_modules()["state"] == "licensing_unavailable"
assert src.refresh_allowed_modules()["state"] == "licensing_unavailable"
assert REAL_SET("halopsa", False)["state"] == "licensing_unavailable" and not fake.calls
PROVIDER["version"] = "1.1.0"
assert src.read_allowed_modules()["state"] == "ok"
assert src.refresh_allowed_modules()["state"] in ("ok", "cached")
assert fake.calls == [("list",), ("refresh",)], fake.calls
fake.calls.clear()
assert REAL_SET("halopsa", False)["state"] == "saved"
assert [c for c in fake.calls if c[0] == "set_selection"] == [("set_selection", {"module_id": "halopsa", "selected": False})], fake.calls

# no other Core file asks for the capability
for path in PKG_DIR.glob("*.py"):
    if path.name not in ("licensing_catalogue_source.py", "contracts.py"):
        assert "ALLOWED_CAPABILITY_ID" not in path.read_text(encoding="utf-8", errors="ignore"), path.name
print("premium untick audit 1.18.18 regression: PASS")

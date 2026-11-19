#!/usr/bin/env python3
"""Regression: Core 1.18.10 allowed-module routes. The source file is tested with a fake provider (no Django needed); the views and
urls are checked at source level, because Django is not installed on every machine that runs this test."""
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

PROVIDER = {"object": None, "missing": False}
caps_stub = types.ModuleType("tec_tac.capabilities")


def get_capability(capability_id, version=None):
    assert capability_id == "licensing.allowed_modules" and version == ">=1.1.0,<2.0.0", (capability_id, version)
    if PROVIDER["missing"]:
        raise LookupError("not installed")
    return PROVIDER["object"]


caps_stub.get_capability = get_capability
sys.modules["tec_tac.capabilities"] = caps_stub
src = importlib.import_module("tec_tac.licensing_catalogue_source")

RID = "11111111-2222-3333-4444-555555555555"


def row(mid, category, *, entitled=True, selected=True, required_by=(), release=True, **extra):
    optional = category == "premium"
    item = {
        "id": mid, "name": mid.title(), "category": category, "entitled": entitled, "availability": "available", "locked": not optional,
        "optional": optional, "selected": selected, "in_plan": release, "required_by": list(required_by), "notes": [],
        "category_source": "licensing", "release": None,
    }
    if release:
        item["release"] = {"release_id": RID, "version": "1.2.3", "sha256": "a" * 64, "publisher_id": "pub", "key_id": "key",
                           "channel": "stable", "dependencies": ["core-thing >=1.0.0"]}
    item.update(extra)
    return item


def good_answer(**top):
    modules = [row("agents", "core"), row("health", "server"), row("halopsa", "premium"), row("huntress", "premium", selected=False),
               row("needed", "premium", required_by=["halopsa"]), row("nolicence", "premium", entitled=False, selected=False, release=False)]
    answer = {"ok": True, "state": "ok", "message": "Done.", "plan_revision": 7, "channel": "stable", "plan_issued_at": "2026-11-18T08:00:00Z",
              "plan_expires_at": "2026-11-19T08:00:00Z", "plan_state": "valid", "fetched_at": "2026-11-18T08:00:01Z", "from_cache": True,
              "count": len(modules), "modules": modules, "last_refresh_state": None}
    answer.update(top)
    return answer


class Fake:
    def __init__(self, answer=None, raises=None, selection=None, has_selection=True):
        self.answer, self.raises, self.selection = answer, raises, selection
        self.frames, self.selection_calls = [], []

    def _frame(self):
        self.frames.append(Path(sys._getframe(2).f_code.co_filename).name)

    def list_modules(self):
        self._frame()
        if self.raises:
            raise self.raises
        return copy.deepcopy(self.answer)

    def refresh(self):
        self._frame()
        if self.raises:
            raise self.raises
        return copy.deepcopy(self.answer)

    def set_selection(self, module_id, selected):
        self._frame()
        self.selection_calls.append((module_id, selected))
        return copy.deepcopy(self.selection)


class NoSelection:
    """A provider without set_selection (an older Licensing)."""

    def __init__(self, answer):
        self.answer, self.selection_calls, self.frames = answer, [], []

    def list_modules(self):
        return copy.deepcopy(self.answer)


def use(provider):
    PROVIDER["object"], PROVIDER["missing"] = provider, provider is None and False
    return provider


# 1. a good answer is whitelisted, and injected keys do not come out
answer = good_answer(token="SECRET-TOKEN", url="https://licensing.example/x", grant="g")
answer["modules"][0]["token"] = "SECRET"
answer["modules"][2]["release"]["url"] = "https://licensing.example/artifact"
answer["modules"][2]["publisher_id"] = "pub2"
fake = use(Fake(answer))
body = src.read_allowed_modules()
assert body["ok"] is True and body["state"] == "ok" and body["count"] == 6 and len(body["modules"]) == 6, body
flat = repr(body)
for needle in ("SECRET", "licensing.example", "sha256", "a" * 64, "publisher_id", "key_id", "pub2", "token", "grant", "artifact"):
    assert needle not in flat, needle
assert set(body) == {"ok", "state", "message", "plan_state", "plan_revision", "channel", "plan_issued_at", "plan_expires_at", "fetched_at",
                     "from_cache", "last_refresh_state", "count", "modules"}, set(body)
first, third = body["modules"][0], body["modules"][2]
assert set(first) == {"id", "name", "category", "entitled", "availability", "locked", "optional", "selected", "in_plan", "required_by",
                      "notes", "category_source", "release"}, set(first)
assert first["locked"] is True and first["selected"] is True and third["optional"] is True
assert set(third["release"]) == {"release_id", "version", "channel", "dependencies"}
assert third["release"]["dependencies"] == {"core-thing": ">=1.0.0"}
assert body["modules"][4]["required_by"] == ["halopsa"]

# 2. control characters and long strings are cleaned
dirty = good_answer()
dirty["modules"][0]["name"] = "Ag\x00en\x1bts" + "x" * 500
dirty["channel"] = "sta\x07ble"
body = use(Fake(dirty)) and src.read_allowed_modules()
assert body["modules"][0]["name"].startswith("Agents") and len(body["modules"][0]["name"]) == 120 and "\x00" not in body["modules"][0]["name"]
assert body["channel"] == "stable"

# 3. malformed answers give invalid_response and no rows
def bad(mutator):
    a = good_answer()
    mutator(a)
    out = src.read_allowed_modules() if use(Fake(a)) else None
    assert out["state"] == "invalid_response" and out["ok"] is False and out["modules"] == [] and out["count"] == 0, out
    return out


bad(lambda a: a.update(modules="nope"))
bad(lambda a: a.update(modules=None))
bad(lambda a: a["modules"][0].update(entitled="yes"))
bad(lambda a: a["modules"][0].update(selected=1))
bad(lambda a: a["modules"][0].update(id="Bad Id"))
bad(lambda a: a["modules"][0].update(id=["x"]))
bad(lambda a: a["modules"][0].update(category="gold"))
bad(lambda a: a["modules"][0].update(required_by="halopsa"))
bad(lambda a: a["modules"][0].update(required_by=["BAD ID"]))
bad(lambda a: a["modules"][2]["release"].update(release_id="not-a-uuid"))
bad(lambda a: a["modules"][2].update(release="x"))
bad(lambda a: a["modules"][2]["release"].update(dependencies=5))
bad(lambda a: a["modules"].append(copy.deepcopy(a["modules"][0])))
bad(lambda a: a["modules"].append("row"))
bad(lambda a: a.update(modules=[row("m%d" % i, "core") for i in range(src.MAX_RELEASES + 1)]))
for broken in ("text", None, [], {"state": 5}, {"state": "mystery"}, {}):
    use(Fake(broken))
    out = src.read_allowed_modules()
    assert out["state"] == "invalid_response" and out["modules"] == [], (broken, out)

# 4. no provider, or a provider that raises (including caller_not_allowed), is licensing_unavailable and never an unrestricted list
PROVIDER["object"], PROVIDER["missing"] = None, True
out = src.read_allowed_modules()
assert out["state"] == "licensing_unavailable" and out["ok"] is False and out["modules"] == [] and out["count"] == 0
PROVIDER["missing"] = False
for exc in (RuntimeError("x"), PermissionError("caller_not_allowed"), KeyError("k")):
    use(Fake(raises=exc))
    out = src.read_allowed_modules()
    assert out["state"] == "licensing_unavailable" and out["modules"] == [] and str(exc) not in out["message"], out
use(None)
assert src.read_allowed_modules()["state"] == "licensing_unavailable"  # a provider that is None answers nothing

# 5. non-ok Licensing states pass through with a message and no rows, even if the provider sent rows
for state in ("not_fetched", "cached_x", "plan_expired", "plan_invalid", "licence_revoked", "licence_grace_expired", "not_registered"):
    if state == "cached_x":
        continue
    a = good_answer(state=state, ok=False, message="Licensing says: " + state)
    out = src.read_allowed_modules() if use(Fake(a)) else None
    assert out["state"] == state and out["ok"] is False and out["modules"] == [] and out["count"] == 0 and out["message"], (state, out)
a = good_answer(state="plan_expired", ok=False, message="Plan \x00ended.\n" + "y" * 900)
out = src.read_allowed_modules() if use(Fake(a)) else None
assert out["message"] and len(out["message"]) <= 400 and "\x00" not in out["message"]

# 6. refresh: ok and cached carry the list, other states do not
fake = use(Fake(good_answer()))
out = src.refresh_allowed_modules()
assert out["state"] == "ok" and out["count"] == 6
out = src.refresh_allowed_modules() if use(Fake(good_answer(state="cached", message="x"))) else None
assert out["state"] == "cached" and out["ok"] is True and out["count"] == 6
out = src.refresh_allowed_modules() if use(Fake(good_answer(state="plan_unavailable", ok=False))) else None
assert out["state"] == "plan_unavailable" and out["modules"] == []
use(Fake(raises=RuntimeError("down")))
assert src.refresh_allowed_modules()["state"] == "licensing_unavailable"

# 7. the frame rule: the first frame outside Licensing is licensing_catalogue_source.py for list, refresh and set_selection
fake = use(Fake(good_answer(), selection={"ok": True, "state": "saved", "message": "Saved.", "module_id": "halopsa", "selected": False,
                                          "before": [], "after": ["halopsa"]}))
src.read_allowed_modules()
src.refresh_allowed_modules()
saved = src.set_premium_selection("halopsa", False)
assert saved["state"] == "saved", saved
assert fake.frames and set(fake.frames) == {"licensing_catalogue_source.py"}, fake.frames
assert len(fake.frames) == 4  # list, refresh, the list read inside set_premium_selection, set_selection

# 8. set_premium_selection
sel_answer = {"ok": True, "state": "saved", "message": "Saved.", "module_id": "halopsa", "selected": False, "before": ["x"], "after": ["halopsa", "x"]}


def select(module_id, selected, answer=None, selection=sel_answer, has_selection=True):
    fake = use(Fake(answer or good_answer(), selection=selection) if has_selection else NoSelection(good_answer()))
    return src.set_premium_selection(module_id, selected), fake


for module_id, expected in (("agents", "locked"), ("health", "locked"), ("nolicence", "locked"), ("ghost", "unknown_module")):
    out, fake = select(module_id, False)
    assert out["state"] == expected and out["ok"] is False and fake.selection_calls == [], (module_id, out)
for module_id, selected in (("Bad Id", False), ("", False), (None, False), (5, True), ("halopsa", "false"), ("halopsa", 0), ("halopsa", None), ("../x", True)):
    out, fake = select(module_id, selected)
    assert out["state"] == "bad_request" and fake.selection_calls == [] and fake.frames == [], (module_id, selected, out)
out, fake = select("halopsa", False)
assert out["ok"] is True and out["state"] == "saved" and out["before"] == ["x"] and out["after"] == ["halopsa", "x"] and out["selected"] is False
assert fake.selection_calls == [("halopsa", False)]
out, fake = select("huntress", True, selection={"state": "saved", "before": ["huntress"], "after": []})
assert out["state"] == "saved" and fake.selection_calls == [("huntress", True)]
# a required_by refusal from Licensing is passed on
out, fake = select("needed", False, selection={"ok": False, "state": "required_by", "message": "m", "required_by": ["halopsa"]})
assert out["state"] == "required_by" and out["required_by"] == ["halopsa"] and out["ok"] is False
# a malformed before/after is not passed on
out, _ = select("halopsa", False, selection={"state": "saved", "before": "x", "after": []})
assert out["state"] == "invalid_response" and out["before"] == [] and out["after"] == []
# a nonsense or missing answer
out, _ = select("halopsa", False, selection="nope")
assert out["state"] == "invalid_response"
out, _ = select("halopsa", False, selection={"state": "plan_expired"})
assert out["state"] == "licensing_unavailable"
# a provider without set_selection: licensing_unavailable, and no other path is tried
out, fake = select("halopsa", False, has_selection=False)
assert out["state"] == "licensing_unavailable" and out["ok"] is False and fake.selection_calls == []
# the list itself unavailable or not ok: nothing is changed
use(Fake(raises=RuntimeError("down"), selection=sel_answer))
assert src.set_premium_selection("halopsa", False)["state"] == "licensing_unavailable"
out, fake = select("halopsa", False, answer=good_answer(state="not_fetched", ok=False))
assert out["state"] == "not_fetched" and fake.selection_calls == []

# 9. source-level checks of the views and the urls
views = (PKG_DIR / "module_allowed_views.py").read_text(encoding="utf-8")
repo_views = (PKG_DIR / "module_repository_views.py").read_text(encoding="utf-8")
# the 1.17.103 test keeps module_repository_views.py cache-only
assert "licensing_catalogue_source" not in repo_views and "ModuleAllowed" not in repo_views
urls = (PKG_DIR / "urls.py").read_text(encoding="utf-8")
for cls in ("ModuleAllowedCatalogView", "ModuleAllowedRefreshView", "ModuleAllowedSelectionView"):
    match = re.search(r"class %s\(APIView\):\n(.*?)(?=\n\n\n|\Z)" % cls, views, re.S)
    assert match, cls
    block = match.group(1)
    assert "permission_classes = [SessionAuthenticated]" in block, cls
    first_call = re.search(r"def (get|post|put)\(self, request\):\n\s+(\S.*)", block)
    assert first_call and first_call.group(2) == "_require_module_manager(request.user)", cls
    assert "licensing_catalogue_source." in block and "get_capability" not in block and "provider" not in block.lower(), cls
    assert "return Response(body" in block and "Response(answer" not in block, cls
assert "ModuleAllowedCatalogView(APIView)" in views and re.search(r"@extend_schema_view\(get=extend_schema\(tags=\[\"Tec-Tac Framework\"\]", views)
assert "def put(self, request)" in views and "def post(self, request)" in views
assert views.count('action="run"') == 1 and views.count('action="modify"') == 1 and views.count('action="deny"') == 1
assert 'module_id="core"' in views and "audit.record(" in views
assert "get_capability" not in views and "licensing.allowed_modules" not in views
for needle in ('path("modules/catalog/allowed/", ModuleAllowedCatalogView.as_view()',
               'path("modules/catalog/allowed/refresh/", ModuleAllowedRefreshView.as_view()',
               'path("modules/catalog/allowed/selection/", ModuleAllowedSelectionView.as_view()'):
    assert needle in urls, needle
contracts = (PKG_DIR / "contracts.py").read_text(encoding="utf-8")
for route in ("/api/tfd/modules/catalog/allowed/", "/api/tfd/modules/catalog/allowed/refresh/", "/api/tfd/modules/catalog/allowed/selection/"):
    assert '"%s": {' % route in contracts, route
openapi_text = (PKG_DIR / "openapi.py").read_text(encoding="utf-8")
assert "/api/tfd/modules/catalog/allowed/" in openapi_text
# the callback map classifies the module that holds the three views (core_group_for_callback keys on the view module name)
assert re.search(r'"tec_tac\.module_allowed_views":\s*"Tec-Tac [^"]*Module Repository"', openapi_text)
docs = (ROOT / "docs" / "module-repositories.md").read_text(encoding="utf-8")
assert "modules/catalog/allowed/selection/" in docs and "core.privileged_operations" in docs

# 10. the provider is called only from licensing_catalogue_source.py, and the file stays Django-free
text = (PKG_DIR / "licensing_catalogue_source.py").read_text(encoding="utf-8")
assert "import django" not in text and "from django" not in text
for other in PKG_DIR.glob("*.py"):
    if other.name not in ("licensing_catalogue_source.py", "contracts.py"):
        assert "get_capability(ALLOWED_CAPABILITY_ID" not in other.read_text(encoding="utf-8"), other.name
print("allowed modules routes 1.18.10: PASS")

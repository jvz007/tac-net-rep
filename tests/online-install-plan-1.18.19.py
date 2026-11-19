#!/usr/bin/env python3
"""Regression: Core 1.18.19 read-only install plan (POST /api/tfd/modules/catalog/online/plan/). Django-free: the allowed list comes from
licensing_catalogue_source with a fake provider, the plan builder gets injected collaborators, and the view, urls and contract are
checked at source level. The real resolve_install_plan is proven at source level only (it needs Django and module state)."""
import ast
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

PROVIDER = {"object": None}
caps_stub = types.ModuleType("tec_tac.capabilities")


def get_capability(capability_id, version=None):
    assert capability_id == "licensing.allowed_modules", capability_id
    if PROVIDER["object"] is None:
        raise LookupError("not installed")
    return PROVIDER["object"]


caps_stub.get_capability = get_capability
sys.modules["tec_tac.capabilities"] = caps_stub
src = importlib.import_module("tec_tac.licensing_catalogue_source")
plan = importlib.import_module("tec_tac.module_install_plan")

RID = {}


def rid(mid):
    return RID.setdefault(mid, f"00000000-0000-4000-8000-{len(RID) + 1:012d}")


def arow(mid, category="premium", *, selected=True, release=True, version="1.0.0", availability="available", entitled=True):
    item = {"id": mid, "name": mid.title(), "category": category, "entitled": entitled, "availability": availability, "locked": False,
            "optional": True, "selected": selected, "in_plan": release, "required_by": [], "notes": [], "category_source": "licensing", "release": None}
    if release:
        item["release"] = {"release_id": rid(mid), "version": version, "sha256": "a" * 64, "publisher_id": "pub", "key_id": "key", "channel": "stable",
                           "dependencies": {}}
    return item


def answer(rows, **top):
    out = {"ok": True, "state": "ok", "message": "Done.", "plan_revision": 3, "channel": "stable", "plan_issued_at": "x", "plan_expires_at": "y",
           "plan_state": "valid", "fetched_at": "2026-11-19T08:00:00Z", "from_cache": True, "count": len(rows), "modules": rows, "last_refresh_state": None}
    out.update(top)
    return out


class Fake:
    def __init__(self, ans):
        self.ans, self.calls, self.frames = ans, [], []

    def list_modules(self):
        self.calls.append("list_modules")
        self.frames.append(Path(sys._getframe(2).f_code.co_filename).name)
        return copy.deepcopy(self.ans)

    def __getattr__(self, name):
        raise AssertionError("the plan must only call list_modules, not " + name)


def cache(mid, version="1.0.0", deps=None, **extra):
    row = {"id": mid, "name": mid.title(), "version": version, "release_id": rid(mid), "dependencies": deps or {}, "optional_dependencies": {},
           "requires": {}, "category": "premium"}
    row.update(extra)
    return (mid, rid(mid)), row


def ver(text):
    return tuple(int(x) for x in text.split("."))


def satisfies(version, constraint):
    constraint = (constraint or "").strip()
    if not constraint or constraint == "*":
        return True
    for part in constraint.split(","):
        m = re.fullmatch(r"(==|>=|<=|>|<)?\s*(\d+\.\d+\.\d+)", part.strip())
        assert m, constraint
        op, want = m.group(1) or "==", ver(m.group(2))
        got = ver(version)
        if not {"==": got == want, ">=": got >= want, "<=": got <= want, ">": got > want, "<": got < want}[op]:
            return False
    return True


def problem_text(problem):
    return "fake " + str(problem.get("type"))


class Resolver:
    """Mimics resolve_install_plan's problem shapes: missing and out-of-range dependencies, injected problems, input-order topological order."""

    def __init__(self, installed, inject=None):
        self.installed, self.inject, self.calls = installed, inject or (lambda ids: []), []

    def __call__(self, candidates):
        ids = [c["id"] for c in candidates]
        self.calls.append(ids)
        assert len(set(ids)) == len(ids)
        problems = list(self.inject(ids))
        future = {k: v["extension_version"] for k, v in self.installed.items()}
        future.update({c["id"]: c["extension_version"] for c in candidates})
        for c in candidates:
            for dep, constraint in c["dependencies"].items():
                if dep not in future:
                    problems.append({"module": c["id"], "type": "missing_dependency", "dependency": dep, "constraint": constraint})
                elif not satisfies(future[dep], constraint):
                    problems.append({"module": c["id"], "type": "dependency_version", "dependency": dep, "constraint": constraint, "version": future[dep]})
        order, left = [], {c["id"]: {d for d in c["dependencies"] if d in ids} for c in candidates}
        while left:
            ready = [m for m, d in left.items() if not d]
            if not ready:
                problems.append({"type": "cycle_problem", "modules": sorted(left)})
                break
            for m in ready:
                order.append(m)
                left.pop(m)
            for d in left.values():
                d.difference_update(ready)
        actions = [{"id": m, "version": next(c["extension_version"] for c in candidates if c["id"] == m), "action": "replace" if m in self.installed else "install",
                    "current_version": self.installed.get(m, {}).get("extension_version")} for m in order]
        return {"valid": not problems, "problems": problems, "optional_dependencies": [], "order": order, "actions": actions, "will_disable": []}


def run(selection, rows, caches, installed=None, inject=None, protected=frozenset({"example"}), disabled=()):
    PROVIDER["object"] = fake = Fake(answer(rows))
    allowed = src.read_allowed_modules()
    installed = installed or {}
    resolver = Resolver(installed, inject)
    out = plan.build_plan(
        selection, allowed, dict(caches), installed, resolver, satisfies, problem_text,
        lambda cand: "It is disabled." if cand["id"] in disabled else None, protected, lambda requires: [])
    return out, resolver, fake


def inst(mid, version="1.0.0"):
    return {"id": mid, "extension_version": version}


def blocked_codes(out):
    return {b["id"]: b["code"] for b in out["blocked"]}


# 1 happy path, two independent modules, input order kept
out, res, fake = run(["b", "a"], [arow("a"), arow("b")], [cache("a"), cache("b")])
assert out["ok"] and out["valid"] and out["state"] == "ok", out
assert [o["id"] for o in out["order"]] == ["b", "a"] and out["blocked"] == [] and out["added_dependencies"] == []
assert out["order"][0]["action"] == "install" and out["order"][0]["added"] is False and out["checks_deferred"] == plan.CHECKS_DEFERRED
assert res.calls == [["b", "a"]]
assert out["plan_state"] == "valid" and out["plan_revision"] == 3 and out["fetched_at"] == "2026-11-19T08:00:00Z"

# 2 a missing dependency is added, ordered first
out, _, _ = run(["a"], [arow("a"), arow("dep")], [cache("a", deps={"dep": ">=1.0.0"}), cache("dep")])
assert out["valid"] and [o["id"] for o in out["order"]] == ["dep", "a"], out
assert out["added_dependencies"] == [{"id": "dep", "version": "1.0.0", "required_by": ["a"]}], out["added_dependencies"]
assert out["order"][0]["added"] is True and out["order"][0]["added_for"] == ["a"]

# 3 a dependency installed at a satisfying version is not added; an old one is replaced
out, _, _ = run(["a"], [arow("a"), arow("dep")], [cache("a", deps={"dep": ">=1.0.0"}), cache("dep")], installed={"dep": inst("dep", "1.2.0")})
assert [o["id"] for o in out["order"]] == ["a"] and out["added_dependencies"] == []
out, _, _ = run(["a"], [arow("a"), arow("dep", version="2.0.0")], [cache("a", deps={"dep": ">=2.0.0"}), cache("dep", "2.0.0")], installed={"dep": inst("dep", "1.0.0")})
assert [o["id"] for o in out["order"]] == ["dep", "a"] and out["order"][0]["action"] == "replace" and out["order"][0]["current_version"] == "1.0.0"

# 4 not selected, no release: blocked, never reach the resolver
out, res, _ = run(["n", "r", "a"], [arow("n", selected=False), arow("r", release=False), arow("a")], [cache("n"), cache("a")])
assert blocked_codes(out) == {"n": "not_selected", "r": "no_release"} and out["valid"] is False and res.calls == [["a"]], out
out, res, _ = run(["x"], [arow("a")], [])
assert blocked_codes(out) == {"x": "not_in_allowed_list"} and res.calls == []
out, _, _ = run(["u", "v"], [arow("u", availability="expired"), arow("v", entitled=False)], [cache("u"), cache("v")])
assert blocked_codes(out) == {"u": "not_available", "v": "not_available"}

# 5 no matching cache release id, and a download_unavailable row
out, res, _ = run(["a", "b"], [arow("a"), arow("b")], [cache("b", download_unavailable=True), (("a", "99999999-9999-4999-8999-999999999999"), {"id": "a"})])
assert blocked_codes(out) == {"a": "not_in_catalogue_cache", "b": "not_in_catalogue_cache"} and res.calls == [], out
assert "Sync" in out["blocked"][0]["message"]

# 6 allowed list not usable: no plan, and the view map gives the right status
status = ast.literal_eval(re.search(r"_ALLOWED_STATUS = (\{.*?\})", (PKG_DIR / "module_allowed_views.py").read_text(encoding="utf-8"), re.DOTALL).group(1))
for state, http in (("not_fetched", 200), ("licensing_unavailable", 503), ("invalid_response", 502)):
    if state == "licensing_unavailable":
        PROVIDER["object"] = None
    elif state == "invalid_response":
        PROVIDER["object"] = Fake(answer("nope"))
    else:
        PROVIDER["object"] = Fake(answer([], state="not_fetched"))
    allowed = src.read_allowed_modules()
    assert allowed["state"] == state, allowed
    out = plan.build_plan(["a"], allowed, {}, {}, None, None, None, None, frozenset(), None)
    assert out["ok"] is False and out["state"] == state and out["order"] == [] and out["blocked"] == [] and out["valid"] is False
    assert status.get(state, 200) == http, (state, status.get(state))


# 7 resolver problem blocks the module and its dependants, survivors re-resolved
def inject_runtime(ids):
    return [{"module": "dep", "type": "runtime", "component": "framework"}] if "dep" in ids else []


out, res, _ = run(["a", "c"], [arow("a"), arow("c"), arow("dep")], [cache("a", deps={"dep": "*"}), cache("c"), cache("dep")], inject=inject_runtime)
assert blocked_codes(out) == {"dep": "runtime", "a": "dependency_blocked"}, out["blocked"]
assert [o["id"] for o in out["order"]] == ["c"] and res.calls == [["a", "c", "dep"], ["c"]], res.calls
assert out["valid"] is False and out["added_dependencies"] == []
out, _, _ = run(["a"], [arow("a")], [cache("a")], inject=lambda ids: [{"module": "a", "type": "category_refused", "message": "Test modules are not installed here."}])
assert out["blocked"][0]["code"] == "category_refused" and out["blocked"][0]["message"] == "Test modules are not installed here." and out["order"] == []

# 8 an added dependency blocked by the resolver blocks what it was added for
out, _, _ = run(["a"], [arow("a"), arow("dep")], [cache("a", deps={"dep": "*"}), cache("dep")], inject=inject_runtime)
assert blocked_codes(out) == {"dep": "runtime", "a": "dependency_blocked"} and out["order"] == [] and out["valid"] is False

# 9 an unattributable problem goes to conflicts and blocks everything
out, _, _ = run(["a", "b"], [arow("a"), arow("b")], [cache("a"), cache("b")], inject=lambda ids: [{"type": "identity_migration_unavailable", "reason": "x"}])
assert blocked_codes(out) == {"a": "plan_conflict", "b": "plan_conflict"} and out["order"] == [] and len(out["conflicts"]) == 1
assert out["conflicts"][0]["type"] == "identity_migration_unavailable" and out["valid"] is False

# 10 the cap: a resolver that always finds a new problem stops at 8 rounds
names = [f"m{i}" for i in range(12)]


def always(ids):
    return [{"module": ids[0], "type": "runtime"}]


out, res, _ = run(names[:10], [arow(n) for n in names], [cache(n) for n in names], inject=always)
assert len(res.calls) == plan.MAX_ROUNDS, res.calls
assert set(blocked_codes(out).values()) == {"runtime", "plan_unstable"}, blocked_codes(out)
assert out["order"] == [] and out["valid"] is False

# 11 up front blocks
out, res, _ = run(["same", "old", "example", "off", "ok"], [arow("same"), arow("old", version="1.0.0"), arow("example"), arow("off"), arow("ok")],
                  [cache("same"), cache("old"), cache("example"), cache("off"), cache("ok")],
                  installed={"same": inst("same", "1.0.0"), "old": inst("old", "2.0.0")}, disabled={"off"})
assert blocked_codes(out) == {"same": "already_installed", "old": "older_than_installed", "example": "protected", "off": "disabled_install"}, out["blocked"]
assert res.calls == [["ok"]] and [o["id"] for o in out["order"]] == ["ok"]
assert "disabled" in next(b for b in out["blocked"] if b["id"] == "off")["message"].lower()

# 12 bad bodies, duplicates dropped
for bad in ("a", None, {"a": 1}, [], [f"m{i}" for i in range(51)], ["Upper"], ["a/b"], ["a.b"], [1], ["../x"], [""]):
    try:
        plan.clean_selection(bad)
    except plan.BadSelection:
        continue
    raise AssertionError(bad)
assert plan.clean_selection(["b", "a", "b"]) == ["b", "a"] and len(plan.clean_selection([f"m{i}" for i in range(50)])) == 50

# 13 read-only proof
PROVIDER["object"] = fake = Fake(answer([arow("a")]))
src.read_allowed_modules()
assert fake.calls == ["list_modules"] and fake.frames == ["licensing_catalogue_source.py"], (fake.calls, fake.frames)
plan_src = (PKG_DIR / "module_install_plan.py").read_text(encoding="utf-8")
code = "\n".join(line for line in plan_src.splitlines() if not line.strip().startswith("#"))
for needle in ("download_grant", "request_grant", "stage_", "queue_", "audit", "open(", "subprocess", ".write", "write_", "refresh_allowed",
               "set_premium_selection", "urllib", "requests"):
    assert needle not in code, needle

# 14 reuse proof at source level
assert "module_manager_v2.resolve_install_plan" in plan_src and "module_manager_v2._check_runtime_requirements" in plan_src
for needle in ("topological", "dependency_cycle", "def _check_runtime", "REFUSED_MESSAGE", "replacement_conflict"):
    assert needle not in plan_src, needle
v2 = (PKG_DIR / "module_manager_v2.py").read_text(encoding="utf-8")
for fn in ("def queue_v2_install", "def queue_batch_install"):
    start = v2.index(fn)
    nxt = v2.find("\ndef ", start + 10)
    assert "resolve_install_plan(" in v2[start:nxt], fn

# 15 response whitelist
out, _, _ = run(["a", "x"], [arow("a"), arow("dep")],
                [cache("a", deps={"dep": "*"}, sha256="b" * 64, download_url="https://x.example/p", publisher_id="p", key_id="k"), cache("dep")])
flat = repr(out).lower()
for needle in ("sha256", "publisher_id", "key_id", "url", "token", "a" * 64, "b" * 64, "grant", "http"):
    assert needle not in flat, needle

# source level: view, urls, contract
views = (PKG_DIR / "module_allowed_views.py").read_text(encoding="utf-8")
cls = views[views.index("class ModuleOnlineInstallPlanView"):]
assert cls.index("_require_module_manager(request.user)") < cls.index("request.data") < cls.index("plan_online_install")
assert "_audit_allowed" not in cls and "audit.record" not in cls
urls = (PKG_DIR / "urls.py").read_text(encoding="utf-8")
assert 'path("modules/catalog/online/plan/", ModuleOnlineInstallPlanView.as_view(), name="tec-tac-module-online-plan")' in urls
contracts = (PKG_DIR / "contracts.py").read_text(encoding="utf-8")
block = contracts[contracts.index('"/api/tfd/modules/catalog/online/plan/"'):]
block = block[:block.index('"/api/tfd/modules/v2/packages/inspect/"')]
assert '"POST"' in block and "core.privileged_operations" in block and "no module calls this route yet" in block and "1.18.19" in block
assert "licensing_catalogue_source" not in (PKG_DIR / "module_repository_views.py").read_text(encoding="utf-8")
docs = (ROOT / "docs" / "module-repositories.md").read_text(encoding="utf-8")
assert "catalog/online/plan/" in docs and "The plan is advice (1.18.19)" in docs
print("online install plan 1.18.19 regression: PASS")

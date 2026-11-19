"""Read-only install plan for several licensed modules (Core 1.18.19, request R1a).

The question this answers: "if the administrator ticked these modules, what would Core install, in which order, and what is in the way?"
It changes nothing. It starts no job, fetches no package, makes no network call and leaves no Core log row (like GET allowed/).

Where the facts come from:
* The allowed list: ``licensing_catalogue_source.read_allowed_modules()`` once. Licensing accepts no other caller.
* The release facts the allowed row does not carry (requires, optional dependencies, category): the Licensing repository cache row with the
  same module id AND release id, read once. No matching row means "sync, then plan again": the plan fails closed, there is no fallback.
* Every dependency, version, runtime, category, replacement and ordering rule: ``module_manager_v2.resolve_install_plan``, the same function
  the single and the batch install call. This file holds no copy of those rules.

The plan is advisory. The real install checks the signed manifest again and stays authoritative.
"""
from __future__ import annotations

import re
from typing import Any

MAX_SELECTION = 50
MAX_CLOSURE = 100
MAX_ROUNDS = 8
ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
# Checks that need the real package. The install path still runs them on the signed manifest.
CHECKS_DEFERRED = ["replacement", "rename", "signature", "licence-in-manifest"]

TEXT = {
    "not_in_allowed_list": "This licence does not list this module.",
    "not_selected": "This module is not ticked for this server. Tick it first.",
    "no_release": "The licence plan has no release of this module (the plan expired, there is none, or the module is not in the plan).",
    "not_available": "This module is not available to this licence.",
    "not_in_catalogue_cache": "Core has no saved catalogue entry for this release. Sync the repository, then plan again.",
    "protected": "This is a protected framework module and cannot be installed from here.",
    "already_installed": "This module is already installed at this version.",
    "older_than_installed": "A newer version of this module is already installed.",
    "disabled_install": "This module is disabled. Enable it, then install again.",
    "plan_conflict": "The plan has a conflict that cannot be tied to one module, so nothing is offered.",
    "plan_unstable": "The plan did not settle, so nothing is offered. Plan again with fewer modules.",
    "dependency_blocked": "A module it needs cannot be installed.",
    "bad_version": "The version of this release could not be read.",
}


class BadSelection(ValueError):
    """The request body is not a list of 1 to 50 module ids."""


def clean_selection(value: Any) -> list[str]:
    """The requested ids, duplicates dropped in order. Anything but a list of 1 to 50 well-formed ids raises BadSelection."""
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_SELECTION:
        raise BadSelection("modules must be a list of 1 to 50 module ids")
    seen: list[str] = []
    for item in value:
        if not isinstance(item, str) or not ID_RE.fullmatch(item):
            raise BadSelection("every module id must be lower case letters, digits, '-' or '_'")
        if item not in seen:
            seen.append(item)
    return seen


def _cut(value: Any, limit: int = 400) -> str:
    return " ".join(str(value or "").split())[:limit]


def build_plan(selection, allowed_body, cache_rows, installed, resolve, satisfies, problem_text, refuse_disabled, protected, runtime_check):
    """The plan as a dict. Every collaborator is passed in, so this runs without Django.

    * ``allowed_body``: the whitelisted body of ``read_allowed_modules()``.
    * ``cache_rows``: {(module id, release id): licensing cache row}.
    * ``installed``: {module id: installed row with extension_version}.
    * ``resolve(candidates)``: ``resolve_install_plan``. ``satisfies(version, constraint)``: ``version_satisfies``.
    * ``problem_text(problem)``: the resolver's own sentence. ``refuse_disabled(candidate)``: a sentence or None.
    * ``protected``: ids that are never installed from here. ``runtime_check(requires)``: the runtime checks of a candidate."""
    top = {"plan_state": allowed_body.get("plan_state"), "plan_revision": allowed_body.get("plan_revision"), "fetched_at": allowed_body.get("fetched_at")}
    base = {"ok": False, "state": allowed_body.get("state"), "message": allowed_body.get("message"), "valid": False, "requested": list(selection),
            "order": [], "added_dependencies": [], "will_disable": [], "conflicts": [], "blocked": [], "optional_dependencies": [],
            **top, "checks_deferred": list(CHECKS_DEFERRED)}
    if allowed_body.get("state") != "ok":
        return base
    allowed = {row["id"]: row for row in allowed_body.get("modules") or []}
    blocked: dict[str, dict] = {}

    def block(module_id, code, message=None, detail=None):
        if module_id not in blocked:
            blocked[module_id] = {"id": module_id, "code": code, "message": _cut(message or TEXT.get(code) or code), "detail": detail or {}}

    def offer(module_id):
        """(candidate, None) for a module Core can plan, else (None, (code, detail))."""
        if module_id in protected:
            return None, ("protected", {})
        row = allowed.get(module_id)
        if row is None:
            return None, ("not_in_allowed_list", {})
        release = row.get("release")
        if not row.get("selected"):
            return None, ("not_selected", {})
        if not release:
            return None, ("no_release", {})
        if row.get("availability") != "available" or not row.get("entitled"):
            return None, ("not_available", {"availability": row.get("availability")})
        cache = cache_rows.get((module_id, release.get("release_id")))
        if cache is None or cache.get("download_unavailable"):
            return None, ("not_in_catalogue_cache", {})
        version = str(release.get("version") or "")
        candidate = {"id": module_id, "name": cache.get("name") or row.get("name") or module_id, "extension_version": version,
                     "dependencies": dict(cache.get("dependencies") or {}), "optional_dependencies": dict(cache.get("optional_dependencies") or {}),
                     "requires": dict(cache.get("requires") or {}), "category": cache.get("category") or row.get("category")}
        try:
            candidate["runtime_requirements"] = runtime_check(candidate["requires"])
            have = installed.get(module_id)
            if have is not None:
                current = have.get("extension_version") or "0.0.0"
                if satisfies(version, f"=={current}"):
                    return None, ("already_installed", {"current_version": current})
                if not satisfies(version, f">={current}"):
                    return None, ("older_than_installed", {"current_version": current})
        except (RuntimeError, ValueError, KeyError, TypeError):  # ModuleStateError and ModuleManagerV2Error are RuntimeErrors
            return None, ("bad_version", {})
        sentence = refuse_disabled(candidate)
        if sentence:
            return None, ("disabled_install", {"reason": _cut(sentence)})
        return candidate, None

    offered: dict[str, dict] = {}
    for module_id in selection:
        candidate, why = offer(module_id)
        if candidate is None:
            block(module_id, why[0], detail=why[1])
        else:
            offered[module_id] = candidate

    def closure():
        """The active candidates (requested first) and who each added one for. Blocks a module whose needed module is blocked."""
        while True:
            chosen = {mid: offered[mid] for mid in selection if mid in offered and mid not in blocked}
            added_for: dict[str, list[str]] = {}
            queue = list(chosen)
            changed = False
            while queue and not changed:
                current = queue.pop(0)
                for dep_id, constraint in (chosen[current].get("dependencies") or {}).items():
                    have = installed.get(dep_id)
                    if have is not None and _fits(satisfies, have.get("extension_version") or "0.0.0", constraint):
                        continue
                    if dep_id in blocked:
                        block(current, "dependency_blocked", f"{TEXT['dependency_blocked']} ({dep_id})", {"dependency": dep_id})
                        changed = True
                        break
                    if dep_id not in chosen:
                        if len(chosen) >= MAX_CLOSURE:
                            continue
                        candidate, _why = offer(dep_id)
                        if candidate is None or not _fits(satisfies, candidate["extension_version"], constraint):
                            continue  # left out: the shared resolver reports it as missing or out of range
                        chosen[dep_id] = candidate
                        queue.append(dep_id)
                    if dep_id not in selection:
                        by = added_for.setdefault(dep_id, [])
                        if current not in by:
                            by.append(current)
            if not changed:
                return chosen, added_for

    result = None
    chosen: dict[str, dict] = {}
    added_for: dict[str, list[str]] = {}
    unstable = False
    for round_number in range(1, MAX_ROUNDS + 1):
        chosen, added_for = closure()
        if not chosen:
            result = None
            break
        result = resolve(list(chosen.values()))
        problems = result.get("problems") or []
        if not problems:
            break
        before = set(blocked)
        unattributed = []
        for problem in problems:
            names = _attribute(problem, chosen)
            if not names:
                unattributed.append(problem)
                continue
            for name in names:
                block(name, str(problem.get("type") or "plan_conflict"), _problem_message(problem, problem_text), {"dependency": problem.get("dependency")} if problem.get("dependency") else {})
        if unattributed:
            conflicts = [_conflict(p, problem_text) for p in unattributed]
            for name in chosen:
                block(name, "plan_conflict")
            return _finish(base, selection, blocked, {}, {}, None, conflicts)
        if set(blocked) == before:
            unstable = True
            break
        result = None
    else:
        unstable = True
    if unstable:
        for name in chosen:
            block(name, "plan_unstable")
        return _finish(base, selection, blocked, {}, {}, None, [])
    return _finish(base, selection, blocked, chosen, added_for, result, [])


def _fits(satisfies, version, constraint) -> bool:
    try:
        return bool(satisfies(version, constraint))
    except (RuntimeError, ValueError, TypeError):
        return False


def _attribute(problem: dict, chosen: dict) -> list[str]:
    """The planned modules a problem belongs to. A broken installed dependant is tied to the package that breaks it."""
    if problem.get("type") == "breaks_dependant":
        name = problem.get("dependency")
        return [name] if name in chosen else []
    if isinstance(problem.get("modules"), list):
        return [name for name in problem["modules"] if name in chosen]
    name = problem.get("module")
    return [name] if name in chosen else []


def _problem_message(problem: dict, problem_text) -> str:
    own = problem.get("message")
    return _cut(own if isinstance(own, str) and own.strip() else problem_text(problem))


def _conflict(problem: dict, problem_text) -> dict:
    return {"type": str(problem.get("type") or "conflict"), "module": problem.get("module"), "dependency": problem.get("dependency"),
            "constraint": problem.get("constraint"), "version": problem.get("version"), "message": _problem_message(problem, problem_text)}


def _finish(base, selection, blocked, chosen, added_for, result, conflicts):
    body = dict(base)
    body["ok"] = True
    body["blocked"] = [blocked[mid] for mid in blocked]
    body["conflicts"] = conflicts
    body["valid"] = not any(mid in blocked for mid in selection)
    if result is not None and not conflicts:
        actions = {item["id"]: item for item in result.get("actions") or []}
        order = []
        for module_id in result.get("order") or []:
            item = actions.get(module_id, {})
            order.append({"id": module_id, "name": chosen[module_id].get("name") or module_id, "version": item.get("version") or chosen[module_id]["extension_version"],
                          "action": item.get("action") if item.get("action") in ("install", "replace") else "install",
                          "current_version": item.get("current_version"), "added": module_id not in selection,
                          "added_for": list(added_for.get(module_id, [])), "dependencies": dict(chosen[module_id].get("dependencies") or {})})
        body["order"] = order
        body["added_dependencies"] = [{"id": mid, "version": chosen[mid]["extension_version"], "required_by": list(by)} for mid, by in added_for.items() if mid in chosen]
        body["will_disable"] = list(result.get("will_disable") or [])
        body["optional_dependencies"] = [{"module": o.get("module"), "dependency": o.get("dependency"), "constraint": o.get("constraint"),
                                          "installed": bool(o.get("installed")), "satisfied": bool(o.get("satisfied"))} for o in result.get("optional_dependencies") or []]
    return body


def plan_online_install(selection: list[str]) -> dict:
    """Wire the real collaborators and build the plan. Imports are lazy so the pure part above tests without Django."""
    from . import licensing_catalogue_source, module_manager_v2, module_repository
    from .module_manager import PROTECTED_PLUGIN_IDS
    from .module_state import version_satisfies

    allowed_body = licensing_catalogue_source.read_allowed_modules()
    if allowed_body.get("state") != "ok":
        return build_plan(selection, allowed_body, {}, {}, None, None, None, None, frozenset(), None)
    repos = [repo for repo in module_repository.list_repositories() if repo.get("kind") == "licensing" and repo.get("enabled", True)]
    development = module_repository.is_development_server() if repos else False
    cache_rows: dict[tuple, dict] = {}
    for repo in repos:
        for item in module_repository._cached_modules(repo, development=development):
            cache_rows.setdefault((item.get("id"), item.get("release_id")), item)
    installed = {item["id"]: item for item in module_manager_v2.installed_catalog_v2() if not item.get("legacy")}

    def refuse_disabled(candidate):
        try:
            module_manager_v2._refuse_disabled_install(candidate)
        except module_manager_v2.ModuleManagerV2Error as exc:
            return str(exc)
        return None

    return build_plan(selection, allowed_body, cache_rows, installed, module_manager_v2.resolve_install_plan, version_satisfies,
                      module_manager_v2._problem_text, refuse_disabled, PROTECTED_PLUGIN_IDS, module_manager_v2._check_runtime_requirements)

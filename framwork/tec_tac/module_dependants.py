"""Which installed modules depend on the calling module (Core 1.17.71; capability ``core.module_dependants`` 1.0.0).

Why. Groups must not let a person delete a group that something still uses (Johan, 21 October 2026: "if any group is used somewhere and not allow
it to be delete"). Groups cannot know who uses it unless Core tells it which installed modules name Groups in their signed manifest
``dependencies`` or ``optional_dependencies``. Groups then asks only those modules, through the contracts they publish.

What it answers. ``dependants()`` returns ``{"module": <caller id>, "dependants": [...], "complete": bool}``. Each row is exactly
``{id, name, version, relation, constraint, enabled, capabilities}``: ``relation`` is ``required`` or ``optional``, ``constraint`` is the version
constraint the dependant declared, ``enabled`` is the dependant's current state (a disabled module is still listed: its saved configuration still
points at the caller), ``capabilities`` are the ``{id, version}`` pairs the dependant's signed manifest declares. Nothing else: no routes,
permissions, settings, paths, audit events or data of the dependant. Rows are sorted by id, at most 200; ``complete`` is False when more exist, and
a caller that needs the whole answer must then treat it as "could not check". Since 1.17.72 ``complete`` is also False when another installed module's
``dependencies`` or ``optional_dependencies`` could not be read in full (a skipped entry or a key that is not an object): Core cannot know whether that module names the caller.

Who may ask (rule 1.10, AD-26). The caller is found by the frame walk of ``calling_module_for_core_provider``: only the code of an installed,
enabled, non-legacy extension is a caller. Core itself, an unverified caller, a disabled or legacy module is refused with ``DependantsRefused``.
The answer is about the calling module's own id only, so a module cannot list the dependants of another. Core calls no provider on behalf of a
module; it only reports who declared the dependency.

Fail closed. A module list or module state that cannot be read raises ``DependantsUnavailable``; it never answers an empty list.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("tec_tac.module_dependants")

CAPABILITY_ID = "core.module_dependants"
CAPABILITY_VERSION = "1.0.0"
MAX_ROWS = 200
ROW_KEYS = ("id", "name", "version", "relation", "constraint", "enabled", "capabilities")

REFUSED_TEXT = "Core could not tell which module is asking, so it did not list any dependants."
UNAVAILABLE_TEXT = "Core could not read the installed modules just now, so it cannot say which modules depend on this one. Try again in a minute."


class DependantsRefused(Exception):
    """The caller is not a verified, enabled module. The text names no module."""


class DependantsUnavailable(Exception):
    """The module list or module state could not be read. Never answered as an empty list."""


def _pairs(spec, attribute: str) -> dict:
    """The ``(module id, constraint)`` pairs of a spec as text. A spec that holds anything else gives an empty map."""
    value = getattr(spec, attribute, ()) or ()
    return {str(item[0]): str(item[1]) for item in value if isinstance(item, (tuple, list)) and len(item) == 2}


def _capabilities(spec) -> list:
    value = getattr(spec, "capabilities", ()) or ()
    out = [{"id": str(item[0]), "version": str(item[1])} for item in value if isinstance(item, (tuple, list)) and len(item) == 2]
    return sorted(out, key=lambda row: (row["id"], row["version"]))


def dependants(*, context=None) -> dict:
    """The installed modules that name the calling module in their manifest ``dependencies`` or ``optional_dependencies`` (see the module docstring).

    ``context`` is accepted for symmetry with the other Core providers and is not used: the answer never depends on it."""
    from . import caller_identity

    check = caller_identity.core_provider_caller_checked(provider_file=__file__)  # the module whose own code called this function
    if check.identity is None:
        if check.unverifiable:
            raise DependantsUnavailable(UNAVAILABLE_TEXT)
        raise DependantsRefused(REFUSED_TEXT)
    caller = check.identity.module_id
    try:
        from . import module_state, registry

        state = module_state.load_state()
        if isinstance(state, dict) and state.get("_corrupt"):
            raise RuntimeError("the module state is corrupt")
        rows = []
        unreadable = []
        for spec in list(registry.discover_plugins()):
            if spec.plugin_type != "extension" or getattr(spec, "legacy", False) or spec.plugin_id == caller:
                continue
            if getattr(spec, "dependencies_incomplete", False) is True:
                unreadable.append(spec.plugin_id)
            required = _pairs(spec, "dependencies")
            optional = _pairs(spec, "optional_dependencies")
            if caller in required:
                relation, constraint = "required", required[caller]
            elif caller in optional:
                relation, constraint = "optional", optional[caller]
            else:
                continue
            rows.append({
                "id": spec.plugin_id, "name": str(getattr(spec, "name", "") or spec.plugin_id), "version": str(getattr(spec, "version", "") or "0.0.0"),
                "relation": relation, "constraint": constraint, "enabled": bool(module_state.is_enabled(spec.plugin_id, state)),
                "capabilities": _capabilities(spec),
            })
    except Exception:
        logger.warning("The dependants of a module could not be listed; failing closed.", exc_info=True)
        raise DependantsUnavailable(UNAVAILABLE_TEXT) from None
    if unreadable:
        logger.warning("The manifest dependencies of module %s could not be read in full, so the dependants answer is incomplete.", ", ".join(sorted(unreadable)))
    rows.sort(key=lambda row: row["id"])
    return {"module": caller, "dependants": rows[:MAX_ROWS], "complete": len(rows) <= MAX_ROWS and not unreadable}


class _DependantsProvider:
    def dependants(self, *, context=None) -> dict:
        return dependants(context=context)


_PROVIDER = _DependantsProvider()


def module_dependants_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["dependants"],
        "python": "tec_tac.module_dependants.dependants(*, context=None) -> {module, dependants: [{id, name, version, relation, constraint, enabled, capabilities: [{id, version}]}], complete}",
        "returns": list(ROW_KEYS),
        "caller": "a verified, enabled, non-legacy module only (the frame walk of AD-26); Core, an unverified caller, a disabled or legacy module is refused with DependantsRefused",
        "answers_about": "the calling module's own id only; a module cannot list the dependants of another",
        "fails": "closed: an unreadable module list or module state raises DependantsUnavailable and is never an empty list; complete is False above 200 rows",
        "calls_provider_for_module": False,
        "requires_framework": ">=1.17.71",
    }


def register_core_module_dependants_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Which installed modules name the calling module in their signed dependencies (ids and declared lists only).",
        operations=("dependants",),
        metadata=module_dependants_contract_metadata(),
    )

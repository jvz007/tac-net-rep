"""Module-owned target resolvers: how a module-owned target type reads as Tactical endpoints (Core 1.17.68, the target-resolver contract).

Why. A schedule's targets can be a Tactical client, site, endpoint or dynamic scope, which Core reads itself, or a type that a module owns (a
Maintenance or Advanced Patch Management profile, for example). Core cannot read a module's type, so a system action on such a schedule was
refused as ``targets_unresolved`` since 1.17.62. This module is the way the owning module tells Core, once and in memory, how its type resolves
to endpoints. It is the contract that request asked for. There is no private path beside it.

What a module does, from ``AppConfig.ready()`` and from its own code:

    from tec_tac.scheduler_target_resolvers import register_target_resolver
    register_target_resolver("maintenance", "profile", resolve_profile_targets)

    def resolve_profile_targets(targets: dict):          # read-only and fast; runs in the caller's process
        return [...]                                     # Tactical agent numbers (whole numbers) or agent ids (text)

Rules, all fail closed.
* The caller is verified from the call stack (``core.caller_identity``) and must be the module named by ``module_id``.
* The target type must belong to the module: it may not be ``none``, ``client``, ``site``, ``endpoint``, ``agent`` (or their plurals) or
  ``dynamic``, and it must be listed in ``target_types`` of one of that module's registered scheduled actions. That is checked at registration
  when the module already has a scheduled action, and again at every use.
* A different resolver under the same key is refused. The same one again is accepted.
* Core canonicalises every returned id to a Tactical agent number and checks that the endpoint exists. A bad id, an id that names no endpoint, an
  id that is ambiguous (a number that is one endpoint's number and another endpoint's id), more than ``MAX_AGENTS`` ids, a result that is not a
  list, and any exception, all mean "unresolved". Nothing is guessed, narrowed or truncated, and the caller then refuses as before.

This resolves to endpoints and decides no right: who may use the endpoints is still decided by the person's scope (at creation) or by the schedule's
creation-time scope (``scheduler_creation_scope``, for an unattended run).

The honest limit. The resolver is module code that runs inside Core's process, as every module does. Core cannot stop a resolver that returns
endpoints it should not have: that is why the result is always intersected with a person's scope or a stored scope before anything is sent.
"""
from __future__ import annotations

import copy
import logging
import re
import threading
from itertools import islice

from .caller_identity import calling_module_for_core_provider

logger = logging.getLogger("tec_tac.scheduler")

# The types Core reads itself (scheduler_targets._NATIVE_KIND, plus none and dynamic). A module may not take one of them over.
NATIVE_TARGET_TYPES = frozenset({"", "none", "client", "clients", "site", "sites", "endpoint", "endpoints", "agent", "agents", "dynamic"})
_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
MAX_TOKEN_CHARS = 64
_CHUNK = 5000

_RESOLVERS: dict[tuple[str, str], object] = {}
_LOCK = threading.RLock()


class TargetResolverRegistrationError(ValueError):
    """``register_target_resolver`` refused the registration. A module wraps the call, logs and goes on, so Tactical always starts."""


# The few places this module reads Core. Each is one small function so a test can replace it without Django.
def _actions_of(module_id: str) -> tuple:
    from .scheduler import scheduled_actions

    return tuple(a for a in scheduled_actions() if a.module_id == module_id)


def _max_agents() -> int:
    from .system_actions import MAX_AGENTS

    return MAX_AGENTS


def _pks_for(identifiers) -> set:
    from . import resources_adapter

    return resources_adapter.agent_pks_for_identifiers(identifiers=identifiers)


def target_type_of(targets) -> str | None:
    """The module-owned target type of a canonical targets object, or None when it is not a module-owned type."""
    if not isinstance(targets, dict):
        return None
    kind = str(targets.get("type") or "").strip().lower()
    return None if kind in NATIVE_TARGET_TYPES else kind


def _declared(module_id: str, target_type: str) -> bool:
    """Is ``target_type`` listed in the target types of a scheduled action of ``module_id`` right now? The use-time rule: with no such action it is False."""
    return any(target_type in action.target_types for action in _actions_of(module_id))


def register_target_resolver(module_id, target_type, resolver) -> None:
    """Register how ``target_type`` of module ``module_id`` reads as endpoints (Core 1.17.68). Memory only; call it from ``AppConfig.ready()``.

    Raises ``TargetResolverRegistrationError`` (a ValueError) for: a caller that is not module ``module_id``'s own code, a type Core reads itself or
    a type that is not a plain lowercase word, a type that none of the module's scheduled actions lists, a resolver that is not callable, and a
    different resolver already registered under the same key. Registering the same resolver again is accepted."""
    identity = calling_module_for_core_provider(provider_file=__file__)
    if identity is None or not isinstance(module_id, str) or identity.module_id != module_id:
        raise TargetResolverRegistrationError("Only the module itself may register a target resolver, from its own code.")
    kind = target_type.strip() if isinstance(target_type, str) else ""
    if kind in NATIVE_TARGET_TYPES or not _TYPE_RE.fullmatch(kind):
        raise TargetResolverRegistrationError("The target type must be a lowercase word that is not none, client, site, endpoint, agent or dynamic.")
    if not callable(resolver):
        raise TargetResolverRegistrationError("The resolver must be a function that takes the targets object.")
    try:
        actions = _actions_of(module_id)
    except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
        raise TargetResolverRegistrationError("Core could not read the module's scheduled actions.") from None
    if actions and not any(kind in action.target_types for action in actions):
        raise TargetResolverRegistrationError("The target type is not listed in target_types of any scheduled action of this module.")
    key = (module_id, kind)
    with _LOCK:
        previous = _RESOLVERS.get(key)
        if previous is not None and previous is not resolver and (
            getattr(previous, "__module__", None) != getattr(resolver, "__module__", None)
            or getattr(previous, "__qualname__", None) != getattr(resolver, "__qualname__", None)
        ):
            raise TargetResolverRegistrationError("A different resolver is already registered for this target type.")
        _RESOLVERS[key] = resolver


def has_resolver(module_id, target_type) -> bool:
    """Is a resolver registered in this process for the module's type, and does a scheduled action of the module still list the type? Never raises."""
    try:
        kind = target_type.strip().lower() if isinstance(target_type, str) else ""
        with _LOCK:
            registered = (module_id, kind) in _RESOLVERS
        return registered and _declared(module_id, kind)
    except Exception:  # noqa: BLE001 - fail closed: a fault here must never raise out of this path
        return False


def resolve_agent_pks(module_id, targets) -> set | None:
    """The Tactical agent numbers a module-owned ``targets`` object names, or None when Core cannot read it (no resolver, an undeclared type, an
    exception, a bad, missing or ambiguous id, or more than ``MAX_AGENTS`` ids). Never raises. Nothing is guessed, narrowed or truncated."""
    try:
        kind = target_type_of(targets)
        if kind is None or not has_resolver(module_id, kind):
            return None
        with _LOCK:
            resolver = _RESOLVERS[(module_id, kind)]
        limit = _max_agents()
        returned = resolver(copy.deepcopy(targets))
        if returned is None or isinstance(returned, (str, bytes, dict)):
            return None
        tokens = list(islice(iter(returned), limit + 1))
        if len(tokens) > limit:
            logger.warning("The target resolver of module %s returned more than %s ids; the targets are unresolved.", module_id, limit)
            return None
        clean = []
        for token in tokens:
            if isinstance(token, bool):
                return None
            if isinstance(token, int):
                if not 0 < token < 2**63:
                    return None
            elif isinstance(token, str):
                token = token.strip()
                if not token or len(token) > MAX_TOKEN_CHARS or not token.isprintable():
                    return None
            else:
                return None
            clean.append(token)
        if not clean:
            return set()
        return {int(pk) for pk in _pks_for(list(dict.fromkeys(clean)))}
    except Exception:
        logger.warning("The target resolver of module %s could not resolve its targets; they are unresolved.", module_id, exc_info=True)
        return None


def _clear_for_tests() -> None:
    with _LOCK:
        _RESOLVERS.clear()

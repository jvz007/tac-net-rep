"""Verified calling-module identity for a provider's service functions (Core 1.17.21, Johan CQ65 a, AD-26).

A provider module (globalsettings.email is the first) sometimes needs to know which module's code is calling it, so it can
refuse a caller it does not allow. Until now a caller named itself in an argument or in a context dict, and nothing checked it.
``calling_module`` answers from the call itself. Nothing is passed in by the caller.

The identity names signed modules only. Core itself is never a caller (AD-26 condition 2): no frame, entry or path answers Core.

How it decides. Core walks the Python stack upward from the frame that called ``calling_module`` and judges each frame by the real
path of its code file:

1. The frame that called ``calling_module`` must be inside the provider's own plugin folder. The provider's frames that follow one
   another directly are skipped, so the provider may call this from any depth of its own code.
2. The first frame after the provider's frames is the caller, and only that frame. When it is inside the folder of an installed module
   that is an ``extension``, not legacy and enabled right now, the answer is that module. The enabled state is read on every call and
   never cached.
3. Anything else in that position gives ``None``, and the walk never looks further up: a frame in a disabled, legacy or unreadable
   module, a frame inside the ``tec_tac`` package (the Scheduler's executor, a row lookup, signal dispatch, ``send_p1_email``), a frame
   with a generated file name such as ``<string>``, and a standard-library, Django, Celery or other third-party frame. So no gap is
   skipped between the provider and the module (AD-26 condition 3): a module's callable that Core or a library runs (a Scheduler handler,
   a row lookup, a signal receiver, a ``functools.partial`` of a provider function) is that module only when its own code frame calls the
   provider directly, else ``None``.
4. A provider must treat ``None`` as refuse.

Any error reading the registry or the module state gives ``None`` (fail closed).

Limits, in plain words (also in docs/caller-identity.md and the contract export):

* Core is never a caller. A module's callable that Core runs (a Scheduler handler, a row lookup, a signal receiver, a functools.partial
  of a provider function) is that module only when its own frame calls the provider directly; a Core, library or generated frame in
  between gives None, which a provider must refuse.
* A module that calls another module's code is seen as the module whose code makes the call. So an allow-list of modules is only as
  strong as every allowed module's callback surface: an allowed module that runs callables other modules hand it (a hook list, a signal
  it sends) can be made to call the provider for them. A provider allows only modules whose code it trusts that far.
* Code that forges its own file name (``compile()`` with another module's path) is hostile code. Signed-module review stays the defence.
* Identity says which module's code is calling, not which person. A provider still checks the person or the service purpose itself.

This module changes nothing else: ``ResourceAccessContext``, ``trusted_service_context``, ``build_operation_context`` and
``notices.publish`` behave as before.
"""
from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("tec_tac.caller_identity")

CAPABILITY_ID = "core.caller_identity"
CAPABILITY_VERSION = "1.0.0"
KIND_MODULE = "module"

_FRAMEWORK_DIR = Path(__file__).resolve().parent  # .../tec_tac: a frame in here is Core, and Core is never a caller

LIMITS = (
    "Core is never a caller: a module's callable that Core runs (a Scheduler handler, a row lookup, a signal receiver, a functools.partial of a provider function) is that module only when its own frame calls the provider directly; a Core, library or generated (<...>) frame in between gives None.",
    "A module that calls another module's code is seen as the module whose code makes the call, so an allow-list of modules is only as strong as every allowed module's callback surface (hooks or signals it runs for other modules).",
    "Code that forges its own file name (compile() with another module's path) is hostile code; signed-module review stays the defence.",
    "Identity says which module's code is calling, not which person; a provider still checks the person or the service purpose itself.",
)


@dataclass(frozen=True)
class CallerIdentity:
    """Which module's code is calling. ``kind`` is always ``module``: Core is never a caller (AD-26)."""

    module_id: str
    kind: str
    module_version: str


def _norm(path) -> str:
    return os.path.normcase(os.path.realpath(str(path)))


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _plugins() -> tuple:
    """Every installed plugin, read from disk on each call (no cache: a module installed a moment ago must be seen)."""
    from . import registry

    return tuple(registry.discover_plugins())


def _enabled(module_id: str) -> bool:
    from . import module_state

    return bool(module_state.is_enabled(module_id))


FAILED_READ_SECONDS = 1  # a failed scan or state read is kept this long at most (1.17.48): a short fault must not cost a whole window


class _ReadFault(Exception):
    """The module list or a module's state could not be read, so the caller cannot be verified (not the same as a foreign caller)."""


class _Snapshot:
    """One short-lived read of the installed modules and their enabled flags (the opt-in cache of ``calling_module_for_core_provider``).
    A new snapshot replaces the old one whole, so no lock is needed. ``plugins`` is ``None`` when the scan failed: that is kept for
    ``FAILED_READ_SECONDS`` at most (``lifetime``), not the full window."""

    __slots__ = ("at", "enabled", "faults", "lifetime", "norms", "plugins")

    def __init__(self, at, plugins, lifetime):
        # ``norms`` keeps the real path of each file name seen in this window: ``realpath`` is a system call per path part and is the
        # largest cost of the frame walk, so the opt-in path asks the disk once a window and not once a frame.
        self.at, self.plugins, self.lifetime = at, plugins, lifetime
        self.enabled, self.norms, self.faults = {}, {}, {}

    def norm(self, path) -> str:
        key = str(path)
        known = self.norms.get(key)
        if known is None:
            known = self.norms[key] = _norm(key)
        return known


_clock = time.monotonic  # a test replaces it
_SNAPSHOT: list = [None]


def clear_snapshot_for_tests() -> None:
    _SNAPSHOT[0] = None


def _snapshot(seconds: float) -> _Snapshot:
    now = _clock()
    snap = _SNAPSHOT[0]
    if snap is not None and 0 <= now - snap.at < min(seconds, snap.lifetime):
        return snap
    try:
        plugins = _plugins()
        lifetime = seconds
    except Exception:
        lifetime = min(seconds, FAILED_READ_SECONDS)
        logger.warning("Could not read the installed modules; callers stay unverifiable for %s second(s).", lifetime, exc_info=True)
        plugins = None
    snap = _Snapshot(now, plugins, lifetime)
    _SNAPSHOT[0] = snap
    return snap


def _enabled_checked(module_id: str) -> bool:
    """``_enabled``, but a corrupt module state is a fault and not 'disabled'. The second read happens only when the module reads as disabled."""
    value = _enabled(module_id)
    if not value:
        from . import module_state

        state = module_state.load_state()
        if isinstance(state, dict) and state.get("_corrupt"):
            raise _ReadFault("the module state is corrupt")
    return value


def _snapshot_enabled(snap: _Snapshot, module_id: str) -> bool:
    """The enabled flag from the snapshot. A good read is kept for the window. A fault (an unreadable or corrupt state) raises
    ``_ReadFault`` and is remembered for ``FAILED_READ_SECONDS`` only, then read again."""
    known = snap.enabled.get(module_id)
    if known is not None:
        return known
    now = _clock()
    failed_at = snap.faults.get(module_id)
    if failed_at is not None and 0 <= now - failed_at < FAILED_READ_SECONDS:
        raise _ReadFault(module_id)
    try:
        value = _enabled_checked(module_id)
    except Exception:
        logger.warning("Could not read the enabled state of module %s; its caller cannot be verified for %s second(s).", module_id,
                       FAILED_READ_SECONDS, exc_info=True)
        snap.faults[module_id] = now
        raise _ReadFault(module_id) from None
    snap.faults.pop(module_id, None)
    snap.enabled[module_id] = value
    return value


def calling_module(*, provider_module_id) -> CallerIdentity | None:
    """The identity of the module whose code called the provider function that called this, or ``None`` (refuse).

    ``provider_module_id`` is the provider's own module id. The provider's own frames directly above this call are skipped, so the
    provider can call this from any depth of its own code. See the module docstring for the full rule. Never raises: any problem is
    ``None``."""
    try:
        return _calling_module(provider_module_id)
    except Exception:
        logger.warning("Could not verify the calling module; treating the caller as unverified.", exc_info=True)
        return None


def _code_path(frame, norm=None) -> str | None:
    """The real path of a frame's code file, or ``None`` for a generated (``<...>``) or empty file name."""
    filename = frame.f_code.co_filename
    if not isinstance(filename, str) or not filename or filename.startswith("<"):
        return None
    return (norm or _norm)(filename)


def _calling_module(provider_module_id) -> CallerIdentity | None:
    if not isinstance(provider_module_id, str) or not provider_module_id.strip():
        return None
    getter = getattr(sys, "_getframe", None)
    if getter is None:
        return None
    provider_id = provider_module_id.strip()
    plugins = _plugins()
    provider = next((p for p in plugins if p.plugin_id == provider_id and p.plugin_type == "extension" and not p.legacy), None)
    if provider is None:
        return None
    provider_root = _norm(provider.root)
    framework = _norm(_FRAMEWORK_DIR)

    frame = getter(2)  # frame 0 is this function and frame 1 is calling_module; 2 is the code that called calling_module
    try:
        seen_provider = False
        path = None
        while frame is not None:
            path = _code_path(frame)
            if path is None or not _under(path, provider_root):
                break
            seen_provider = True
            frame = frame.f_back
        if not seen_provider or frame is None or path is None:
            return None  # not called by the provider, nothing called the provider, or a generated frame called it: refuse
        if _under(path, framework):
            return None  # Core code (the Scheduler, a row lookup, signal dispatch, send_p1_email): Core is never a caller
        for plugin in plugins:
            if _under(path, _norm(plugin.root)):
                if plugin.plugin_type != "extension" or plugin.legacy or not _enabled(plugin.plugin_id):
                    return None  # a disabled, legacy or non-extension module: refuse, never look further up
                return CallerIdentity(plugin.plugin_id, KIND_MODULE, str(plugin.version or "0.0.0"))
        return None  # the standard library, Django, Celery or other code outside every module: no gap is skipped
    finally:
        frame = None


@dataclass(frozen=True)
class CallerCheck:
    """The answer of ``core_provider_caller_checked``: ``identity`` is the module, or ``None``. ``unverifiable`` is True when the answer is
    ``None`` only because a read failed (the module list, a module's state, the frame helper or the walk), and False for a real answer
    (the owner, another module, a disabled or legacy module, a Core, library or generated frame)."""

    identity: CallerIdentity | None
    unverifiable: bool = False


def _seconds(cache_seconds) -> float:
    try:
        value = float(cache_seconds)
    except (TypeError, ValueError):
        return 0.0
    if not value > 0 or value == float("inf"):
        return 0.0
    return value


def calling_module_for_core_provider(*, provider_file, cache_seconds: float = 0) -> CallerIdentity | None:
    """Core-internal (1.17.27, CQ87): the module whose code called a Core-owned provider function, or ``None`` (refuse).

    Not a public contract: it is not listed in the contract export and no module may import it. A Core provider (tec_tac.accounts) calls
    it from its own function, with its own ``__file__``. Every frame in that file is skipped, however deep the provider's own calls go.
    The first other frame is the caller, and only that frame: it gives a module only when it is the code of an installed, enabled,
    non-legacy extension. A Core frame, a library or Django frame, a generated (``<...>``) frame, a disabled or legacy module and any error
    give ``None``. Core is never identified (AD-26 condition 2): this names module code and nothing else. Enabled state is read on every call
    unless the provider opts in with ``cache_seconds`` (1.17.47, event jobs: a path that runs on every Tactical alert save). With
    ``cache_seconds`` above 0 the installed modules and each enabled flag come from a process-local snapshot kept that long; a failed read
    is kept for ``FAILED_READ_SECONDS`` at most (1.17.48) and refuses (fail closed). The frame walk is never cached. At 0 (the default)
    nothing is cached. Since 1.17.48 a thin wrapper over the same walk as ``core_provider_caller_checked``: it cannot tell a fault from a
    foreign caller, and both are ``None``.
    """
    seconds = _seconds(cache_seconds)
    try:
        getter = getattr(sys, "_getframe", None)
        if getter is None:
            return None
        return _checked_from(getter(1), provider_file, seconds).identity  # frame 1 is the provider function that called this
    except Exception:
        logger.warning("Could not verify the calling module of a Core provider; treating the caller as unverified.", exc_info=True)
        return None


def core_provider_caller_checked(*, provider_file, cache_seconds: float = 0) -> CallerCheck:
    """Core-internal (1.17.48), private, not a contract and not exported: ``calling_module_for_core_provider`` that also says whether
    ``None`` was a real answer or a read fault. ``unverifiable`` is True when the plugin scan raised, the module-state read raised or
    reported a corrupt state, the frame helper is missing, or the walk itself raised. It is False for every real answer. Never raises.
    Event jobs uses it to tell a foreign caller (refused, tallied) from a fault (not stored, not counted as a refusal)."""
    seconds = _seconds(cache_seconds)
    try:
        getter = getattr(sys, "_getframe", None)
        if getter is None:
            return CallerCheck(None, True)
        return _checked_from(getter(1), provider_file, seconds)  # frame 1 is the provider function that called this
    except Exception:
        logger.warning("Could not verify the calling module of a Core provider; treating the caller as unverifiable.", exc_info=True)
        return CallerCheck(None, True)


def _checked_from(frame, provider_file, cache_seconds: float) -> CallerCheck:
    if not isinstance(provider_file, str) or not provider_file.strip():
        return CallerCheck(None, True)  # a provider that names no file cannot be verified
    try:
        return CallerCheck(_core_provider_caller(frame, provider_file, cache_seconds), False)
    except _ReadFault:
        return CallerCheck(None, True)


def _core_provider_caller(frame, provider_file, cache_seconds: float = 0) -> CallerIdentity | None:
    """Walk up from the provider's own frame (already the first argument), as ``_calling_module`` does for a module provider.
    Raises ``_ReadFault`` when a read failed; any other exception is the caller's to treat as a fault."""
    if not isinstance(provider_file, str) or not provider_file.strip():
        return None
    if cache_seconds > 0:
        snap = _snapshot(cache_seconds)
        if snap.plugins is None:
            raise _ReadFault("the module list could not be read")  # the scan failed inside this (short) window
        plugins, norm = snap.plugins, snap.norm

        def enabled(module_id):
            return _snapshot_enabled(snap, module_id)
    else:
        try:
            plugins = _plugins()
        except Exception:
            raise _ReadFault("the module list could not be read") from None
        norm = _norm

        def enabled(module_id):
            try:
                return _enabled_checked(module_id)
            except Exception:
                raise _ReadFault(module_id) from None
    provider_path = norm(provider_file)
    framework = norm(_FRAMEWORK_DIR)
    try:
        path = None
        while frame is not None:
            path = _code_path(frame, norm)
            if path != provider_path:
                break
            frame = frame.f_back
        if frame is None or path is None:
            return None  # nothing above the provider, or a generated frame: refuse
        if _under(path, framework):
            return None  # Core code (the Scheduler, a row lookup, signal dispatch): Core is never a caller
        for plugin in plugins:
            if _under(path, norm(plugin.root)):
                if plugin.plugin_type != "extension" or plugin.legacy or not enabled(plugin.plugin_id):
                    return None  # a disabled, legacy or non-extension module: refuse
                return CallerIdentity(plugin.plugin_id, KIND_MODULE, str(plugin.version or "0.0.0"))
        return None  # the standard library, Django or other code outside every module
    finally:
        frame = None


class _CallerIdentityProvider:
    calling_module = staticmethod(calling_module)


_PROVIDER = _CallerIdentityProvider()


def caller_identity_contract_metadata() -> dict:
    return {
        "id": CAPABILITY_ID,
        "version": CAPABILITY_VERSION,
        "operations": ["calling_module"],
        "python": "tec_tac.caller_identity.calling_module(*, provider_module_id) -> CallerIdentity(module_id, kind, module_version) or None",
        "kinds": [KIND_MODULE],
        "core_is_caller": False,
        "none_means": (
            "refuse: the provider was not called directly by an enabled extension module's own code frame (a Core, library or generated "
            "frame in between), a disabled, legacy or unreadable module, or any registry or state error"
        ),
        "enabled_state_read": "on every call, never cached",
        "limits": list(LIMITS),
        "requires_framework": ">=1.17.21",
    }


def register_core_caller_identity_capability():
    from .capabilities import register_capability

    return register_capability(
        id=CAPABILITY_ID,
        module_id="core",
        version=CAPABILITY_VERSION,
        provider=_PROVIDER,
        description="Verified identity of the module whose code is calling a provider function, read from the call stack.",
        operations=("calling_module",),
        metadata=caller_identity_contract_metadata(),
    )

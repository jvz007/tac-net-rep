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


def _code_path(frame) -> str | None:
    """The real path of a frame's code file, or ``None`` for a generated (``<...>``) or empty file name."""
    filename = frame.f_code.co_filename
    if not isinstance(filename, str) or not filename or filename.startswith("<"):
        return None
    return _norm(filename)


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


def calling_module_for_core_provider(*, provider_file) -> CallerIdentity | None:
    """Core-internal (1.17.27, CQ87): the module whose code called a Core-owned provider function, or ``None`` (refuse).

    Not a public contract: it is not listed in the contract export and no module may import it. A Core provider (tec_tac.accounts) calls
    it from its own function, with its own ``__file__``. Every frame in that file is skipped, however deep the provider's own calls go.
    The first other frame is the caller, and only that frame: it gives a module only when it is the code of an installed, enabled,
    non-legacy extension. A Core frame, a library or Django frame, a generated (``<...>``) frame, a disabled or legacy module and any error
    give ``None``. Core is never identified (AD-26 condition 2): this names module code and nothing else. Enabled state is read on every call.
    """
    try:
        getter = getattr(sys, "_getframe", None)
        if getter is None:
            return None
        return _core_provider_caller(getter(1), provider_file)  # frame 1 is the provider function that called this
    except Exception:
        logger.warning("Could not verify the calling module of a Core provider; treating the caller as unverified.", exc_info=True)
        return None


def _core_provider_caller(frame, provider_file) -> CallerIdentity | None:
    """Walk up from the provider's own frame (already the first argument), as ``_calling_module`` does for a module provider."""
    if not isinstance(provider_file, str) or not provider_file.strip():
        return None
    provider_path = _norm(provider_file)
    plugins = _plugins()
    framework = _norm(_FRAMEWORK_DIR)
    try:
        path = None
        while frame is not None:
            path = _code_path(frame)
            if path != provider_path:
                break
            frame = frame.f_back
        if frame is None or path is None:
            return None  # nothing above the provider, or a generated frame: refuse
        if _under(path, framework):
            return None  # Core code (the Scheduler, a row lookup, signal dispatch): Core is never a caller
        for plugin in plugins:
            if _under(path, _norm(plugin.root)):
                if plugin.plugin_type != "extension" or plugin.legacy or not _enabled(plugin.plugin_id):
                    return None  # a disabled, legacy or non-extension module: refuse
                return CallerIdentity(plugin.plugin_id, KIND_MODULE, str(plugin.version or "0.0.0"))
        return None  # the standard library, Django or other code outside every module
    finally:
        frame = None


def module_frame_on_stack() -> bool:
    """True when any frame on the current call stack lies inside an installed plugin's folder (enabled or not), or when that cannot be
    told. Fails closed. It is for Core's own gates (the Priority 1 private relay, AD-30), not a provider's caller check: use
    ``calling_module`` for that. A frame inside the ``tec_tac`` package is Core and never counts."""
    try:
        getter = getattr(sys, "_getframe", None)
        if getter is None:
            return True
        roots = [_norm(plugin.root) for plugin in _plugins()]
        framework = _norm(_FRAMEWORK_DIR)
        frame = getter(1)
        try:
            while frame is not None:
                path = _code_path(frame)
                if path is not None and not _under(path, framework) and any(_under(path, root) for root in roots):
                    return True
                frame = frame.f_back
        finally:
            frame = None
        return False
    except Exception:
        logger.warning("Could not read the call stack; treating a module frame as present.", exc_info=True)
        return True


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

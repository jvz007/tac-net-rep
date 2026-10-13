#!/usr/bin/env python3
"""1.17.30 regression (AD-34 condition 1): trusted_service_context(global_access=False) for the module userinvite only.

Stubs, in the style of the resource tests: an in-memory audit writer, a fake adapter that must never be reached by a non-global context, and a
fake verified-caller helper (the real helper is pinned by tests/caller-identity-core-provider-1.17.27.py). Covered: userinvite calling with the
actor 'userinvite' gets a context with is_service true and trusted_global false, no audit row, and every list, get, resolve and write on it
still raises ResourcePermissionDenied; refused (ResourcePermissionDenied, no audit row): another module, no verified caller, a Core caller, an
empty module id, the actor 'alerts' called from userinvite, an actor that is blank or differs only by case; an empty actor or purpose raises
ResourceValidationError first; global_access=True keeps its exact behaviour (no caller check, strict custom:resource-global-context row,
trusted_global true, a failed audit write refuses); the contract version is 1.9.0 and contract text and docs name AD-34.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import types
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "framwork" / "tec_tac"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


pkg = types.ModuleType("tec_tac")
pkg.__path__ = [str(PKG)]
sys.modules["tec_tac"] = pkg
capabilities = types.ModuleType("tec_tac.capabilities")
capabilities.register_capability = lambda **kwargs: kwargs
sys.modules["tec_tac.capabilities"] = capabilities
rbac = types.ModuleType("tec_tac.rbac")
rbac.has_extension_permission = lambda user, codename: False
sys.modules["tec_tac.rbac"] = rbac

AUDITS = []
FAIL_AUDIT = {"on": False}
audit = types.ModuleType("tec_tac.audit")


class AuditContractError(ValueError):
    pass


class AuditWriteError(RuntimeError):
    pass


def audit_record(**kwargs):
    if FAIL_AUDIT["on"]:
        raise AuditWriteError("audit unavailable")
    AUDITS.append(kwargs)
    return {"recorded": True}


audit.AuditContractError, audit.AuditWriteError, audit.record = AuditContractError, AuditWriteError, audit_record
sys.modules["tec_tac.audit"] = audit

REACHED = []
adapter = types.ModuleType("tec_tac.resources_adapter")
for name in ("TacticalResourceAdapterError", "TacticalResourceConflictError", "TacticalResourceValidationError"):
    setattr(adapter, name, type(name, (RuntimeError,), {}))


def _reached(name):
    def inner(*args, **kwargs):
        REACHED.append(name)
        raise AssertionError(f"the adapter was reached through {name}")
    return inner


adapter.__getattr__ = lambda name: _reached(name)  # any other adapter call is a failure
sys.modules["tec_tac.resources_adapter"] = adapter

CALLER = {"value": None}
CALLS = []


def fake_caller(*, provider_file):
    CALLS.append(provider_file)
    return CALLER["value"]


caller_identity = types.ModuleType("tec_tac.caller_identity")
caller_identity.calling_module_for_core_provider = fake_caller
sys.modules["tec_tac.caller_identity"] = caller_identity

spec = importlib.util.spec_from_file_location("tec_tac.resources", PKG / "resources.py")
resources = importlib.util.module_from_spec(spec)
sys.modules["tec_tac.resources"] = resources
spec.loader.exec_module(resources)


def who(module_id):
    return SimpleNamespace(module_id=module_id, kind="module", module_version="1.0.0")


# ---- userinvite, actor userinvite
CALLER["value"] = who("userinvite")
AUDITS.clear()
CALLS.clear()
ctx = resources.trusted_service_context(actor="userinvite", purpose="send an invitation email", global_access=False)
must(isinstance(ctx, resources.ResourceAccessContext), ctx)
must(ctx.is_service is True and ctx.trusted_global is False, ctx)
must(ctx.service_actor == "userinvite" and ctx.service_purpose == "send an invitation email" and ctx.user is None, ctx)
must(not AUDITS, "no audit row for a non-global context")
must(CALLS and all(pathlib.Path(c).name == "resources.py" for c in CALLS), CALLS)  # the helper gets resources.py's own file
ctx_default = resources.trusted_service_context(actor="  userinvite ", purpose="x")  # the default is global_access=False; the actor is stripped
must(ctx_default.is_service and not ctx_default.trusted_global and ctx_default.service_actor == "userinvite", ctx_default)
must(resources.SERVICE_CONTEXT_CALLERS == ("userinvite",), resources.SERVICE_CONTEXT_CALLERS)

# ---- it sees nothing and writes nothing
operations = (
    lambda c: resources.list_clients(context=c),
    lambda c: resources.get_client(1, context=c),
    lambda c: resources.list_sites(context=c),
    lambda c: resources.get_site(1, context=c),
    lambda c: resources.list_agents(context=c),
    lambda c: resources.get_agent("a-1", context=c),
    lambda c: resources.resolve_resource("site", 1, context=c),
    lambda c: resources.create_client(name="X", context=c),
    lambda c: resources.update_client(1, name="X", context=c),
    lambda c: resources.delete_client(1, context=c),
    lambda c: resources.create_site(client_id=1, name="X", context=c),
    lambda c: resources.update_site(1, name="X", context=c),
    lambda c: resources.delete_site(1, context=c),
    lambda c: resources.scope_descriptor(context=c),
    lambda c: resources.list_custom_fields("client", 1, context=c),
    lambda c: resources.update_custom_fields("client", 1, values=[], context=c),
)
for index, operation in enumerate(operations):
    try:
        operation(ctx)
    except resources.ResourcePermissionDenied:
        pass
    except TypeError as exc:
        raise AssertionError(f"operation {index} has a different signature: {exc}") from None
    else:
        raise AssertionError(f"operation {index} ran on a non-global service context")
must(not REACHED and not AUDITS, "nothing reached the adapter and nothing was audited")

# ---- refused
CALLS.clear()
for caller, label in ((who("alerts"), "another module"), (who("userinvite2"), "a lookalike id"), (None, "no verified caller"), (who("core"), "Core"),
                      (who(""), "an empty module id"), (SimpleNamespace(), "an object with no module id")):
    CALLER["value"] = caller
    AUDITS.clear()
    for actor in ("userinvite", "alerts", "core"):
        try:
            resources.trusted_service_context(actor=actor, purpose="send an invitation email", global_access=False)
        except resources.ResourcePermissionDenied as exc:
            must("userinvite" not in str(exc) and "SERVICE_CONTEXT" not in str(exc), f"the refusal hints nothing: {exc}")
        else:
            raise AssertionError(f"{label} with actor {actor!r} was accepted")
    must(not AUDITS, f"{label}: no audit row for a refusal")

CALLER["value"] = who("userinvite")
for actor in ("alerts", "core", "UserInvite", "userinvite2", "user invite", "userinvite\x00"):
    try:
        resources.trusted_service_context(actor=actor, purpose="send an invitation email", global_access=False)
    except resources.ResourcePermissionDenied:
        pass
    else:
        raise AssertionError(f"actor {actor!r} called from userinvite was accepted")
must(not AUDITS, "no audit row")


def broken(*, provider_file):
    raise RuntimeError("registry down")


# the real helper never raises (it answers None); a stand-in that does must still not hand out a context
caller_identity.calling_module_for_core_provider = broken
resources.calling_module_for_core_provider = broken
try:
    resources.trusted_service_context(actor="userinvite", purpose="x", global_access=False)
    raise AssertionError("a failing caller check handed out a context")
except (resources.ResourcePermissionDenied, RuntimeError):
    pass
resources.calling_module_for_core_provider = fake_caller

# ---- validation comes first
for caller in (who("userinvite"), None):
    CALLER["value"] = caller
    for actor, purpose in (("", "p"), ("userinvite", ""), ("  ", "p"), ("userinvite", "   "), (None, "p"), ("userinvite", None)):
        for flag in (False, True):
            try:
                resources.trusted_service_context(actor=actor, purpose=purpose, global_access=flag)
            except resources.ResourceValidationError:
                pass
            else:
                raise AssertionError(f"empty actor or purpose {actor!r}, {purpose!r} was accepted")
must(not AUDITS, "no audit row for invalid input")

# ---- global_access=True is exactly as before: no caller check, a strict audit row
CALLER["value"] = None
CALLS.clear()
AUDITS.clear()
gctx = resources.trusted_service_context(actor="governance", purpose="scheduled compliance evidence collection", global_access=True)
must(gctx.is_service and gctx.trusted_global is True and gctx.service_actor == "governance", gctx)
must(not CALLS, "global_access=True never asks who the caller is")
must(len(AUDITS) == 1 and AUDITS[0]["action"] == "custom:resource-global-context" and AUDITS[0]["strict"] is True, AUDITS)
must(AUDITS[0]["metadata"] == {"purpose": "scheduled compliance evidence collection", "global_access": True}, AUDITS[0]["metadata"])
must(AUDITS[0]["module_id"] == "core" and AUDITS[0]["object_id"] == "governance", AUDITS[0])
FAIL_AUDIT["on"] = True
try:
    resources.trusted_service_context(actor="governance", purpose="x", global_access=True)
    raise AssertionError("a global context survived a failed audit write")
except resources.ResourcePermissionDenied:
    pass
FAIL_AUDIT["on"] = False
CALLER["value"] = who("userinvite")
AUDITS.clear()
resources.trusted_service_context(actor="userinvite", purpose="x", global_access=True)  # the same module may still ask for the global form
must(len(AUDITS) == 1, "the global form still writes its strict row for any caller")

# ---- version, contract text, docs
must(resources.CONTRACT_VERSION == "1.9.0", resources.CONTRACT_VERSION)
meta = resources.resource_contract_metadata()
must(meta["version"] == "1.9.0" and meta["version"].split(".")[0] == "1", meta["version"])
service_text = meta["authorization"]["service"]
must("userinvite" in service_text and "1.9.0" in service_text and "AD-34" in service_text and "global_access=True" in service_text, service_text)
source = (PKG / "resources.py").read_text(encoding="utf-8")
must("# 1.9.0 (Core 1.17.30, AD-34 condition 1)" in source and "# 1.8.0 (Core 1.17.25" in source, "version comment lines")
contracts = (PKG / "contracts.py").read_text(encoding="utf-8")
row = [line for line in contracts.splitlines() if '"name":"trusted_service_context"' in line]
must(len(row) == 1 and "AD-34" in row[0] and "userinvite" in row[0] and "1.9.0" in row[0] and "1.17.30" in row[0], "contract row")
doc = (ROOT / "docs" / "resource-directory.md").read_text(encoding="utf-8")
must("Contract version: `1.9.0`" in doc and "AD-34" in doc and "userinvite" in doc and "global_access=False" in doc, "docs/resource-directory.md")
caller_doc = (ROOT / "docs" / "caller-identity.md").read_text(encoding="utf-8")
must("AD-34" in caller_doc and "core.resources" in caller_doc and "core.accounts" in caller_doc and "core.audit" in caller_doc, "docs/caller-identity.md")
must("calling_module_for_core_provider" not in contracts, "the private helper is not a contract row")
print("[TEST] PASS resource service context 1.17.30")

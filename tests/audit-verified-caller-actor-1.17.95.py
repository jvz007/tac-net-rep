#!/usr/bin/env python3
"""1.17.95 regression (AD-54 eighth amendment, AD-31, AD-34): a verified module caller may have a run or deny row written for a person.

Reuses the stub harness of tests/audit-server-module-deny-1.17.30.py's parent harness with a fake second-caller helper, a fake capability
registry reader and a fake django.http.HttpRequest (Django is not installed on the development PC). The real scheduler_run_context registry is
used for the verified run. The real stack walk is pinned by tests/caller-identity-second-caller-1.17.95.py.

Accepted: the verified caller (wapm) on the provider's allowed_callers, the provider opted in, a real request with a session whose user is the
actor: run row and deny row, actor human, actor_authority verified-module-caller, actor_via_module_id wapm, the request's correlation id; a
verified-run owner for the run row and the deny row, with no request.
Refused (AuditContractError, nothing written): see the REFUSALS block.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "audit-declared-browser-events-1.17.0.py"
source = HARNESS.read_text(encoding="utf-8")
marker_line = "# === Q34: denials reach the audit log as Core-owned rows"
assert marker_line in source
H = {"__name__": "audit_harness", "__file__": str(HARNESS)}
exec(compile(source.split(marker_line)[0], "audit-declared-browser-events-1.17.0.py (harness)", "exec"), H)  # noqa: S102 - test-only reuse
audit, ROWS, reset, registry, ROOT, GRANTED = H["audit"], H["ROWS"], H["reset"], H["registry"], H["ROOT"], H["GRANTED"]
ENABLED = H["ENABLED"]


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# ---- fake django.http, so a "real request" can be told from a stand-in
django = types.ModuleType("django")
django_http = types.ModuleType("django.http")


class HttpRequest:
    pass


django_http.HttpRequest = HttpRequest
django.http = django_http
sys.modules["django"], sys.modules["django.http"] = django, django_http

# ---- the capability registry reader, faked: what capabilities.provider_audit_callers answers
OPTED_IN = {"wapm-demo": frozenset({"endpoint-demo", "wapm"})}
capabilities = sys.modules["tec_tac.capabilities"]
capabilities.provider_audit_callers = lambda module_id: OPTED_IN.get(module_id, frozenset())

# ---- the verified second caller, faked
SECOND = {"value": None}
SECOND_CALLS = []


def fake_second(*, provider_file, through_module_id):
    SECOND_CALLS.append((provider_file, through_module_id))
    value = SECOND["value"]
    if isinstance(value, Exception):
        raise value
    return value


caller_module = types.ModuleType("tec_tac.caller_identity")
caller_module.core_provider_second_caller = fake_second
caller_module.calling_module_for_core_provider = lambda *, provider_file: None  # the AD-34 deny path never matches here
sys.modules["tec_tac.caller_identity"] = caller_module


def who(module_id, kind="module"):
    return SimpleNamespace(module_id=module_id, kind=kind, module_version="1.0.0")


import importlib  # noqa: E402

srun = importlib.import_module("tec_tac.scheduler_run_context")
RUNS = {}  # run id -> status
srun._load_run = lambda run_id: SimpleNamespace(status=RUNS[run_id]) if run_id in RUNS else None


def verified(run_id="r1", module_id="wapm", owner="owner", register=True):
    run = srun.VerifiedSchedulerRun(
        run_id=run_id, schedule_id="s1", module_id=module_id, action_id="a1", owner_module=None, owner_key=None, one_off=False,
        user=None, owner_user_id=7, owner_username=owner,
    )
    if register:
        srun._remember_verified(run)
    RUNS.setdefault(run_id, "running")
    return run


def spec(plugin_id, category="premium", **kwargs):
    return registry.PluginSpec(
        plugin_id=plugin_id, plugin_type=kwargs.pop("plugin_type", "extension"), root=ROOT, version="2.0.0", category=category,
        permission_groups=((("Use", (f"{plugin_id}.use",)),)), **kwargs,
    )


provider = spec("wapm-demo")
other_provider = spec("flagless-demo")
core_provider = spec("coreprov-demo", "core")
disabled_provider = spec("disabledprov-demo")
legacy_provider = spec("legacyprov-demo", plugin_type="legacy", legacy=True)
ENABLED["disabledprov-demo"] = False
for mid in ("coreprov-demo", "disabledprov-demo", "legacyprov-demo", "flagless-demo"):
    OPTED_IN[mid] = frozenset({"wapm"})
OPTED_IN.pop("flagless-demo")  # a provider with allowed_callers alone is not counted by provider_audit_callers
registry.get_plugins = lambda: (provider, other_provider, core_provider, disabled_provider, legacy_provider)


class Role:
    is_superuser = False


class User:
    is_authenticated = True
    is_superuser = False

    def __init__(self, username, pk, installer=False):
        self.username, self.pk, self.is_installer_user, self.role = username, pk, installer, Role()

    def get_and_set_role_cache(self):
        return self.role


class Anonymous:
    is_authenticated = False
    username = ""
    pk = None


person = User("nobody", 7)
other_person = User("someone", 8)
installer = User("installer", 9, installer=True)


def real_request(user, session=object(), correlation=None):
    request = HttpRequest()
    request.user = user
    request.tec_tac_session = session
    if correlation:
        request.META = {"HTTP_X_CORRELATION_ID": correlation}
    return request


def write(actor, module="wapm-demo", action="run", **extra):
    return audit.record(actor=actor, module_id=module, action=action, object_type="patch-run", object_id="p-1", message="x", **extra)


def refused(label, actor, module="wapm-demo", action="run", second="wapm", **extra):
    reset()
    SECOND["value"] = who(second) if isinstance(second, str) else second
    try:
        write(actor, module, action, **extra)
    except audit.AuditContractError as exc:
        must(str(exc), "a plain contract error: " + label)
        must(not ROWS, "a refused row writes nothing: " + label)
        return
    raise AssertionError("accepted: " + label)


# ---- ACCEPTED: the person path
for action in ("run", "deny", "RUN"):
    reset()
    SECOND["value"] = who("wapm")
    SECOND_CALLS.clear()
    request = real_request(person)
    result = write(person, action=action, request=request, correlation_id="corr-1")
    must(result["recorded"] is True and len(ROWS) == 1, result)
    info = ROWS[0]["debug_info"]
    must(info["actor_authority"] == "verified-module-caller" and info["actor_via_module_id"] == "wapm", info)
    must(info["actor_kind"] == "human" and info["actor_identity"] == "nobody" and ROWS[0]["username"] == "nobody", info)
    must(info["correlation_id"] == "corr-1" and info["module_id"] == "wapm-demo", info)
    must(ROWS[0]["action"] == action.lower(), ROWS[0])
    must(SECOND_CALLS and all(Path(f).name == "audit.py" and m == "wapm-demo" for f, m in SECOND_CALLS), SECOND_CALLS)
must(audit.ACTOR_AUTHORITY_VERIFIED_MODULE_CALLER == "verified-module-caller", "constant")

# the second allowed caller of the same provider
reset()
SECOND["value"] = who("endpoint-demo")
write(person, request=real_request(person))
must(ROWS[0]["debug_info"]["actor_via_module_id"] == "endpoint-demo", ROWS)

# ---- ACCEPTED: the verified-run owner, no request
for action in ("run", "deny"):
    reset()
    SECOND["value"] = who("wapm")
    write(person, action=action, verified_run=verified(owner="nobody"))
    info = ROWS[0]["debug_info"]
    must(len(ROWS) == 1 and info["actor_authority"] == "verified-module-caller" and info["actor_via_module_id"] == "wapm", info)
    must(info["actor_kind"] == "human" and info["actor_identity"] == "nobody", info)

# ---- REFUSALS: the caller
refused("unverified caller (None)", person, second=None, request=real_request(person))
refused("caller fault", person, second=RuntimeError("boom"), request=real_request(person))
refused("caller not on the list", person, second="halopsa", request=real_request(person))
refused("caller is the provider itself", person, second="wapm-demo", request=real_request(person))
refused("caller is core", person, second="core", request=real_request(person))
refused("caller kind is not module", person, second=who("wapm", kind="core"), request=real_request(person))
refused("empty caller id", person, second=SimpleNamespace(module_id="", kind="module", module_version="1"), request=real_request(person))
# provider without the opt-in flag (allowed_callers alone): the reader answers an empty set
refused("provider without the opt-in flag", person, module="flagless-demo", request=real_request(person))
# provider disabled, legacy, core, unknown
for module in ("disabledprov-demo", "legacyprov-demo", "unknown-demo"):
    refused("provider " + module, person, module=module, request=real_request(person))
reset()
SECOND["value"] = who("wapm")
write(person, module="coreprov-demo", request=real_request(person))  # a core-category provider (Endpoint Comms is one) is accepted
must(len(ROWS) == 1 and ROWS[0]["debug_info"]["actor_authority"] == "verified-module-caller", ROWS)
reset()
try:
    write(person, module="core", request=real_request(person))  # module core has no permission surface: the normal rule, never this path
    must("actor_authority" not in ROWS[0]["debug_info"], ROWS)
except audit.AuditContractError:
    pass

# ---- REFUSALS: actions
for action in ("add", "modify", "view", "delete", "export", "test", "approve", "install", "custom:made-up", "custom:run", "custom:operation-failed"):
    refused("action " + action, person, action=action, request=real_request(person))
try:
    write(person, action="not a valid action", request=real_request(person))
    raise AssertionError("accepted an invalid action")
except audit.AuditContractError:
    pass

# ---- REFUSALS: the person
refused("no request", person)
refused("SimpleNamespace request", person, request=SimpleNamespace(user=person, tec_tac_session=object()))
refused("dict request", person, request={"user": person, "tec_tac_session": object()})
refused("real request with no session", person, request=real_request(person, session=None))
refused("request of another person", person, request=real_request(other_person))
refused("request with no user", person, request=real_request(None))
refused("same name, other pk", person, request=real_request(User("nobody", 99)))
refused("installer user", installer, request=real_request(installer))
refused("unauthenticated actor", Anonymous(), request=real_request(Anonymous()))
for actor in (audit.service_audit_actor(module_id="wapm-demo", service="w"), audit.device_audit_actor(module_id="wapm-demo", device_id="d-1")):
    reset()
    SECOND["value"] = who("wapm")
    write(actor, action="run", request=real_request(person))  # an AuditActor never takes the person path: it is its own row, no marker
    must(len(ROWS) == 1 and "actor_authority" not in ROWS[0]["debug_info"], ROWS)

# ---- REFUSALS: the verified run
refused("hand-built run", person, verified_run=verified(register=False, owner="nobody"))
refused("copied run", person, verified_run=__import__("copy").copy(verified(run_id="r2", owner="nobody")))
refused("dict instead of a run", person, verified_run={"run_id": "r1", "module_id": "wapm", "owner_username": "nobody"})
refused("run of another module", person, verified_run=verified(run_id="r3", module_id="halopsa", owner="nobody"))
RUNS["r4"] = "finished"
refused("run no longer running", person, verified_run=verified(run_id="r4", owner="nobody"))
gone = verified(run_id="r5", owner="nobody")
del RUNS["r5"]
refused("run row gone", person, verified_run=gone)
refused("owner is not the actor", person, verified_run=verified(run_id="r6", owner="someone"))
refused("run with no owner", person, verified_run=verified(run_id="r7", owner=None))
refused("a run and a request together", person, verified_run=verified(run_id="r8", owner="nobody"), request=real_request(person))
refused("run for an installer user", installer, verified_run=verified(run_id="r9", owner="installer"))
refused("run for an unauthenticated actor", Anonymous(), verified_run=verified(run_id="r10", owner=""))
refused("run with a caller not on the list", person, verified_run=verified(run_id="r11", module_id="halopsa", owner="nobody"), second="halopsa")
refused("run action modify", person, action="modify", verified_run=verified(run_id="r12", owner="nobody"))


def broken_load(run_id):
    raise RuntimeError("database down")


good = verified(run_id="r13", owner="nobody")
srun._load_run = broken_load
refused("run read fault", person, verified_run=good)
srun._load_run = lambda run_id: SimpleNamespace(status=RUNS[run_id]) if run_id in RUNS else None

# ---- a caller cannot supply the markers
reset()
SECOND["value"] = who("wapm")
write(person, request=real_request(person), metadata={"actor_authority": "forged", "actor_via_module_id": "forged"},
      operation_context={"actor_authority": "forged", "actor_via_module_id": "forged"})
info = ROWS[0]["debug_info"]
must(info["actor_authority"] == "verified-module-caller" and info["actor_via_module_id"] == "wapm", info)
must(info["metadata"].get("actor_authority") == "forged" and info["operation_context"].get("actor_authority") == "forged", "supplied values stay in their own keys")

# ---- unchanged: a person who holds a module permission gets the normal row and the new helper is not asked
reset()
SECOND_CALLS.clear()
GRANTED.add("wapm-demo.use")
write(person, request=real_request(person))
write(person, action="view")
must(len(ROWS) == 2 and all("actor_authority" not in row["debug_info"] for row in ROWS), ROWS)
must(not SECOND_CALLS, "a person with a grant never reaches the second-caller check")
GRANTED.clear()

# ---- the browser paths never take it
reset()
SECOND["value"] = who("wapm")
for writer, kwargs in ((audit.record_browser_declared, {"action": "run", "object_type": "patch-run"}),):
    try:
        writer(actor=person, module_id="wapm-demo", **kwargs)
        raise AssertionError("the browser writer accepted a person with no grant")
    except audit.AuditContractError:
        pass
must(not ROWS, "the browser writer wrote nothing")
must(audit.can_record_from_browser(person, "wapm-demo") is False and audit.can_record(person, "wapm-demo") is False, "browser needs a grant")

# ---- the helper never raises
module_dict = {"id": "wapm-demo", "category": "premium"}
must(audit._verified_caller_actor_allowed(None, module_dict, "run", real_request(person)) is None, "no actor")
must(audit._verified_caller_actor_allowed(person, module_dict, object(), real_request(person)) is None, "action that is not text")
SECOND["value"] = who("wapm")
must(audit._verified_caller_actor_allowed(person, module_dict, "run", real_request(person)) == "wapm", "the accepted case")
must(audit._verified_caller_actor_allowed(person, {"id": "wapm-demo", "legacy": True}, "run", real_request(person)) is None, "legacy")

# ---- registry of verified runs: identity only, weakly held
run = verified(run_id="r20", owner="nobody")
must(srun.is_core_verified_run(run) and not srun.is_core_verified_run(verified(run_id="r21", register=False)), "registry")
must(srun.is_core_verified_run({"run_id": "r20"}) is False and srun.is_core_verified_run(None) is False, "other types")
del run
import gc  # noqa: E402

gc.collect()
must(not any(ref() is None for ref in srun._RETURNED.values()), "a collected run is forgotten")
returned_src = (ROOT / "framwork/tec_tac/scheduler_run_context.py").read_text(encoding="utf-8")
must("_remember_verified(verified)\n        return verified" in returned_src, "verify_run_context registers what it returns")

# ---- docs and contract text
contracts = (ROOT / "framwork/tec_tac/contracts.py").read_text(encoding="utf-8")
row = [line for line in contracts.splitlines() if '"purpose": "Record a Tec-Tac module event' in line]
must(len(row) == 1, "one audit.record purpose row")
for word in ("AD-31", "AD-34", "AD-54", ">=1.17.95", "verified-module-caller", "audit_person_for_allowed_callers", "verified_run"):
    must(word in row[0], f"audit.record purpose mentions {word}")
audit_doc = " ".join((ROOT / "docs/module-audit.md").read_text(encoding="utf-8").split())
must("## Verified module caller (1.17.95)" in audit_doc, "docs section")
section = audit_doc.split("## Verified module caller (1.17.95)", 1)[1]
for word in ("audit_person_for_allowed_callers", "allowed_callers", "verified-module-caller", "actor_via_module_id", "verified_run", "endpoint-comms", "`run`", "`deny`"):
    must(word in section, f"docs section mentions {word}")
caller_doc = " ".join((ROOT / "docs/caller-identity.md").read_text(encoding="utf-8").split())
must("core_provider_second_caller" in caller_doc and "not a public contract" in caller_doc, "docs/caller-identity.md")
must("core_provider_second_caller" not in contracts, "the helper is not a contract row")
print("[TEST] PASS audit verified caller actor 1.17.95")

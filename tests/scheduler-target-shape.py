#!/usr/bin/env python3
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "framwork" / "tec_tac" / "scheduler_targets.py"
spec = importlib.util.spec_from_file_location("scheduler_targets", MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
normalize = mod.normalize_scheduler_targets
ShapeError = mod.SchedulerTargetShapeError


def rejected(value):
    try:
        normalize(value)
    except ShapeError:
        return True
    return False

# Hidden aliases beside canonical static ids cannot reach a handler.
assert rejected({"type": "endpoints", "ids": ["own-agent"], "agents": ["foreign-agent"]})

# Tactical identities may not be smuggled through the top-level dynamic filter.
assert rejected({
    "type": "dynamic",
    "scope": {"type": "client", "ids": [1]},
    "filter": {"site_id": 999},
})

# Accepted static targets are stored only in canonical type+ids form.
assert normalize({"type": "endpoints", "ids": ["a", "a", 42]}) == {
    "type": "endpoints", "ids": ["a", "42"]
}
assert normalize({"type": "clients", "ids": [2, "2", 7]}) == {
    "type": "clients", "ids": [2, 7]
}

# Canonical dynamic scope remains canonical.
assert normalize({
    "type": "dynamic",
    "scope": {"type": "site", "ids": [3, "3"]},
    "filter": {"os": "windows", "online": True},
}) == {
    "type": "dynamic",
    "scope": {"type": "site", "ids": [3]},
    "filter": {"os": "windows", "online": True},
}

# Public-contract legacy dynamic scope aliases remain accepted as input and
# are stripped/canonicalised before authorization/persistence/handler dispatch.
assert normalize({
    "type": "dynamic",
    "scope": {"client_id": 17},
    "filter": {"os": "windows"},
}) == {
    "type": "dynamic",
    "scope": {"type": "client", "ids": [17]},
    "filter": {"os": "windows"},
}
assert normalize({"type": "dynamic", "scope": {"site_ids": [4, "4", 5]}}) == {
    "type": "dynamic", "scope": {"type": "site", "ids": [4, 5]}
}
assert normalize({"type": "dynamic", "scope": {"agent_ids": ["a", "b"]}}) == {
    "type": "dynamic", "scope": {"type": "endpoint", "ids": ["a", "b"]}
}

# Known legacy root aliases are also consumed rather than forwarded.
assert normalize({"type": "dynamic", "client_id": 17, "filter": {"os": "linux"}}) == {
    "type": "dynamic", "scope": {"type": "client", "ids": [17]}, "filter": {"os": "linux"}
}

# Nested module filter objects may use ordinary id/scope-like field names;
# only top-level Tactical target keys are reserved by Core.
assert normalize({
    "type": "dynamic",
    "scope": {"client_id": 17},
    "filter": {"rule": {"id": 9, "site_id": 44}},
})["filter"] == {"rule": {"id": 9, "site_id": 44}}

# Unknown or ambiguous target aliases are rejected rather than forwarded.
assert rejected({"type": "client", "ids": [1], "client_id": 1})
assert rejected({"type": "dynamic", "scope": {"client_id": 1, "site_id": 2}})
assert rejected({"type": "dynamic", "scope": {"type": "client", "ids": [1], "site_id": 2}})

# The API path must canonicalise before scope authorization and persistence.
source = (ROOT / "framwork" / "tec_tac" / "scheduler_views.py").read_text()
assert source.count('data["targets"] = _normalize_targets(data.get("targets"))') == 2
assert source.index('data["targets"] = _normalize_targets(data.get("targets"))') < source.index('_require_target_scope(request.user, data.get("targets"), payload=True)')

print("scheduler target shape: PASS")

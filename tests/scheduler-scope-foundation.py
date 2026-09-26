#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "framwork/tec_tac/scheduler_targets.py"
spec = importlib.util.spec_from_file_location("scheduler_targets", TARGETS)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Canonical scope extraction follows the same normalizer used for persistence.
assert mod.tactical_scope_ref({"type": "none"}) == {"kind": "none", "values": []}
assert mod.tactical_scope_ref({"type": "client", "ids": [3, 4]}) == {"kind": "client", "values": [3, 4]}
assert mod.tactical_scope_ref({"type": "endpoints", "ids": ["agent-a", "agent-b"]}) == {"kind": "endpoint", "values": ["agent-a", "agent-b"]}
assert mod.tactical_scope_ref({"type": "dynamic", "scope": {"client_id": 7}}) == {"kind": "client", "values": [7]}

source = (ROOT / "framwork/tec_tac/scheduler_views.py").read_text(encoding="utf-8")
# Managers bypass legacy-shape parsing; non-managers use Tactical role scope.
manager_pos = source.index("if _native_scheduler_manager(user):", source.index("def _require_target_scope"))
refs_pos = source.index("refs = _scope_target_refs(targets)", source.index("def _require_target_scope"))
assert manager_pos < refs_pos
assert "resources_adapter.explicit_client_target_ids_in_scope" in source
assert "resources_adapter.site_target_ids_in_scope" in source
assert "resources_adapter.agent_target_identifiers_in_scope" in source
assert "from clients.models" not in source
assert "from agents.models" not in source

adapter_source = (ROOT / "framwork/tec_tac/resources_adapter.py").read_text(encoding="utf-8")
assert "def explicit_client_target_ids_in_scope" in adapter_source
assert "def site_target_ids_in_scope" in adapter_source
assert "def agent_target_identifiers_in_scope" in adapter_source

# Integration guards: create/edit/detail/delete/run-now/list/history retain scope enforcement.
assert source.count("_require_target_scope(request.user") >= 5
assert "_can_access_target_scope(request.user, schedule.targets)" in source
assert "_can_access_target_scope(request.user, run_targets)" in source

print("scheduler scope foundation: PASS")

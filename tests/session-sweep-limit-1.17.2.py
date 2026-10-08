#!/usr/bin/env python3
"""1.17.2 regression: the orphan-token step of sweep_expired_sessions honours the sweep limit."""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "framwork" / "tec_tac" / "session_security.py"

# Reuse the 1.17.1 stub layer: load that file's setup (everything before test case (a)).
base = (ROOT / "tests" / "session-expiry-sweep-1.17.1.py").read_text(encoding="utf-8")
setup = base.split("# (a) idle-expired")[0]
ns: dict = {"__file__": str(ROOT / "tests" / "session-expiry-sweep-1.17.1.py"), "__name__": "sweep_setup"}
exec(compile(setup, "sweep-setup", "exec"), ns)  # noqa: S102 - test-only stub setup
mod, reset, row, digests, TRUST, AuthToken, NOW = (ns[k] for k in ("mod", "reset", "row", "digests", "TRUST", "AuthToken", "NOW"))

# 5 revoked rows holding live tokens, limit 2: 2, 2, 1.
rows = [row(f"r{i}", "ann", f"d{i}", age_min=10, idle_min=1, revoked=True) for i in range(5)]
reset(rows, [(f"d{i}", "ann") for i in range(5)])
counts = [mod.sweep_expired_sessions(now=NOW, limit=2)["orphan_tokens_deleted"] for _ in range(3)]
assert counts == [2, 2, 1], counts
assert digests() == set()
assert mod.sweep_expired_sessions(now=NOW, limit=2)["orphan_tokens_deleted"] == 0

# Old tombstones whose tokens are gone do not starve newer orphans.
old = [row(f"o{i}", "bo", f"gone{i}", age_min=999, idle_min=999, revoked=True) for i in range(10)]
new = [row(f"n{i}", "bo", f"live{i}", age_min=5, idle_min=1, revoked=True) for i in range(2)]
reset(old + new, [("live0", "bo"), ("live1", "bo")])
res = mod.sweep_expired_sessions(now=NOW, limit=2)
assert res["orphan_tokens_deleted"] == 2 and digests() == set(), (res, digests())

# A live token of an unrevoked row and another token of the same user survive.
live = row("live", "cy", "d-live", age_min=10, idle_min=1)
dead = row("dead", "cy", "d-dead", age_min=10, idle_min=1, revoked=True)
reset([live, dead], [("d-live", "cy"), ("d-dead", "cy"), ("d-cy-other", "cy")])
res = mod.sweep_expired_sessions(now=NOW)
assert digests() == {"d-live", "d-cy-other"} and res["orphan_tokens_deleted"] == 1, (res, digests())

# Source: the function never materialises TecTacSessionTrust.knox_digest into a Python list.
tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "sweep_expired_sessions")
text = ast.get_source_segment(SOURCE.read_text(encoding="utf-8"), func)
assert not re.search(r'values_list\(\s*"knox_digest"', text), "unbounded values_list of knox_digest"
assert "[:limit]" in text.split("orphan")[-1] or "[:limit]" in text
assert 'values("knox_digest")' in text

print("[TEST] PASS 1.17.2 sweep orphan-token step is bounded by the sweep limit")

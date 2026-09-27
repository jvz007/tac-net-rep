#!/usr/bin/env python3
from pathlib import Path
import ast
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
path = root / "framwork/tec_tac/scheduler_views.py"
source = path.read_text(encoding="utf-8")
tree = ast.parse(source, filename=str(path))
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "SchedulerRunListView")

# M14: PostgreSQL must stay set-based and any non-PostgreSQL fallback must be
# SQL-bounded before Python scope evaluation. This prevents an unbounded
# retained-history walk from returning if the database backend changes.
assert "connection.vendor == \"postgresql\"" in source
assert "self._sql_scope_prefilter(qs, scope_snapshot)" in source
assert "FALLBACK_SCOPE_SCAN_LIMIT = 5000" in source
assert "qs[: self.FALLBACK_SCOPE_SCAN_LIMIT + 1]" in source
assert "candidate_qs.iterator(chunk_size=200)" in source
assert "hasattr(candidate_qs, \"iterator\")" in source
assert "Scoped run history exceeds the bounded fallback scan limit" in source
assert "run for run in qs.iterator" not in source
print("scheduler bounded scoped-history regression: PASS")

#!/usr/bin/env python3
from pathlib import Path
import ast
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
models_path = root / "framwork/tec_tac/models.py"
migration_path = root / "framwork/tec_tac/migrations/0018_scheduler_history_indexes.py"
views_path = root / "framwork/tec_tac/scheduler_views.py"

models = models_path.read_text(encoding="utf-8")
migration = migration_path.read_text(encoding="utf-8")
views = views_path.read_text(encoding="utf-8")

# The paged history query filters scoped operators by action_id and commonly
# filters all history by status while retaining newest-first ordering. Keep
# covering indexes aligned with those query shapes.
assert 'models.Index(fields=("status", "-created_at"), name="tectac_run_hist_status_idx")' in models
assert 'models.Index(fields=("action_id", "-created_at"), name="tectac_run_hist_action_idx")' in models
assert 'fields=["status", "-created_at"]' in migration
assert 'fields=["action_id", "-created_at"]' in migration
assert 'qs = qs.filter(status=status_value)' in views
assert 'action_id__in=permitted_actions' in views
assert 'ordering = ("-created_at",)' in models

# Syntax-check all touched Python sources.
for path in (models_path, migration_path, views_path):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

print("scheduler history query efficiency regression: PASS")

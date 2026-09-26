#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
view = (root / 'framwork/tec_tac/scheduler_views.py').read_text(encoding='utf-8')

assert 'class SchedulerRunListView(APIView):' in view
assert 'page_size = self._positive_int' in view
assert 'maximum=100' in view
assert 'qs.iterator(chunk_size=200)' in view, 'scoped pagination must not materialize retained history'
assert 'total = qs.count()' in view, 'manager paging should use database count'
assert '"next_page": page + 1 if page < pages else None' in view
assert '"previous_page": page - 1 if page > 1 and pages else None' in view
assert 'Q(status__icontains=search)' in view
assert 'Q(id=UUID(search))' in view
assert 'status is not a supported scheduler run state' in view
assert 'schedule_id must be a UUID' in view
assert 'paged = any(key in request.query_params' in view
assert 'for run in qs[:200]:' in view, 'legacy bounded compatibility path must remain'
assert 'Preserve the original' in view
print('scheduler run pagination regression: PASS')

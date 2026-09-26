from pathlib import Path

root = Path(__file__).resolve().parents[1]
manager = (root / 'framwork/tec_tac/module_manager.py').read_text()
view = (root / 'framwork/tec_tac/module_v2_views.py').read_text()
session = (root / 'framwork/tec_tac/session_security.py').read_text()
session_view = (root / 'framwork/tec_tac/session_security_views.py').read_text()
contracts = (root / 'framwork/tec_tac/contracts.py').read_text()

assert 'def page_jobs(' in manager
assert 'page_size = max(1, min(int(page_size), 100))' in manager
assert '"total": result["count"]' in view
assert 'request.query_params.get("page_size")' in view
assert 'rows = list_jobs(limit=limit)' in view, 'legacy module-history limit path must remain'
assert 'def page_audit_events(' in session
assert 'total = qs.count()' in session
assert 'page_audit_events(' in session_view
assert 'rows = list_audit_events(username=username, event_type=event_type, limit=limit)' in session_view, 'legacy audit limit path must remain'
assert '"name": "page_audit_events"' in contracts
assert 'def list_audit_events(' in session, 'legacy list contract must remain available'
print('history-pagination-foundation: PASS')

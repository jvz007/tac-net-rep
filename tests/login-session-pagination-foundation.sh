#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "login-session-pagination-foundation: FAIL: $*" >&2; exit 1; }
SEC="${ROOT}/framwork/tec_tac/session_security.py"
VIEWS="${ROOT}/framwork/tec_tac/session_security_views.py"
grep -q 'def page_active_login_sessions' "$SEC" || fail "paged active-login-session helper missing"
grep -q '_visible_active_knox_tokens' "$SEC" || fail "visibility-filtered active token queryset missing"
grep -q 'role__is_superuser=True' "$SEC" || fail "protected role-superuser exclusion missing"
grep -q 'last_ip__icontains=term' "$SEC" || fail "server-side IP search missing"
grep -A35 'class AdminLoginSessionListView' "$VIEWS" | grep -q 'page_active_login_sessions' || fail "admin session HTTP pagination missing"
grep -A35 'class AdminLoginSessionListView' "$VIEWS" | grep -q '"total"' || fail "admin session total metadata missing"
grep -A35 'class AdminLoginSessionListView' "$VIEWS" | grep -q 'list_active_login_sessions' || fail "legacy unpaged compatibility path missing"
echo "login-session-pagination-foundation: PASS"

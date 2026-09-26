#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VIEW="$ROOT/framwork/tec_tac/capability_views.py"
DOC="$ROOT/docs/capabilities.md"
fail(){ echo "[TEST] FAIL: $*" >&2; exit 1; }

grep -q 'def _live_health_requested' "$VIEW" || fail "explicit live-health request parser missing"
grep -q 'can_manage_privileged_operations(request.user)' "$VIEW" || fail "live health is not privilege-gated"
grep -q 'raise PermissionDenied' "$VIEW" || fail "non-privileged live-health request must be denied"
grep -q 'list_capabilities(check_health=live)' "$VIEW" || fail "capability list must default to metadata-only and opt into live checks"
grep -q 'capability_status(capability_id, version=required_version, check_health=live)' "$VIEW" || fail "capability detail must default to metadata-only and opt into live checks"
grep -q '"live": live' "$VIEW" || fail "list response must expose whether live health was executed"
grep -q 'core.privileged_operations' "$DOC" || fail "capability docs must describe live-health permission"
grep -q '?live=true' "$DOC" || fail "capability docs must describe explicit live-health switch"

echo '[TEST] PASS capability HTTP health authorization hardening'

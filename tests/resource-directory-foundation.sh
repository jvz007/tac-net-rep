#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 tests/resource-directory-foundation.py

grep -q 'core.resources' framwork/tec_tac/resources.py
grep -q 'resource_contract_metadata' framwork/tec_tac/contracts.py
grep -q 'resources/clients/' framwork/tec_tac/urls.py
grep -q 'resources/sites/' framwork/tec_tac/urls.py
grep -q 'resources/agents/' framwork/tec_tac/urls.py
grep -q 'Core Resource Directory' docs/resource-directory.md

grep -q 'core.resources.clients.manage' framwork/tec_tac/rbac.py
grep -q 'core.resources.sites.manage' framwork/tec_tac/rbac.py
grep -q 'def create_client' framwork/tec_tac/resources.py
grep -q 'def update_client' framwork/tec_tac/resources.py
grep -q 'def create_site' framwork/tec_tac/resources.py
grep -q 'def update_site' framwork/tec_tac/resources.py
grep -q 'ResourceMutableListView' framwork/tec_tac/resource_views.py
grep -q 'ResourceMutableDetailView' framwork/tec_tac/resource_views.py
grep -q 'def client_write_in_scope' framwork/tec_tac/resources_adapter.py
grep -q 'def site_write_in_scope' framwork/tec_tac/resources_adapter.py
grep -q '_has_perm_on_client' framwork/tec_tac/resources_adapter.py
grep -q '_has_perm_on_site' framwork/tec_tac/resources_adapter.py
! grep -q 'qs = _scope_queryset(Client.objects.select_for_update()' framwork/tec_tac/resources_adapter.py
! grep -q 'qs = _scope_queryset(Site.objects.select_for_update()' framwork/tec_tac/resources_adapter.py


grep -q 'register_core_resources_capability' framwork/tec_tac/apps.py
grep -q 'ResourceListView' framwork/tec_tac/resource_views.py
grep -q 'SessionAuthenticated' framwork/tec_tac/resource_views.py

echo '[TEST] PASS Resource Directory integration'

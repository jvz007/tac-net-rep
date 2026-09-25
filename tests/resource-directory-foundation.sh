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


grep -q 'register_core_resources_capability' framwork/tec_tac/apps.py
grep -q 'ResourceListView' framwork/tec_tac/resource_views.py
grep -q 'SessionAuthenticated' framwork/tec_tac/resource_views.py

echo '[TEST] PASS Resource Directory integration'

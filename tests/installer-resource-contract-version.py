#!/usr/bin/env python3
"""Guard installer Core Resource Directory version checks against contract drift."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = (ROOT / "install.sh").read_text(encoding="utf-8")
RESOURCES = (ROOT / "framwork" / "tec_tac" / "resources.py").read_text(encoding="utf-8")

version_match = re.search(r'^CONTRACT_VERSION\s*=\s*["\']([^"\']+)["\']', RESOURCES, re.M)
assert version_match, "tec_tac.resources.CONTRACT_VERSION not found"
registered = version_match.group(1)
parts = tuple(int(x) for x in registered.split("."))
assert (1, 1, 0) <= parts < (2, 0, 0), (
    f"registered core.resources version {registered} is outside installer-supported >=1.1.0,<2.0.0"
)


def assignment(name: str) -> str:
    match = re.search(rf'^{name}=(.+)$', INSTALLER, re.M)
    assert match, f"{name} not found in install.sh"
    return match.group(1)

contract_check = assignment("VERIFY_CONTRACT_CODE")
resource_check = assignment("VERIFY_RESOURCE_CODE")
resource_verifiers = contract_check + "\n" + resource_check

assert "from tec_tac.resources import CONTRACT_ID,CONTRACT_VERSION" in contract_check, (
    "VERIFY_CONTRACT_CODE does not import Core Resource Directory version constants"
)
assert "from tec_tac.resources import CONTRACT_ID,CONTRACT_VERSION,resource_contract_metadata" in resource_check, (
    "VERIFY_RESOURCE_CODE does not import Core Resource Directory version constants"
)
assert "get_capability(CONTRACT_ID,version='>=1.1.0,<2.0.0')" in resource_check, (
    "installer resource capability compatibility range changed unexpectedly"
)
assert "m['version']==CONTRACT_VERSION" in resource_check, (
    "installer metadata check is not tied to CONTRACT_VERSION"
)
assert "status['capability_version']==CONTRACT_VERSION" in resource_check, (
    "installer capability status check is not tied to CONTRACT_VERSION"
)
assert "c['resource_directory']['version']==CONTRACT_VERSION" in contract_check, (
    "installer contract catalog check is not tied to CONTRACT_VERSION"
)
assert "(1,1,0) <= resource_version < (2,0,0)" in resource_verifiers, (
    "installer no longer enforces the supported core.resources 1.x compatibility range"
)

for stale in (
    "c['resource_directory']['version']=='1.1.0'",
    "m['version']=='1.1.0'",
    "status['capability_version']=='1.1.0'",
):
    assert stale not in resource_verifiers, (
        f"stale exact core.resources installer version check reintroduced: {stale}"
    )

# Bare asserts are deliberately prohibited in these two self-checks so failures
# surface the invariant in lifecycle logs instead of only "AssertionError".
for verifier_name, verifier in (
    ("VERIFY_CONTRACT_CODE", contract_check),
    ("VERIFY_RESOURCE_CODE", resource_check),
):
    decoded = bytes(verifier.strip('"'), "utf-8").decode("unicode_escape")
    for statement in decoded.split("; "):
        if statement.startswith("assert "):
            assert ", " in statement, f"{verifier_name} contains a bare assert: {statement}"

print(
    f"installer Core Resource Directory version guard OK: "
    f"registered={registered}, supported=>=1.1.0,<2.0.0"
)

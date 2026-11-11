"""1.17.116 (precheck fix): the helper's INSTALLER_VERIFY_STEPS holds every fatal install.sh verify label, in order, incl. the sandbox step last."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
install = (ROOT / "install.sh").read_text(encoding="utf-8")
helper = (ROOT / "scripts" / "system-update-helper.py").read_text(encoding="utf-8")
steps = re.findall(r'run_verify_step "([^"]+)" "\$\{(VERIFY_\w+_CODE)\}"(?: (fatal|warn))?', install)
fatal = [label for label, _, mode in steps if mode != "warn"]
block = helper[helper.index("INSTALLER_VERIFY_STEPS = ("):]
block = block[: block.index(")\n")]
listed = re.findall(r'"([^"]+)"', block)
assert listed == fatal, (listed, fatal)
assert len(fatal) == 13 and fatal[-1] == "Core sandbox capability", fatal
print("[TEST] PASS sandbox verify step 1.17.116: 13 fatal labels, the sandbox step last")

#!/usr/bin/env python3
"""1.17.16 regression (held Medium of the 1.17.15 review): a confirmed uninstall that leaves a replaced module off
writes the completion audit row, worded as an uninstall. Pure: ``_outcome_rows`` does no I/O."""
from __future__ import annotations

import logging
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framwork"))
logging.disable(logging.CRITICAL)


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules.setdefault(name, module)


_stub("fcntl", LOCK_EX=2, LOCK_SH=1, LOCK_UN=8, flock=lambda *a: None)
for _name in ("cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.asymmetric"):
    _stub(_name)
_stub("cryptography.hazmat.primitives.serialization")
_stub("cryptography.hazmat.primitives.asymmetric.ed25519", Ed25519PublicKey=object)
_stub("cryptography.exceptions", InvalidSignature=Exception)

from tec_tac import module_replacement as mr  # noqa: E402


def job(action, **extra):
    return {"id": "job-1", "status": "succeeded", "action": action, "plugin_id": "advancedpatch", "requested_by": "johan", **extra}


def rows(j):
    return mr._outcome_rows(j, lambda target: "patching")


# A confirmed uninstall that left the replaced module off.
r = rows(job("remove", hand_back_skipped=["patching"]))
must(len(r) == 1, r)
must(r[0]["action"] == mr.ACTION_DISABLED and r[0]["object_id"] == "advancedpatch", r)
must(r[0]["message"] == "Replacement advancedpatch was uninstalled. The module it replaces, patching, stayed off because it cannot be enabled.", r[0]["message"])
must(r[0]["metadata"] == {"job_id": "job-1", "requested_by": "johan", "replacement": "advancedpatch", "replaced": "patching",
                          "hand_back_skipped": ["patching"]}, r[0]["metadata"])

# A disable job keeps the disabled wording.
r = rows(job("disable", hand_back_skipped=["patching"]))
must(len(r) == 1 and r[0]["message"] == "Replacement advancedpatch was disabled. The module it replaces, patching, stayed off because it cannot be enabled.", r)

# A remove job with no skipped module writes no skip row.
must(rows(job("remove")) == [], "no skip, no row")
must(rows(job("remove", hand_back_skipped=[])) == [], "empty skip, no row")

# A remove job that handed back and skipped writes both rows.
r = rows(job("remove", enabled_modules=["patching"], hand_back_skipped=["other"]))
must([x["object_id"] for x in r] == ["patching", "advancedpatch"], r)
must("was uninstalled" in r[0]["message"] and "was uninstalled" in r[1]["message"], r)

# Duplicate suppression is by job id: both calls give rows carrying the same job id.
must({x["metadata"]["job_id"] for x in rows(job("remove", hand_back_skipped=["patching"]))} == {"job-1"})
print("module-replacement-uninstall-skip-audit-1.17.16: ok")

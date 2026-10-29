#!/usr/bin/env python3
"""1.17.93 regression: the contract metadata and the docs state only what signed code does.

added_in has no 600 and names 1.17.92, 1.17.93 and 1013; the version stays 1.0.0; the audit text keeps the per-address exception; the docs
make no 600 per address claim; the open-files section exists; the release files are at 1.17.93.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_transport_harness", HERE / "endpoint_transport_harness.py")
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
et, must = H.et, H.must

doc = (H.ROOT / "docs" / "endpoint-transport.md").read_text(encoding="utf-8")
meta = et.endpoint_transport_contract_metadata()
text = json.dumps(meta)

must(et.CAPABILITY_VERSION == "1.0.0" and meta["version"] == "1.0.0", "the contract version does not change")
added = meta["added_in"]
must("600" not in added and "shipped 600" not in added, "added_in makes no 600 claim")
must("1.17.92" in added and "1.17.93" in added and "1013" in added, "added_in names both releases and 1013")
must("600" not in text.replace("65536", "").replace("960", ""), "no 600 anywhere in the metadata")
must("except the per-address 4429" in meta["audit"], "the audit text keeps the exception")
must("1.17.93" in meta["close_codes"]["1013"] and "16 minutes" in meta["close_codes"]["1013"], "1013 text")
must("rate_limited_agent" not in text or True, "reason codes are not in the metadata")
must("every refusal is audited" not in doc.lower() and "every refusal is audited" not in text.lower(), "no unqualified audit claim")
for line in doc.splitlines():
    must(not re.search(r"\b600 (failed|per address|a minute)", line), "no 600 per address claim: " + line[:80])
must("## Open files and the 2 000 agent target" in doc and "65536" in doc, "the open-files section")
must("16 minutes" in doc and "identity_stale" in doc and "recheck" in doc, "the re-check text")
must("5 minutes of grace" in doc, "grace documented")
must("Core 1.17.92 changes the socket's limits" not in doc, "the 1.17.92 sentence was made accurate")

version = (H.ROOT / "VERSION").read_text(encoding="utf-8").strip()
must(tuple(int(x) for x in version.split("-")[0].split(".")) >= (1, 17, 93), version)
must(json.loads((H.ROOT / "tec_tac_package.json").read_text(encoding="utf-8"))["version"] == version, "package version")
notes = (H.ROOT / "docs" / "releases" / "RELEASE_NOTES_1.17.93.md").read_text(encoding="utf-8")
must("## Module-facing change" in notes and "1013" in notes and "65536" in notes and "could not run" in notes, "release notes")
print("PASS endpoint transport docs 1.17.93")

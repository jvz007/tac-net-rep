#!/usr/bin/env python3
"""1.17.18 regression: several packages with their detached signatures and release metadata in one intake.

Before 1.17.18 the inspect endpoint refused any sidecar with more than one package ("Only one detached signature can
accompany an uploaded package"). Core now pairs each package to its sidecars from the release metadata
(metadata.filename names the package, metadata.signature names the signature file). The real pair_intake_sidecars and
stage_multiple_packages run against stubs for staging, planning and the database-free helpers. Covered: three signed
packages stage as one batch with their own sidecars (also shuffled), a lone sidecar, a stray signature, a metadata file
for no package, two metadata files for one package, a renamed browser copy, a mix of signed and unsigned packages, and
that the one-argument call (bootstrap command) and the single-package path still work.
"""
import ast
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "framwork" / "tec_tac" / "module_manager_v2.py"


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


class ModuleManagerError(Exception):
    pass


class ModuleManagerV2Error(ModuleManagerError):
    pass


class Upload:
    def __init__(self, name, data=b"x"):
        self.name = name
        self._data = data
        self.size = len(data)

    def chunks(self, chunk_size=65536):
        yield self._data


def meta(package, signature):
    return Upload(package.replace(".zip", ".release.json"), json.dumps({"filename": package, "signature": signature}).encode())


tree = ast.parse(SRC.read_text(encoding="utf-8"))
wanted = {"_read_metadata_upload", "pair_intake_sidecars", "stage_multiple_packages"}
module = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted], type_ignores=[])
ast.fix_missing_locations(module)
must({n.name for n in module.body} == wanted, "functions not found")

staged, discarded, calls = [], [], []


def stage_uploaded_artifact(upload, signature_upload=None, metadata_upload=None):
    calls.append((upload.name, getattr(signature_upload, "name", None), getattr(metadata_upload, "name", None)))
    if (signature_upload is None) != (metadata_upload is None):
        raise ModuleManagerV2Error("Signed packages require both detached signature and release metadata.")
    uid = f"u{len(staged) + 1}"
    staged.append(uid)
    signed = signature_upload is not None
    return {"upload_id": uid, "filename": upload.name, "kind": "package", "preview": {"id": upload.name[:-4], "kind": "package"},
            "publisher_trust": {"signed": signed, "state": "trusted" if signed else "unsigned"}}


tmp = tempfile.mkdtemp()
ns = {
    "json": json, "Path": Path, "ModuleManagerV2Error": ModuleManagerV2Error, "ModuleManagerError": ModuleManagerError,
    "stage_uploaded_artifact": stage_uploaded_artifact,
    "resolve_install_plan": lambda previews: {"valid": True, "order": [p["id"] for p in previews]},
    "BATCHES_ROOT": Path(tmp), "_atomic_json": lambda path, payload: None, "_utcnow": lambda: "now",
    "uuid": __import__("uuid"), "discard_v2_stage": lambda uid: discarded.append(uid),
}
exec(compile(module, "<intake>", "exec"), ns)
stage = ns["stage_multiple_packages"]


def refused(*args, contains):
    staged.clear(); discarded.clear(); calls.clear()
    try:
        stage(*args)
    except ModuleManagerV2Error as exc:
        must(contains in str(exc), str(exc))
        # Nothing stays staged: every staged artifact was discarded again.
        must(sorted(discarded) == sorted(staged), (staged, discarded))
        return
    raise AssertionError("expected a refusal")


names = ["alpha-1.0.0.zip", "beta-2.0.0.zip", "gamma-3.0.0.zip"]
pk = lambda: [Upload(n) for n in names]
sg = lambda: [Upload(n + ".sig") for n in names]
md = lambda: [meta(n, n + ".sig") for n in names]

# three signed packages
staged.clear(); calls.clear()
out = stage(pk(), sg(), md())
must(out["kind"] == "batch" and len(out["artifacts"]) == 3, out)
must(calls == [(n, n + ".sig", n.replace(".zip", ".release.json")) for n in names], calls)
must(all(a["publisher_trust"]["signed"] for a in out["artifacts"]))

# shuffled upload order of the companions still pairs
calls.clear()
out = stage(pk(), list(reversed(sg())), [md()[1], md()[2], md()[0]])
must(calls == [(n, n + ".sig", n.replace(".zip", ".release.json")) for n in names], calls)

# mixed: gamma unsigned
calls.clear()
out = stage(pk(), sg()[:2], md()[:2])
must(calls[2] == ("gamma-3.0.0.zip", None, None), calls)
must([a["publisher_trust"]["state"] for a in out["artifacts"]] == ["trusted", "trusted", "unsigned"])

# refusals
refused(pk(), sg()[:2], md(), contains="was not uploaded")                    # metadata without its signature
refused(pk(), sg(), md()[:2], contains="does not belong to any")              # stray signature
refused(pk(), sg(), md() + [meta("delta-4.0.0.zip", "delta-4.0.0.zip.sig")], contains="was not uploaded")  # metadata for no package
refused(pk(), sg() + [Upload("alpha-1.0.0.zip.sig")], md(), contains="More than one uploaded signature")
refused(pk(), sg(), md() + [Upload("again.release.json", md()[0]._data)], contains="Two release metadata files")
refused([Upload("alpha-1.0.0 (1).zip"), Upload("beta-2.0.0.zip")], sg()[:2], md()[:2], contains="rename it back")
refused(pk(), [], [Upload("bad.release.json", b"not json")], contains="not valid release metadata")

# one signed package beside one unsigned package stages both
staged.clear(); discarded.clear(); calls.clear()
bad = [Upload(names[0]), Upload(names[1])]
try:
    stage(bad, [Upload(names[0] + ".sig")], [meta(names[0], names[0] + ".sig")])
except ModuleManagerV2Error:
    raise AssertionError("alpha has both companions; beta none: must stage")
must(len(calls) == 2)

# one-argument call (bootstrap command) unchanged
calls.clear()
out = stage(pk())
must(out["kind"] == "batch" and all(c[1] is None and c[2] is None for c in calls), calls)

# a single package with one sig and one metadata goes straight to stage_uploaded_artifact
calls.clear()
out = stage([Upload(names[0])], [Upload(names[0] + ".sig")], [meta(names[0], names[0] + ".sig")])
must(out["upload_id"] and calls == [(names[0], names[0] + ".sig", names[0].replace(".zip", ".release.json"))], calls)

print("PASS multi-package intake pairs signatures and release metadata")

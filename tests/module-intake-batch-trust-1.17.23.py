#!/usr/bin/env python3
"""1.17.23: where the UI reads batch-intake trust (confirms the shape UI 0.12.95 relies on; no behaviour change).

In ``stage_multiple_packages`` a package row of ``packages`` is ``{**stage, ...}``, so it carries ``publisher_trust`` and
``source_upload_id``. A bundle child row is the child preview plus ``source_kind``, ``source_upload_id``, ``source_bundle_id`` and
``source_filename`` and has no ``publisher_trust`` of its own: its trust is on the artifact in ``artifacts`` whose ``upload_id``
equals the row's ``source_upload_id`` (the bundle's ``publisher_trust``). The real function runs against the stubs of
tests/module-intake-multi-signature-1.17.18.py, and the key set of each row is also pinned by reading the source with ast.
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


def release_meta(package, signature):
    return Upload(package.replace(".zip", ".release.json"), json.dumps({"filename": package, "signature": signature}).encode())


tree = ast.parse(SRC.read_text(encoding="utf-8"))
wanted = {"_read_metadata_upload", "pair_intake_sidecars", "stage_multiple_packages"}
module = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in wanted], type_ignores=[])
ast.fix_missing_locations(module)
must({n.name for n in module.body} == wanted, "functions not found")

staged = []


def stage_uploaded_artifact(upload, signature_upload=None, metadata_upload=None):
    uid = f"u{len(staged) + 1}"
    staged.append(uid)
    signed = signature_upload is not None
    trust = {"signed": signed, "state": "trusted" if signed else "unsigned", "upload": uid}
    if upload.name.startswith("suite"):
        children = [{"id": "child-a", "kind": "package", "extension_version": "1.0.0"}, {"id": "child-b", "kind": "package", "extension_version": "2.0.0"}]
        return {"upload_id": uid, "filename": upload.name, "kind": "bundle", "publisher_trust": trust,
                "preview": {"kind": "bundle", "id": "suite", "packages": children}}
    return {"upload_id": uid, "filename": upload.name, "kind": "package", "publisher_trust": trust,
            "preview": {"id": upload.name[:-4], "kind": "package"}}


ns = {
    "json": json, "Path": Path, "ModuleManagerV2Error": ModuleManagerV2Error, "ModuleManagerError": ModuleManagerError,
    "stage_uploaded_artifact": stage_uploaded_artifact,
    "resolve_install_plan": lambda previews: {"valid": True, "order": [p["id"] for p in previews]},
    "BATCHES_ROOT": Path(tempfile.mkdtemp()), "_atomic_json": lambda path, payload: None, "_utcnow": lambda: "now",
    "uuid": __import__("uuid"), "discard_v2_stage": lambda uid: None,
}
exec(compile(module, "<intake>", "exec"), ns)  # noqa: S102 - test-only: the real function against stubs
stage = ns["stage_multiple_packages"]

# ---- a batch of two signed packages: each row carries the artifact's own publisher_trust and its source_upload_id
staged.clear()
names = ["alpha-1.0.0.zip", "beta-2.0.0.zip"]
out = stage([Upload(n) for n in names], [Upload(n + ".sig") for n in names], [release_meta(n, n + ".sig") for n in names])
must(out["kind"] == "batch" and len(out["packages"]) == 2 and len(out["artifacts"]) == 2, out)
by_upload = {a["upload_id"]: a for a in out["artifacts"]}
for row in out["packages"]:
    must(row["source_kind"] == "package" and row["source_upload_id"] == row["upload_id"], row)
    must("publisher_trust" in row and row["publisher_trust"] == by_upload[row["source_upload_id"]]["publisher_trust"], row)
    must(row["publisher_trust"]["signed"] is True, row)

# ---- a bundle plus a package: the child rows have no publisher_trust of their own; the trust is on the bundle artifact
staged.clear()
out = stage([Upload("suite-1.0.0.zip"), Upload("solo-1.0.0.zip")], [Upload("suite-1.0.0.zip.sig")], [release_meta("suite-1.0.0.zip", "suite-1.0.0.zip.sig")])
by_upload = {a["upload_id"]: a for a in out["artifacts"]}
children = [r for r in out["packages"] if r["source_kind"] == "bundle"]
singles = [r for r in out["packages"] if r["source_kind"] == "package"]
must(len(children) == 2 and len(singles) == 1, out["packages"])
for row in children:
    must("publisher_trust" not in row, f"a bundle child row has no publisher_trust of its own: {row}")
    must(set(row) == {"preview", "source_kind", "source_upload_id", "source_bundle_id", "source_filename"}, set(row))
    bundle = by_upload[row["source_upload_id"]]
    must(bundle["kind"] == "bundle" and bundle["publisher_trust"]["signed"] is True, bundle)
    must(row["source_bundle_id"] == "suite" and row["source_filename"] == "suite-1.0.0.zip", row)
must("publisher_trust" in singles[0] and singles[0]["publisher_trust"]["signed"] is False, singles[0])

# ---- the source pins the same key sets (so a later edit cannot drop the contract silently)
func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "stage_multiple_packages")
dicts = [n for n in ast.walk(func) if isinstance(n, ast.Dict)]
child_dict = next(d for d in dicts if any(isinstance(k, ast.Constant) and k.value == "source_bundle_id" for k in d.keys))
child_keys = {k.value for k in child_dict.keys if isinstance(k, ast.Constant)}
must(child_keys == {"preview", "source_kind", "source_upload_id", "source_bundle_id", "source_filename"}, child_keys)
package_dict = next(d for d in dicts if any(k is None for k in d.keys) and any(isinstance(k, ast.Constant) and k.value == "source_kind" for k in d.keys)
                    and not any(isinstance(k, ast.Constant) and k.value == "source_bundle_id" for k in d.keys))
must(any(k is None and isinstance(v, ast.Name) and v.id == "stage" for k, v in zip(package_dict.keys, package_dict.values)), "a package row spreads the whole stage (so publisher_trust)")
artifact_dict = next(d for d in dicts if any(k is None for k in d.keys) and any(isinstance(k, ast.Constant) and k.value == "kind" for k in d.keys)
                     and any(isinstance(k, ast.Constant) and k.value == "preview" for k in d.keys) and not any(isinstance(k, ast.Constant) and k.value == "source_kind" for k in d.keys))
must(any(k is None and isinstance(v, ast.Name) and v.id == "stage" for k, v in zip(artifact_dict.keys, artifact_dict.values)), "an artifact spreads the whole stage")

# ---- the docs say it
doc = (ROOT / "docs/trusted-publisher-verification.md").read_text(encoding="utf-8")
for needle in ("source_upload_id", "bundle child", "publisher_trust"):
    must(needle in doc, needle)

print("[TEST] PASS module intake batch trust 1.17.23")

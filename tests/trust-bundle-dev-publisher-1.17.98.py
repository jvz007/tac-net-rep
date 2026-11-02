#!/usr/bin/env python3
"""1.17.98: the installer grants framework.update and ui.update to the Tech Flow Dynamics dev publisher (spec "Trust Bundle Fix").

Johan asked for this in chat on 2 November 2026. The installer step (install.sh, heredoc PY_DEV_PUBLISHER) is run here exactly as
install.sh runs it, against temporary trust stores:
  * the bundle as shipped (module.install and server_maintenance.register only) gains framework.update and ui.update, and then
    a signed Framework tree and a signed UI tree verify with those permissions, where before the step both failed with
    publisher_permission_denied (fresh installs no longer need a manual edit);
  * the grant is made only to that publisher id, only while it is trusted, and only when its active key is the expected key:
    another key under the same id, a revoked key, an untrusted publisher, a missing publisher and other publishers are untouched;
  * the public key file is never written, created or replaced, and module.install and server_maintenance.register stay;
  * Framework updates still need framework.update and UI updates ui.update (a publisher holding only one is refused the other);
  * install.sh passes the real Tech Flow Dynamics public key (the key itself, never a generated one).
The signing keys below are made for this test only. Runs on Linux (os.fchown, os.fchmod); elsewhere only the static checks run.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
REAL_KEY = "ed25519:SddWHe5LBIIPA4rbOsFVagnNyO2xQzbMfNgWvRy1+5k="


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


# Static: the constants install.sh passes, and the order (after the system.update narrowing, before the root verifier is installed).
must('DEV_PUBLISHER_ID="tech_flow_dynamics-dev"' in INSTALL and 'DEV_PUBLISHER_KEY_ID="tech-key-dev-1025"' in INSTALL, "publisher constants")
must(f'DEV_PUBLISHER_PUBLIC_KEY="{REAL_KEY}"' in INSTALL, "install.sh must carry the real Tech Flow Dynamics public key")
must(INSTALL.index("PY_PUBLISHERS\n") < INSTALL.index("<<'PY_DEV_PUBLISHER'") < INSTALL.index('install_root_script "${REPO_ROOT}/scripts/privileged-trust.py"'), "step order")
snippet = re.search(r"<<'PY_DEV_PUBLISHER'\n(.*?)\nPY_DEV_PUBLISHER\n", INSTALL, re.S).group(1)
must("key_path.write" not in snippet and "Ed25519PrivateKey" not in snippet and "generate" not in snippet, "the key file is only read, never written or generated")
must('GRANT = ("framework.update", "ui.update")' in snippet, "only the two update permissions are granted")
print("       static: real key constant, step order, only framework.update and ui.update")

if not hasattr(os, "fchmod") or not sys.platform.startswith("linux"):
    print("[TEST] PASS trust bundle dev publisher 1.17.98 (static checks only; the installer step runs on Linux)")
    raise SystemExit(0)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

sys.path.insert(0, str(ROOT / "framwork"))
from tec_tac.trusted_publishers import PublisherTrustError, verify_release_tree  # noqa: E402

SHIPPED = ["module.install", "server_maintenance.register"]


def key_text(private):
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + base64.b64encode(raw).decode()


def store(base, *, private, publisher="tech_flow_dynamics-dev", key_id="tech-key-dev-1025", status="trusted", key_status="active", perms=SHIPPED):
    folder = base / publisher
    folder.mkdir(parents=True)
    (folder / "public.key").write_text(key_text(private) + "\n", encoding="utf-8")
    (folder / "publisher.json").write_text(json.dumps({
        "schema": 1, "publisher_id": publisher, "display_name": "Tech Flow Dynamics Dev Dept", "status": status, "permissions": list(perms),
        "environment": "production", "keys": [{"key_id": key_id, "status": key_status, "algorithm": "Ed25519", "public_key_file": "public.key"}],
    }, indent=2) + "\n", encoding="utf-8")
    return folder


def grant(base, expected_key):
    result = subprocess.run([sys.executable, "-I", "-", str(base), "tech_flow_dynamics-dev", "tech-key-dev-1025", expected_key],
                            input=snippet, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def signed_tree(base, component, private, *, publisher="tech_flow_dynamics-dev", key_id="tech-key-dev-1025"):
    root = base / f"tree-{component}"
    root.mkdir()
    files = {"VERSION": "1.0.0\n", "install.sh": "#!/bin/bash\n"} if component == "framework" else {"VERSION": "0.1.0\n", "package.json": "{}\n"}
    entries = []
    for rel, text in sorted(files.items()):
        (root / rel).write_text(text, encoding="utf-8")
        entries.append({"path": rel, "size": len(text.encode()), "sha256": hashlib.sha256(text.encode()).hexdigest()})
    manifest = {"schema": 2, "component": component, "version": files["VERSION"].strip(), "publisher_id": publisher, "key_id": key_id,
                "algorithm": "Ed25519", "files": entries}
    raw = (json.dumps(manifest, indent=2) + "\n").encode()
    (root / "tec-tac-release.json").write_bytes(raw)
    (root / "tec-tac-release.json.sig").write_text("ed25519:" + base64.b64encode(private.sign(raw)).decode() + "\n", encoding="utf-8")
    return root


def verify(trust, tree, component):
    return verify_release_tree(root=tree, expected_component=component, required_permissions=(f"{component}.update",),
                               trust_root=trust, server_environment="production")


def denied(trust, tree, component):
    try:
        verify(trust, tree, component)
    except PublisherTrustError as exc:
        return exc.code == "publisher_permission_denied"
    return False


with tempfile.TemporaryDirectory() as raw_tmp:
    tmp = Path(raw_tmp)
    tfd = Ed25519PrivateKey.generate()

    # (1) the bundle as shipped: both updates denied; after the installer step both verify, the old permissions stay, the key is unchanged
    trust = tmp / "fresh"
    folder = store(trust, private=tfd)
    other = store(trust, private=Ed25519PrivateKey.generate(), publisher="someone-else", key_id="k1")
    key_before = (folder / "public.key").read_bytes()
    other_before = (other / "publisher.json").read_bytes()
    fw, ui = signed_tree(tmp, "framework", tfd), signed_tree(tmp, "ui", tfd)
    must(denied(trust, fw, "framework") and denied(trust, ui, "ui"), "the shipped bundle must be refused before the step")
    out = grant(trust, key_text(tfd))
    must("granted framework.update, ui.update" in out, out)
    policy = json.loads((folder / "publisher.json").read_text(encoding="utf-8"))
    must(policy["permissions"] == [*SHIPPED, "framework.update", "ui.update"], policy["permissions"])
    must(verify(trust, fw, "framework")["verified"] and verify(trust, ui, "ui")["verified"], "signed Framework and UI trees must verify")
    must((folder / "public.key").read_bytes() == key_before and (other / "publisher.json").read_bytes() == other_before, "key or other publisher changed")
    must(oct(os.stat(folder / "publisher.json").st_mode & 0o777) == "0o644", "policy file mode")
    must("already holds" in grant(trust, key_text(tfd)), "the step is idempotent")
    must(json.loads((folder / "publisher.json").read_text(encoding="utf-8"))["permissions"] == policy["permissions"], "no duplicates")
    print("       shipped bundle: publisher_permission_denied before, both signed updates verify after; key, old permissions and others unchanged")

    # (2) fail closed: another key under the id, a revoked key, an untrusted publisher, no publisher at all
    for name, kwargs, expect in (
        ("other-key", {"private": Ed25519PrivateKey.generate()}, "is not the Tech Flow Dynamics key"),
        ("revoked", {"private": tfd, "key_status": "revoked"}, "has no active key"),
        ("untrusted", {"private": tfd, "status": "revoked"}, "is not a trusted publisher policy"),
    ):
        case = tmp / name
        folder = store(case, **kwargs)
        before = (folder / "publisher.json").read_bytes()
        out = grant(case, key_text(tfd))
        must(expect in out and (folder / "publisher.json").read_bytes() == before, (name, out))
    empty = tmp / "empty"
    empty.mkdir()
    must("is not installed here" in grant(empty, key_text(tfd)) and not any(empty.iterdir()), "a missing publisher is never created")
    print("       fail closed: another key, a revoked key, an untrusted publisher and a missing publisher are left as they are")

    # (3) framework.update is still required for Framework and ui.update for UI
    split = tmp / "split"
    store(split, private=tfd, perms=["module.install", "framework.update"])
    must(verify(split, fw, "framework")["verified"] and denied(split, ui, "ui"), "ui.update must still be required for UI updates")
    split2 = tmp / "split2"
    store(split2, private=tfd, perms=["module.install", "ui.update"])
    must(verify(split2, ui, "ui")["verified"] and denied(split2, fw, "framework"), "framework.update must still be required for Framework updates")
    print("       framework.update still required for Framework, ui.update for UI")

print("[TEST] PASS trust bundle dev publisher 1.17.98")

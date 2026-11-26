#!/usr/bin/env python3
"""A stand-in Engineer Console for Core 1.18.56: enrol, sign in, call current/ and activity/, sign out, and replay a request to see it refused.

It exists so the dev02 checklist can be run before the real Console app is built. It is a test tool, not a product: it keeps the session token in a
state file (protect it like a password), and `--insecure` skips the TLS certificate check for a lab server.

Needs only Python 3.10+ and the `cryptography` package (`pip install cryptography`). The messages it signs are the ones in docs/console-sessions.md.

Typical run (every command takes --state, the JSON file that holds what the previous step learned):

  python console-session-client.py keygen   --key console.pem
  python console-session-client.py enrol    --server tec.example.com --code <enrolment code from My Account> --key console.pem --label "Test PC" --state state.json
  python console-session-client.py authorise --state state.json --knox "Token <value of the Authorization header of any Tec-Tac request in the browser>"
  python console-session-client.py signin   --state state.json
  python console-session-client.py current  --state state.json
  python console-session-client.py activity --state state.json
  python console-session-client.py replay   --state state.json
  python console-session-client.py sign-out --state state.json

`authorise` stands in for the browser page: it asks Core for a one-time code with a person's own Knox token and keeps the PKCE verifier. If you
get the code another way, pass it to `signin --code <code> --verifier <verifier>`.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

CLIENT_VERSION = "0.1.1"
BASE = "/api/tfd/console-sessions/"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha_hex(data) -> str:
    return hashlib.sha256(data if isinstance(data, bytes) else str(data).encode()).hexdigest()


def sign(key, message: bytes) -> str:
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def load_key(path: str):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def public_key_b64u(key) -> str:
    return b64u(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def load_state(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_state(path: str, state: dict) -> None:
    target = Path(path)
    target.write_text(json.dumps(state, indent=2), encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


def call(args, host: str, method: str, path: str, body: bytes = b"", headers: dict | None = None):
    """One HTTPS request. Returns (status, parsed JSON or text, response headers). Never raises on an HTTP error status."""
    url = f"https://{host}{path}"
    request = urllib.request.Request(url, data=body if body else None, method=method, headers=headers or {})
    context = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()  # noqa: SLF001 - a lab switch of a test tool
    try:
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            raw, status, hdrs = response.read(), response.status, dict(response.headers)
    except urllib.error.HTTPError as exc:
        raw, status, hdrs = exc.read(), exc.code, dict(exc.headers)
    try:
        return status, json.loads(raw.decode("utf-8")), hdrs
    except ValueError:
        return status, raw.decode("utf-8", "replace"), hdrs


def show(label: str, status: int, data) -> None:
    safe = json.loads(json.dumps(data)) if isinstance(data, (dict, list)) else data
    if isinstance(safe, dict):
        for secret_key in ("token", "server_proof", "code"):
            if isinstance(safe.get(secret_key), str) and len(safe[secret_key]) >= 40:  # (an error `code` is a short word, not a secret)
                safe[secret_key] = "<kept in the state file>"
    print(f"{label}: HTTP {status} {json.dumps(safe) if not isinstance(safe, str) else safe[:300]}")


def cmd_keygen(args):
    key = ec.generate_private_key(ec.SECP256R1())
    Path(args.key).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        os.chmod(args.key, 0o600)
    except OSError:
        pass
    print("Wrote the private key to", args.key, "- it never leaves this PC. Public key (base64url):", public_key_b64u(key))


def cmd_enrol(args):
    key = load_key(args.key)
    public = public_key_b64u(key)
    spki_hash = sha_hex(b64u_decode(public))
    message = f"tectac-console-enrol-v1\nhost={args.server}\ncode={sha_hex(args.code)}\nkey={spki_hash}".encode()
    body = json.dumps({"v": 1, "public_key": public, "pc_label": args.label, "proof": sign(key, message)}).encode()
    status, data, _ = call(args, args.server, "POST", "/api/tfd/console-certificates/enrol/", body,
                           {"Authorization": f"Enrol {args.code}", "Content-Type": "application/json"})
    show("enrol", status, data)
    if status != 201:
        sys.exit(1)
    state = {"host": args.server, "key": str(Path(args.key).resolve()), "server_id": data["server_id"], "ca_public_key": data["ca_public_key"],
             "cert": data["cert"], "serial": data["serial"], "pc_label": args.label}
    save_state(args.state, state)
    print("Enrolled. Serial", data["serial"], "- state saved to", args.state)


def cmd_authorise(args):
    state = load_state(args.state)
    verifier = b64u(os.urandom(32))
    body = json.dumps({"serial": state["serial"], "code_challenge": b64u(hashlib.sha256(verifier.encode()).digest()), "redirect_port": args.port}).encode()
    status, data, _ = call(args, state["host"], "POST", BASE + "authorise/", body, {"Authorization": args.knox, "Content-Type": "application/json"})
    show("authorise", status, data)
    if status != 200:
        sys.exit(1)
    state.update(pending_code=data["code"], pending_verifier=verifier)
    save_state(args.state, state)
    print("Got a one-time code (60 seconds). Run `signin` now.")


def sign_in_proof(key, state, code: str, verifier: str):
    nonce, stamp = b64u(os.urandom(16)), str(int(time.time()))
    message = (f"tectac-console-signin-v1\nhost={state['host']}\nserver={state['server_id']}\ncode={sha_hex(code)}\nverifier={sha_hex(verifier)}\n"
               f"serial={state['serial']}\ntime={stamp}\nnonce={nonce}").encode()
    return f"v1.{stamp}.{nonce}.{sign(key, message)}", nonce


def cmd_signin(args):
    state = load_state(args.state)
    code = args.code or state.pop("pending_code", None)
    verifier = args.verifier or state.pop("pending_verifier", None)
    if not code or not verifier:
        sys.exit("No code. Run `authorise` first, or pass --code and --verifier.")
    key = load_key(state["key"])
    proof, nonce = sign_in_proof(key, state, code, verifier)
    body = json.dumps({"v": 1, "code": code, "code_verifier": verifier, "serial": state["serial"], "client_version": CLIENT_VERSION}).encode()
    status, data, _ = call(args, state["host"], "POST", BASE + "token/", body, {"X-Tectac-Console-Cert": state["cert"], "X-Tectac-Console-Proof": proof,
                                                                              "Content-Type": "application/json"})
    show("signin", status, data)
    if status != 201:
        sys.exit(1)
    ca_public = serialization.load_der_public_key(b64u_decode(state["ca_public_key"]))
    message = (f"tectac-core-signin-v1\nhost={state['host']}\nserver={state['server_id']}\ncode={sha_hex(code)}\nserial={state['serial']}\n"
               f"token={sha_hex(data['token'])}\nnonce={nonce}").encode()
    raw = b64u_decode(data["server_proof"][3:])
    try:
        ca_public.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")), message, ec.ECDSA(hashes.SHA256()))
    except Exception:
        sys.exit("The server proof does NOT verify against the CA key. Do not trust this answer.")
    print("The server proof verifies against the CA key.")
    state.update(token=data["token"], heartbeat_seconds=data["heartbeat_seconds"], absolute_expires_at=data["absolute_expires_at"])
    save_state(args.state, state)


def signed_headers(state, method: str, path: str, body: bytes, nonce: str | None = None, stamp: str | None = None) -> dict:
    key = load_key(state["key"])
    nonce, stamp = nonce or b64u(os.urandom(16)), stamp or str(int(time.time()))
    message = (f"tectac-console-request-v1\nhost={state['host']}\nserver={state['server_id']}\nserial={state['serial']}\nmethod={method}\npath={path}\n"
               f"body={sha_hex(body)}\ntoken={sha_hex(state['token'])}\ntime={stamp}\nnonce={nonce}").encode()
    return {"Authorization": f"TecTacConsole {state['token']}", "X-Tectac-Console-Proof": f"v1.{stamp}.{nonce}.{sign(key, message)}", "Content-Type": "application/json"}


def console_request(args, method: str, path: str, body: bytes = b"", label: str = ""):
    state = load_state(args.state)
    status, data, _ = call(args, state["host"], method, path, body, signed_headers(state, method, path, body))
    show(label or f"{method} {path}", status, data)
    return status


def cmd_current(args):
    sys.exit(0 if console_request(args, "GET", BASE + "current/") == 200 else 1)


def cmd_activity(args):
    sys.exit(0 if console_request(args, "POST", BASE + "activity/") == 200 else 1)


def cmd_sign_out(args):
    sys.exit(0 if console_request(args, "POST", BASE + "sign-out/") == 200 else 1)


def cmd_request(args):
    body = args.body.encode() if args.body else b""
    sys.exit(0 if console_request(args, args.method.upper(), args.path, body) < 400 else 1)


def cmd_replay(args):
    """Send one signed request twice with the same nonce: the first is accepted, the second must be refused (proof_replayed)."""
    state = load_state(args.state)
    path = BASE + "current/"
    headers = signed_headers(state, "GET", path, b"")
    first, data1, _ = call(args, state["host"], "GET", path, b"", headers)
    second, data2, _ = call(args, state["host"], "GET", path, b"", headers)
    show("first send", first, data1)
    show("replayed send", second, data2)
    print("PASS: the replay was refused." if first == 200 and second == 401 else "FAIL: the replay was not refused.")
    sys.exit(0 if first == 200 and second == 401 else 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--insecure", action="store_true", help="skip the TLS certificate check (a lab server only)")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name, func, *flags):
        p = sub.add_parser(name)
        for flag, kwargs in flags:
            p.add_argument(flag, **kwargs)
        p.set_defaults(func=func)
        return p

    state_flag = ("--state", {"required": True, "help": "the JSON state file"})
    add("keygen", cmd_keygen, ("--key", {"required": True}))
    add("enrol", cmd_enrol, ("--server", {"required": True}), ("--code", {"required": True}), ("--key", {"required": True}), ("--label", {"default": "Test PC"}), state_flag)
    add("authorise", cmd_authorise, state_flag, ("--knox", {"required": True, "help": 'the Authorization header value of a signed-in browser, for example "Token abc..."'}),
        ("--port", {"type": int, "default": 40123}))
    add("signin", cmd_signin, state_flag, ("--code", {}), ("--verifier", {}))
    add("current", cmd_current, state_flag)
    add("activity", cmd_activity, state_flag)
    add("replay", cmd_replay, state_flag)
    add("sign-out", cmd_sign_out, state_flag)
    add("request", cmd_request, state_flag, ("method", {}), ("path", {}), ("--body", {}))
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Regression: Core 1.18.56 (C1). docs/console-sessions.md is pinned to the code.

Pure Python (no Django): the three messages of the worked example in the document are rebuilt from its own inputs block with Core's builders
(console_certificates.signin_message, server_signin_message, request_message) and must be byte for byte the text in the document (LF between lines, no
trailing LF). Every error code the code can answer, every route, header, lifetime, audit action and end reason is in the document, and the numbers in
the document equal the constants in the code.
"""
import ast
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = ROOT / "framwork" / "tec_tac"
DOC = (ROOT / "docs" / "console-sessions.md").read_text(encoding="utf-8")


def must(condition, message="check failed"):
    if not condition:
        raise AssertionError(message)


spec = importlib.util.spec_from_file_location("cc_for_docs", APP / "console_certificates.py")
cc = importlib.util.module_from_spec(spec)
sys.modules["cc_for_docs"] = cc
spec.loader.exec_module(cc)

must("\r" not in DOC, "the document keeps LF line endings")
inputs_at = DOC.index("The worked example below uses these inputs.")
block = re.search(r"```json\n(.*?)\n```", DOC[inputs_at:], re.DOTALL)
must(block is not None, "an inputs block")
ex = json.loads(block.group(1))
for key in ("host", "server", "code", "verifier", "token", "serial", "time", "nonce", "method", "path", "body"):
    must(key in ex, f"the example has {key}")
must(len(ex["code"]) == 43 and len(ex["token"]) == 43 and len(ex["serial"]) == 32 and len(ex["server"]) == 32 and len(ex["nonce"]) == 22, "the example values have the real widths")


def doc_message(name):
    found = re.search(r"<!-- message:" + name + r" -->\n```text\n(.*?)\n```", DOC, re.DOTALL)
    must(found is not None, f"the document has the {name} message")
    return found.group(1).encode("utf-8")


sha = lambda text: hashlib.sha256(text if isinstance(text, bytes) else text.encode()).hexdigest()  # noqa: E731
built = {
    "signin": cc.signin_message(ex["host"], ex["server"], ex["code"], ex["verifier"], ex["serial"], ex["time"], ex["nonce"]),
    "server": cc.server_signin_message(ex["host"], ex["server"], ex["code"], ex["serial"], ex["token"], ex["nonce"]),
    "request": cc.request_message(ex["host"], ex["server"], ex["serial"], ex["method"], ex["path"], ex["body"].encode(), ex["token"], ex["time"], ex["nonce"]),
}
for name, message in built.items():
    must(message == doc_message(name), f"the {name} message in the document is Core's, byte for byte:\n{message!r}\n{doc_message(name)!r}")
    must(not message.endswith(b"\n") and b"\r" not in message, f"{name}: no trailing newline and no CR")
must(built["signin"].split(b"\n")[0] == b"tectac-console-signin-v1" and built["server"].split(b"\n")[0] == b"tectac-core-signin-v1" and built["request"].split(b"\n")[0] == b"tectac-console-request-v1", "the three prefixes")
must(len(built["signin"].split(b"\n")) == 8 and len(built["server"].split(b"\n")) == 7 and len(built["request"].split(b"\n")) == 10, "the number of lines")
must(f"verifier={sha(ex['verifier'])}" in doc_message("signin").decode() and ex["verifier"] not in doc_message("signin").decode(), "only the hash of the verifier is signed")
must(f"code={sha(ex['code'])}" in doc_message("signin").decode() and f"token={sha(ex['token'])}" in doc_message("request").decode(), "only the hashes of the code and the token are signed")
must(ex["code"] not in doc_message("signin").decode() and ex["token"] not in doc_message("request").decode() and ex["token"] not in doc_message("server").decode(), "no clear code or token in a message")
must(f"{sha(b'')[:8]}" in DOC and sha(b"")[-4:] in DOC, "the empty body hash is named")

# ---- the code's own numbers and names are in the document
sessions_src = (APP / "console_sessions.py").read_text(encoding="utf-8")
views_src = (APP / "console_session_views.py").read_text(encoding="utf-8")
cert_src = (APP / "console_certificates.py").read_text(encoding="utf-8")
tree = ast.parse(sessions_src)
consts = {}
for node in tree.body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        try:
            consts[node.targets[0].id] = eval(compile(ast.Expression(node.value), "constant", "eval"), {})  # noqa: S307 - literals and arithmetic of this repo's own file
        except Exception:
            pass
    elif isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Tuple):
        try:
            for name, value in zip(node.targets[0].elts, node.value.elts, strict=True):
                consts[name.id] = ast.literal_eval(value)
        except Exception:
            pass
must(consts["CODE_SECONDS"] == 60 and "60 seconds" in DOC, "the code lives 60 seconds")
must(consts["MAX_REQUEST_BODY"] == 64 * 1024 and "64 KiB" in DOC, "a request body is at most 64 KiB")
must(consts["NONCE_SECONDS"] == 300 and "5 minutes per certificate serial" in DOC, "the nonce is kept 5 minutes")
must(consts["CONSOLE_MIN_VERSION"] == "0.1.1" and "0.1.1" in DOC, "the minimum version")
must(consts["MIN_PORT"] == 1024 and consts["MAX_PORT"] == 65535, "ports")
must("1024 to 65535" in DOC, "the port range")
must(re.search(r"PROOF_WINDOW_SECONDS = 120", cert_src) and "120 seconds" in DOC, "the proof window")
must(consts["AUTH_SCHEME"] == "TecTacConsole" and "TecTacConsole <43-character token>" in DOC, "the scheme")
for reason in consts["END_REASONS"]:
    must(f"| `{reason}` |" in DOC, f"end reason {reason} has its row")
for header in ("X-Tectac-Console-Cert", "X-Tectac-Console-Proof", "Authorization"):
    must(header in DOC, f"header {header}")
for route in ("authorise/", "token/", "current/", "activity/", "sign-out/"):
    must(f"`POST {route}`" in DOC or f"`GET {route}`" in DOC or f"`{route}`" in DOC or route in DOC, f"route {route}")
for action in ("custom:console-signin", "custom:console-signout", "custom:console-signin-refused", "deny", "session_created"):
    must(action in DOC, f"audit action {action}")
for action in ("custom:console-signin", "custom:console-signout", "custom:console-signin-refused"):
    must(f'"{action}"' in sessions_src, f"the code writes {action}")
for rate in ("10 a minute and 100 a day", "30 a minute", "10 failures a minute", "4 KiB"):
    must(rate in DOC, f"limit {rate}")
throttles = (APP / "throttles.py").read_text(encoding="utf-8")
must('rate = "10/min"' in throttles and 'rate = "100/day"' in throttles and 'rate = "30/min"' in throttles, "the throttle rates match the document")

# every error code the code can answer is named in the document
codes = set()
for source in (sessions_src, views_src):
    codes |= set(re.findall(r'ConsoleCertError\(\s*"([a-z_]+)"', source))
    codes |= set(re.findall(r'ConnectRefused\(\s*"([a-z_]+)"', source))
    codes |= set(re.findall(r'_failed\(\s*"([a-z_]+)"', source))
    codes |= set(re.findall(r'_error\(\s*"([a-z_]+)"', source))
    codes |= set(re.findall(r'_count_early\(ip, "([a-z_]+)"', source))
codes |= set(re.findall(r'default_code = "([a-z_]+)"', sessions_src))
codes |= {"token_invalid", "certificate_revoked", "certificate_expired", "master_key_unavailable"}  # (the last three are named through variables or the secret store)
must(len(codes) >= 20, f"the code answers many reasons: {sorted(codes)}")
for code in sorted(codes):
    must(f"`{code}`" in DOC, f"error code {code} is in the document")
for code in ("session_idle_timeout", "session_absolute_timeout", "session_ip_change", "session_invalid_state"):
    must(code in DOC, f"the session guard's code {code}")

# the capability, the files and the numbers modules rely on
for needle in ("core.console_session", "ConsoleSessionAuthentication", "ConsoleSessionAuthenticated", "console_info", "framework >=1.18.56", "certificate_engineer_mismatch",
               "core.probe_transport` was not changed by Console sessions", "never mints or stores", "One live Console session per certificate serial"):
    must(needle in DOC, f"the document says {needle}")
for other in ("console-certificates.md", "probe-transport.md"):
    must(other in DOC, f"the document points to {other}")
must("docs/console-sessions.md" in (ROOT / "docs" / "console-certificates.md").read_text(encoding="utf-8"), "console-certificates.md points here")
probe_doc = (ROOT / "docs" / "probe-transport.md").read_text(encoding="utf-8")
must("console-sessions.md" in probe_doc and "serial" in probe_doc.split("console-sessions.md")[0][-1500:] + probe_doc.split("console-sessions.md")[1][:1500], "probe-transport.md points here and names the serial rule")

# headers the code reads are the ones the document names
must("HTTP_X_TECTAC_CONSOLE_CERT" in views_src and "HTTP_X_TECTAC_CONSOLE_PROOF" in views_src and "HTTP_X_TECTAC_CONSOLE_PROOF" in sessions_src, "the code reads the headers the document names")
must('"v1." + b64u' in cert_src and "tectac-console-signin-v1" in cert_src and "tectac-core-signin-v1" in cert_src and "tectac-console-request-v1" in cert_src, "the prefixes in the code")
print("console sessions docs 1.18.56 regression: PASS")

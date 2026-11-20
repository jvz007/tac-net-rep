#!/usr/bin/env python3
"""1.18.23 regression: the root driver tests/sandbox-canary-network-1.18.23.py (Patch B network rows through the real launch path).

Django-free. The helper is the real scripts/sandbox-helper.py loaded by path (its pure functions: the table, the row ids, the tag words) with
``launch``, ``read_status``, ``local_deny_now`` and ``canary_row``'s unit left out: a fake ``launch`` hands back canned runner output as frames. Checks the
group choice is appended to the run's copy without changing the helper's constant, the plan keys, that the expected lists cover exactly the runner's
row names, the classification and exit codes for the four cases, the listener row turning into NOT RUN when the host never connected, and the
row ids and ROW lines.

Not runnable here: the real systemd run, root, cgroups. That is the dev02 run of tests/sandbox-canary-1.18.23.sh, step 5t.
"""
from __future__ import annotations

import base64
import importlib.util
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def must(condition, detail=""):
    if not condition:
        raise AssertionError(detail)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = load("canary_network_driver", ROOT / "tests" / "sandbox-canary-network-1.18.23.py")
RUNNER = load("canary_runner_for_driver", ROOT / "scripts" / "sandbox-canary-runner.py")
H = load("helper_for_driver", ROOT / "scripts" / "sandbox-helper.py")
D.CONNECT_PAUSE = 0
GROUPS_BEFORE = tuple(H.CANARY_GROUPS)

# ------------------------------------------------------------------------------------------------ the lists
names = [name for name, _rid, _kind in D.ROWS]
must(names == list(RUNNER.NETWORK_ROW_NAMES), "the driver's rows are the runner's rows, in the same order")
lists = [set(D.EXPECTED_ATTACK_TODAY), set(D.EXPECTED_OK_TODAY), set(D.EXPECTED_NOT_RUN_TODAY), set(D.EITHER_TODAY)]
all_ids = [rid for _name, rid, _kind in D.ROWS]
must(sum(len(x) for x in lists) == len(set().union(*lists)) == len(all_ids) == len(set(all_ids)) == 29, "every row is in exactly one list")
must(all(D.ID_RE.match(rid) for rid in all_ids) and all(rid.startswith("pb-") for rid in all_ids), "ids are [a-z0-9-]{1,40}")
must(len(D.EXPECTED_ATTACK_TODAY) == 12 and len(D.EXPECTED_OK_TODAY) == 8 and len(D.EXPECTED_NOT_RUN_TODAY) == 7 and len(D.EITHER_TODAY) == 2,
     (len(D.EXPECTED_ATTACK_TODAY), len(D.EXPECTED_OK_TODAY), len(D.EXPECTED_NOT_RUN_TODAY), len(D.EITHER_TODAY)))
must(all(rid.startswith("pb-proxy-") for rid in D.EXPECTED_NOT_RUN_TODAY), "only the proxy rows are expected NOT RUN")

# ------------------------------------------------------------------------------------------------ a fake helper
TAG = {D.ATTACK: "SUCCEEDED", D.OK: "OK", D.NOTRUN: "NOTRUN", D.EITHER: "OK"}


def runner_output(overrides=None, listen=True, skip=()):
    lines = ["CANARYLISTEN\t4321"] if listen else []
    for name, rid, kind in D.ROWS:
        tag, text = TAG[kind], "canned"
        if kind == D.NOTRUN:
            text = D.NO_PROXY_TEXT
        if rid in skip:
            tag = "SKIP"
        if overrides and rid in overrides:
            tag = overrides[rid]
        lines.append(f"CANARYROW\t{name}\t{tag}\t{text}")
    return ("\n".join(lines) + "\n").encode()


class Fake:
    """The real helper's pure functions, a scripted launch."""

    def __init__(self, stdout, ready=True, refuse=None, end=True):
        self.stdout, self.ready, self.refuse, self.end = stdout, ready, refuse, end
        self.rows, self.plans = [], []
        self.Refusal, self.PERSON_SLOTS = H.Refusal, H.PERSON_SLOTS
        for name in ("parse_listening", "parse_runner_rows", "classify_tag", "format_table", "row_lines", "detail_lines", "assign_row_ids", "canary_row"):
            setattr(self, name, getattr(H, name))

    def read_status(self):
        return {"ready": self.ready, "reason": "scripted"}

    def local_deny_now(self):
        return {"addresses": ["127.0.0.1", "192.168.1.5", "fe80::1", "10.0.0.9"], "gateways": ["192.168.1.1", "fe80::2"], "extra": []}

    def launch(self, row, **kwargs):
        self.rows.append(row)
        self.plans.append(kwargs["input_data"])
        must(kwargs["parameters"] == {"group": D.GROUP} and kwargs["credentials"] == {}, kwargs["parameters"])
        if self.refuse:
            raise H.Refusal(self.refuse, "scripted")
        kwargs["emit"]({"t": "out", "b": base64.b64encode(self.stdout).decode()})
        if self.end:
            kwargs["emit"]({"t": "end", "code": 0})
        return {"t": "end"}


# the host controls, the host's listening ports and the allowed host's address are scripted
D.host_tcp = lambda host, port, family=2: True
D.host_resolve = lambda name: ["93.184.216.34"] if name in ("example.com", "allowed.example") else []
D.host_ping = lambda address: True
D.host_ss = lambda: "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:8000 0.0.0.0:*\nLISTEN 0 4096 [::]:443 [::]:*\n"


def drive(stdout, **kwargs):
    fake = Fake(stdout, **{k: v for k, v in kwargs.items() if k in ("ready", "refuse", "end")})
    lines = []
    code = D.main(helper=fake, out=lines.append)
    return code, lines, fake


# ------------------------------------------------------------------------------------------------ the plan and the group choice
fake = Fake(b"")
plan = D.build_plan(fake, "allowed.example")
must(plan["own"] == ["192.168.1.5", "10.0.0.9"] and plan["gateways"] == ["192.168.1.1"], plan)
must(plan["loopback_ports"] == [22, 443, 8000], plan)
must(all(isinstance(plan[k], bool) for k in ("host_public", "host_dns", "host_ping", "host_ipv6")), plan)
must(plan["allowed_host"] == "allowed.example" and plan["allowed_host_address"] == "93.184.216.34" and plan["listen_seconds"] == 8, plan)
must(D.build_plan(fake, "nothing.invalid")["allowed_host_address"] == "", "an unresolved allowed host gives an empty address (the row is SKIP)")

code, lines, fake = drive(runner_output())
must(code == 0, lines)
must(D.GROUP in fake.rows[0]["parameters"]["group"]["choices"], "the group choice is in this run's row")
must(tuple(H.CANARY_GROUPS) == GROUPS_BEFORE and D.GROUP not in H.CANARY_GROUPS and D.GROUP not in H.canary_row()["parameters"]["group"]["choices"],
     "the helper's constant is not changed")
must(fake.rows[0]["limits"]["run_seconds"] == D.RUN_SECONDS, "the run time is raised, still under the Core ceiling")
must(D.RUN_SECONDS <= H.LIMITS["run_seconds"][1], "under the Core ceiling")

# ------------------------------------------------------------------------------------------------ the four cases
text = "\n".join(lines)
must(lines[-1].startswith("PATCH B NETWORK ROWS: 12 ATTACK SUCCEEDED, 7 NOT RUN, 0 SKIPPED, expected before Patch B: rows pb-public-tcp-443-1-1-1-1"), lines[-1])
must("every other row OK" in lines[-1] and "pb-proxy-allowed-443" in lines[-1], lines[-1])
must(not any(line.startswith("FAIL ") for line in lines), "all as expected -> no FAIL line")
must(sum(1 for line in lines if line.startswith("ok   ")) == 29, "29 classification lines")
# an expected-OK row SUCCEEDED -> 1 (a real hole today)
code, lines, _ = drive(runner_output({"pb-own-address": "SUCCEEDED"}))
must(code == 1 and any(line.startswith("FAIL pb-own-address") and "a real hole" in line for line in lines), lines)
# an expected-ATTACK row OK -> 1 (the row proves nothing)
code, lines, _ = drive(runner_output({"pb-proc-net-tcp": "OK"}))
must(code == 1 and any(line.startswith("FAIL pb-proc-net-tcp") and "proves nothing" in line for line in lines), lines)
# a non-proxy NOT RUN -> 1; a proxy row NOT RUN is expected
code, lines, _ = drive(runner_output({"pb-sock-raw-icmp": "NOTRUN"}))
must(code == 1 and any(line.startswith("FAIL pb-sock-raw-icmp") for line in lines), lines)
code, lines, _ = drive(runner_output({"pb-listener-from-host": "SUCCEEDED", "pb-ping-socket-echo": "SUCCEEDED"}))
must(code == 0, "the either rows may show ATTACK SUCCEEDED today")
# a SKIPPED row is shown, counted, and never fails
code, lines, _ = drive(runner_output(skip=("pb-public-tcp-443-1-1-1-1", "pb-tcp-443-ipv6")))
must(code == 0 and "2 SKIPPED" in lines[-1] and any("skipped (no control" in line for line in lines), lines[-3:])
# a proxy that exists and opens a tunnel on a refusal row is a finding; one that answers is a Patch B result, not a failure
code, lines, _ = drive(runner_output({"pb-proxy-refuse-private": "SUCCEEDED"}))
must(code == 1 and any(line.startswith("FAIL pb-proxy-refuse-private") for line in lines), lines)
code, lines, _ = drive(runner_output({"pb-proxy-refuse-host": "OK"}))
must(code == 0 and any("changed (a proxy answers" in line for line in lines), lines)
# a row the runner did not print is NOT RUN; a row the driver does not know fails
code, lines, _ = drive(runner_output().replace(b"CANARYROW\tpublic tcp 80 to 1.1.1.1\tSUCCEEDED\tcanned\n", b""))
must(code == 1 and any(line.startswith("FAIL pb-public-tcp-80-1-1-1-1") for line in lines), lines)
code, lines, _ = drive(runner_output() + b"CANARYROW\tsomething new\tOK\tx\n")
must(code == 1 and any("not a row the driver knows" in line for line in lines), lines)

# ------------------------------------------------------------------------------------------------ the listener row needs a host that tried
code, lines, _ = drive(runner_output({"pb-listener-from-host": "SUCCEEDED"}, listen=False))
must(code == 1 and any(line.startswith("FAIL pb-listener-from-host") and "NOT RUN" in line for line in lines), "no CANARYLISTEN line: the host never tried")
tried = []
D.host_tcp = lambda host, port, family=2: tried.append((host, port)) or False
code, lines, _ = drive(runner_output({"pb-listener-from-host": "SUCCEEDED"}))
must(code == 0 and ("127.0.0.1", 4321) in tried and ("192.168.1.5", 4321) in tried, tried)
D.host_tcp = lambda host, port, family=2: True

# ------------------------------------------------------------------------------------------------ exit 2: the unit could not start
must(drive(b"", ready=False)[0] == 2, "selftest not ready")
code, lines, _ = drive(b"", refuse="sandbox_unavailable")
must(code == 2 and "sandbox_unavailable" in lines[-1], lines)
must(drive(runner_output(), end=False)[0] == 2, "no end frame")
D_ENV = D.os.environ.get("TECTAC_CANARY_ALLOWED_HOST")
D.os.environ["TECTAC_CANARY_ALLOWED_HOST"] = "bad host;rm"
must(drive(runner_output())[0] == 2, "a host name that is not plain is refused")
if D_ENV is None:
    del D.os.environ["TECTAC_CANARY_ALLOWED_HOST"]
else:
    D.os.environ["TECTAC_CANARY_ALLOWED_HOST"] = D_ENV

# ------------------------------------------------------------------------------------------------ ids and ROW lines
code, lines, _ = drive(runner_output())
row_lines = [line for line in lines if line.startswith("ROW ")]
must(len(row_lines) == 29, len(row_lines))
ids = []
for line in row_lines:
    match = re.fullmatch(r"ROW ([a-z0-9-]{1,40}) (OK|ATTACK SUCCEEDED|SKIPPED|NOT RUN|WARN)", line)
    must(match, line)
    ids.append(match.group(1))
must(len(set(ids)) == 29 and ids == all_ids, "ids are unique and stable")
must(lines[1].startswith("host controls: host_public=True"), lines[:3])
print("[TEST] PASS sandbox canary network driver 1.18.23")

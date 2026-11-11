#!/usr/bin/env python3
"""1.17.118 regression: the canary of scripts/sandbox-helper.py and its in-unit attack program (core.sandbox Patch 2, part D).

Django-free. The verdict logic and the table are tested with a scripted ``collect`` (no unit is started): an attack that succeeds, a probe
that cannot run and a skipped public check are each classified correctly and SKIPPED is never read as OK; the canary summary file holds no
secret; ``--selftest --canary`` is root only and is not in the sudo rule; the canary record is never written to the registry and cannot be
started as a registry runner; markers are planted with distinct random content before the run and removed on success and on error; the
program that runs inside the unit prints lines the helper parses without trusting them; the output parsers for ``ss`` and ``ip route``.

Not runnable here: the shell wrapper (tests/sandbox-canary-1.17.118.sh), systemd, cgroups and the real attacks. That is dev02.
"""
from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import py_compile
import shutil
import sys
import threading
from pathlib import Path

sys.dont_write_bytecode = True
# The shared set-up (fake file system, helper loaded as sh, fake systemd), loaded by path; the names it gives are taken explicitly.
_SPEC = importlib.util.spec_from_file_location("sandbox_harness_118", Path(__file__).with_name("sandbox-harness-1.17.118.py"))
H = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(H)
(BASE, CHMODS, CHOWNS, HELPER, ROOT, header, must, norm, sh, start,) = (H.BASE, H.CHMODS, H.CHOWNS, H.HELPER, H.ROOT, H.header, H.must, H.norm, H.sh, H.start,)

# ------------------------------------------------------------------------------------------------ classification
must([sh.classify_tag(t) for t in ("OK", "SUCCEEDED", "SKIP")] == ["OK", "ATTACK SUCCEEDED", "SKIPPED"], "tags")
for odd in ("", "ok", "PASS", "SUCCESS", "OK ", "WARN", None):
    must(sh.classify_tag(odd) == "NOT RUN", f"an unknown word from the unit ({odd!r}) is NOT RUN, never OK")
rows = sh.parse_runner_rows(b"noise\nCANARYROW\tfiles\tOK\tnot found\nCANARYROW\tbad\nCANARYROW\ta\tb\tc\td\nCANARYROW\t\tOK\tx\nCANARYROW\tx\tSKIP\twhy\n")
must([r["attack"] for r in rows] == ["files", "x"] and rows[1]["tag"] == "SKIP", rows)
must(sh.parse_runner_rows("CANARYROW\tp\tOK\t" + "y" * 900)[0]["actual"] == "y" * 300, "an over-long text is cut")
must(sh.parse_runner_rows(b"\xff\xfeCANARYROW\tz\tOK\tfine\n") != [] or True, "bad UTF-8 never raises")

# a table: missing required rows are NOT RUN
table = sh.group_table("Privilege", "privilege", "EPERM", [{"attack": "setuid(0)", "tag": "OK", "actual": "EPERM"}])
verdicts = {r["attack"]: r["verdict"] for r in table}
must(verdicts["setuid(0)"] == "OK" and verdicts["mount"] == "NOT RUN" and verdicts["raw socket"] == "NOT RUN" and len(table) == 8, verdicts)
table = sh.group_table("Public", "public", "x", [{"attack": "public tcp 443", "tag": "SKIP", "actual": "no public route"}])
must(table[0]["verdict"] == "SKIPPED" and table[0]["verdict"] != "OK", table)
table = sh.group_table("Sockets", "sockets", "x", [{"attack": "unix a", "tag": "OK", "actual": "ENOENT"}] * 5)
must(any(r["verdict"] == "NOT RUN" and "5 of 13" in r["actual"] for r in table), table)
table = sh.group_table("Files", "files", "x", [], plan_names=["read /etc/x"])
must(table[0]["verdict"] == "NOT RUN", "a planted marker with no result is NOT RUN")
must(sh.group_table("Limits", "unknown-group", "x", [])[0]["verdict"] == "NOT RUN", "nothing printed at all is NOT RUN")
# the summary
S = sh.canary_summary
ok_row = {"verdict": "OK"}
must(S([ok_row] * 3)[0] is True, "all OK")
must(S([ok_row, {"verdict": "SKIPPED"}, {"verdict": "WARN"}])[0] is True and S([{"verdict": "SKIPPED"}])[1]["OK"] == 0, "SKIPPED and WARN do not fail, and are not counted OK")
must(S([ok_row, {"verdict": "ATTACK SUCCEEDED"}])[0] is False, "a succeeded attack fails")
must(S([ok_row, {"verdict": "NOT RUN"}])[0] is False, "a probe that did not run fails")
must(S([ok_row, {"verdict": "something else"}])[0] is False, "an unknown verdict fails")
must(S([])[0] is True, "")

# ------------------------------------------------------------------------------------------------ the scripted canary
def lines(*pairs):
    return ("\n".join(f"CANARYROW\t{a}\t{t}\t{d}" for a, t, d in pairs) + "\n").encode()


FILES_SOCKS = [(f"unix /s{k}", "OK", "ENOENT") for k in range(13)]
GOOD = {
    "files": None, "work_peer": lines(("another run's /work", "OK", "not found")), "sockets": lines(*FILES_SOCKS),
    "loopback": lines(("loopback 127.0.0.1:80", "OK", "EPERM")),
    "lan": lines(*([(f"udp {a}", "OK", "eperm") for a in range(5)] + [(f"tcp {a}:80", "OK", "EPERM") for a in range(5)])),
    "dns": lines(("allowed resolver answers", "OK", "answered"), ("other resolver dropped", "SKIP", "none listed")),
    "public": lines(("public tcp 443", "OK", "connected")),
    "privilege": lines(*[(n, "OK", "EPERM") for n in ("setuid(0)", "ptrace attach to parent", "mount", "unshare", "mknod", "raw socket", "write /proc/sys", "load a kernel module")]),
    "writes": lines(*[(f"write /{k}", "OK", "EROFS") for k in range(9)]),
    "processes": lines(("host processes invisible", "OK", "2"), ("pid 1 invisible", "OK", "not found")),
    "abstract": lines(("abstract sockets (3 listed)", "OK", "none reachable")),
    "mem": lines(("memory beyond MemoryMax", "OK", "x")), "fork": lines(("fork bomb", "OK", "63 children, then EAGAIN")),
    "scratch": lines(("scratch past its size", "OK", "ENOSPC after 8 MiB")),
    "cred": lines(("credential arrives", "OK", "arrived"), ("credential mode", "OK", "0o400"), ("credential not in environment", "OK", "absent")),
    "work_hold": lines(("hold", "OK", "held")),
}
CALLS = []
PLANS = {}


def make_collect(overrides=None, boom_on=None):
    overrides = overrides or {}

    def collect(group, plan, **kwargs):
        CALLS.append((group, kwargs))
        PLANS[group] = plan
        if boom_on == group:
            raise RuntimeError("scripted failure")
        result = {"stdout": b"", "stderr": b"", "end": {"reason": "exited", "exit": 0}, "refused": None, "run_id": os.urandom(16).hex()}
        if group in overrides:
            result["stdout"] = overrides[group]
        elif group == "files":
            result["stdout"] = lines(*[("read " + m["path"], "OK", "ENOENT") for m in plan["markers"]])
        elif group in GOOD:
            result["stdout"] = GOOD[group]
        if group == "mem":
            result["end"] = {"reason": "oom"}
        elif group == "loop":
            result["end"] = {"reason": "timeout"}
        elif group == "flood":
            result["end"] = {"reason": "output_limit"}
        elif group == "cred":
            result["end"] = {"reason": "exited", "credential_b64": base64.b64encode(("refreshed-" + plan["credential_token"]).encode()).decode()}
        return result
    return collect


class Outside:
    def run_cmd(self, argv, *, timeout=15):
        if argv[0] == "ss":
            return 0, "LISTEN 0 4096 127.0.0.53:53 0.0.0.0:*\nLISTEN 0 511 *:443 *:*\nLISTEN 0 128 [::]:22 [::]:*\nLISTEN 0 100 127.0.0.1:5432 0.0.0.0:*\n", ""
        if argv[0] == "ip":
            return 0, "default via 192.168.1.1 dev eth0 proto dhcp\n", ""
        return 0, "", ""


REAL_CONCURRENCY, REAL_LATENCY = sh._concurrency_rows, sh._latency_rows
# neutralise the parts that need a real server
sh._cancel_rows = lambda collect, status: [{"wall": "Cancel", "attack": "stop mid-run", "expected": "gone", "actual": "gone=True", "verdict": "OK"}]
sh._holders_search = lambda token, unit: []
sh._latency_rows = lambda collect, status: [{"wall": "Latency", "attack": "50 no-op runs", "expected": "p95", "actual": "p95 40 ms", "verdict": "OK"}]
sh._concurrency_rows = lambda collect, status: [{"wall": "Concurrency", "attack": "3 starts", "expected": "2 run", "actual": "ok", "verdict": "OK"}]
MARK_DIRS = []
for name in ("m_etc", "m_var", "m_opt"):
    folder = BASE / name
    folder.mkdir()
    MARK_DIRS.append(str(folder))
sh.CANARY_MARKER_DIRS = tuple(MARK_DIRS) + (str(BASE / "does-not-exist"),)
real_file = BASE / "local_settings.py"
real_file.write_text("SECRET_KEY='x'\n", encoding="utf-8")
sh.CANARY_REAL_FILES = (str(real_file), str(BASE / "absent-real-file"))
status = {"ready": True, "resolver": "127.0.0.53", "resolvers": ["127.0.0.53"]}
Path(sh.RESOLV_CONF).write_text("nameserver 127.0.0.53\nnameserver 10.0.0.2\nnameserver ::1\n", encoding="utf-8")

table = sh.run_canary(status=status, collect=make_collect(), outside=Outside())
passed, counts = sh.canary_summary(table)
must(passed, [r for r in table if r["verdict"] not in ("OK", "SKIPPED")])
must(counts["SKIPPED"] == 1 and counts["OK"] > 40 and counts["ATTACK SUCCEEDED"] == 0 and counts["NOT RUN"] == 0, counts)
walls = {r["wall"] for r in table}
for wall in ("Files", "Sockets", "Loopback", "LAN", "DNS", "Public", "Privilege", "Writes", "Processes", "Limits", "Abstract sockets", "Credential", "Cancel", "Concurrency", "Latency"):
    must(wall in walls, (wall, walls))
# plan details handed to the unit: listening ports, the resolver's ports without DNS, the gateway first, other resolvers IPv4 only
must(PLANS["loopback"]["ports"] == [22, 53, 443, 5432] and PLANS["loopback"]["resolver"] == "127.0.0.53", PLANS["loopback"])
must(PLANS["loopback"]["resolver_ports"] == [22, 53, 443] or PLANS["loopback"]["resolver_ports"] == [53, 443, 22] or sorted(PLANS["loopback"]["resolver_ports"]) == [22, 53, 443], PLANS["loopback"])
must(PLANS["lan"]["lan"][0] == "192.168.1.1" and "169.254.169.254" in PLANS["lan"]["lan"] and len(PLANS["lan"]["lan"]) == 6, PLANS["lan"])
must(PLANS["dns"]["other_resolvers"] == ["10.0.0.2"], PLANS["dns"])
# markers: distinct random content, real files marked as "readable at all", the runner told, and all removed afterwards
markers = PLANS["files"]["markers"]
planted = [m for m in markers if m["content"] is not None]
must(len(planted) == 3 and len({m["content"] for m in planted}) == 3 and all(len(m["content"]) == 32 for m in planted), markers)
must([m for m in markers if m["content"] is None] == [{"path": str(real_file), "content": None}], "the real file, no content")
must(len({os.path.basename(m["path"]) for m in planted}) == 3 and all(os.path.basename(m["path"]).startswith(".tectac-canary-") for m in planted), "distinct names")
must(not list(BASE.glob("*/.tectac-canary-*")) and not sh.CANARY_MARKERS_FILE.exists(), "markers removed on success")
must(real_file.exists(), "a real file is never touched")
# the markers were on disk, 0644, with that content, while the files group ran
seen = {}


def collect_seen(group, plan, **kwargs):
    if group == "files":
        for m in plan["markers"]:
            if m["content"] is not None:
                seen[m["path"]] = (Path(m["path"]).read_text(encoding="utf-8"), CHMODS.get(norm(m["path"])), json.loads(sh.CANARY_MARKERS_FILE.read_text(encoding="utf-8")))
    return make_collect()(group, plan, **kwargs)


sh.run_canary(status=status, collect=collect_seen, outside=Outside())
must(len(seen) == 3 and all(v[0] and v[1] == 0o644 and k in v[2]["paths"] for k, v in seen.items()), seen)
# an error in the middle still removes them
try:
    sh.run_canary(status=status, collect=make_collect(boom_on="sockets"), outside=Outside())
    raise AssertionError("the scripted failure was swallowed")
except RuntimeError:
    pass
must(not list(BASE.glob("*/.tectac-canary-*")) and not sh.CANARY_MARKERS_FILE.exists(), "markers removed on error")
# a crash that leaves the list behind is cleaned by the sweep
sh._plant_markers()
must(len(list(BASE.glob("*/.tectac-canary-*"))) == 3, "planted")
with contextlib.redirect_stdout(io.StringIO()):
    sh.sweep()
must(not list(BASE.glob("*/.tectac-canary-*")), "the sweep removes planted markers")

# ---- an attack that works, a probe that did not run, a skipped public check
bad = sh.run_canary(status=status, collect=make_collect({"privilege": lines(*[(n, "OK", "EPERM") for n in ("setuid(0)", "mount", "unshare", "mknod", "raw socket", "write /proc/sys", "load a kernel module")] + [("ptrace attach to parent", "SUCCEEDED", "returned 0")])}), outside=Outside())
must(sh.canary_summary(bad)[0] is False and next(r for r in bad if r["verdict"] == "ATTACK SUCCEEDED")["attack"] == "ptrace attach to parent", "attack succeeded")
bad = sh.run_canary(status=status, collect=make_collect({"writes": lines(("write /usr", "OK", "EROFS"))}), outside=Outside())
must(sh.canary_summary(bad)[0] is False and any(r["verdict"] == "NOT RUN" and r["wall"] == "Writes" for r in bad), "a probe that printed too little")
bad = sh.run_canary(status=status, collect=make_collect({"files": b"garbage"}), outside=Outside())
must(sh.canary_summary(bad)[0] is False, "markers with no results")
skip = sh.run_canary(status=status, collect=make_collect({"public": lines(("public tcp 443", "SKIP", "no public route"))}), outside=Outside())
must(sh.canary_summary(skip)[0] is True and sum(1 for r in skip if r["verdict"] == "SKIPPED") == 2 and not [r for r in skip if r["attack"] == "public tcp 443" and r["verdict"] == "OK"], "skipped public is not OK")
refused = sh.run_canary(status=status, collect=lambda g, p, **k: {"stdout": b"", "end": None, "refused": "sandbox_unavailable"}, outside=Outside())
must(sh.canary_summary(refused)[0] is False and all(r["verdict"] in ("NOT RUN", "OK", "SKIPPED", "ATTACK SUCCEEDED") for r in refused), "a refused start is NOT RUN")
notready = sh.run_canary(status={"ready": False, "reason": "no cgroup v2"}, collect=make_collect(), outside=Outside())
must(len(notready) == 1 and notready[0]["verdict"] == "NOT RUN" and sh.canary_summary(notready)[0] is False, notready)
# the limit rows: the wrong reason is a finding
liv = sh._limit_rows(make_collect(), status)
must(all(r["verdict"] == "OK" for r in liv) and len(liv) == 5, liv)
wrong = make_collect()


def wrong_collect(group, plan, **kwargs):
    result = wrong(group, plan, **kwargs)
    if group == "loop":
        result["end"] = {"reason": "exited"}
    return result


liv = sh._limit_rows(wrong_collect, status)
must([r["verdict"] for r in liv if r["attack"] == "infinite loop"] == ["ATTACK SUCCEEDED"], liv)
# the credential rows
cr = sh._credential_rows(make_collect(), status)
must(all(r["verdict"] == "OK" for r in cr), [r for r in cr if r["verdict"] != "OK"])
sh._holders_search = lambda token, unit: ["ps"]
cr = sh._credential_rows(make_collect(), status)
must([r["verdict"] for r in cr if "ps," in r["attack"]] == ["ATTACK SUCCEEDED"], "a token visible in ps is a finding")
sh._holders_search = lambda token, unit: []
(sh.SECRETS_ROOT / ("a" * 32)).mkdir(parents=True)
cr = sh._credential_rows(make_collect(), status)
must([r["verdict"] for r in cr if "secrets folder" in r["attack"]] == ["ATTACK SUCCEEDED"], "a leftover secrets folder is a finding")
shutil.rmtree(sh.SECRETS_ROOT / ("a" * 32))

# the concurrency and latency rows, with a scripted collect (the real starts are dev02's)
LOCK, COUNT = threading.Lock(), {"n": 0}


def staged_collect(group, plan, **kwargs):
    with LOCK:
        COUNT["n"] += 1
        n = COUNT["n"]
    refused = {3: "busy", 6: "person_busy"}.get(n)
    return {"refused": refused, "end": None if refused else {"reason": "exited"}, "stdout": b""}


conc = REAL_CONCURRENCY(staged_collect, status)
must([r["verdict"] for r in conc] == ["OK", "OK"] and "busy" in conc[0]["actual"] and "person_busy" in conc[1]["actual"], conc)
COUNT["n"] = 99   # every start runs: three runs on two slots is a finding
conc = REAL_CONCURRENCY(lambda g, p, **k: {"refused": None, "end": {"reason": "exited"}, "stdout": b""}, status)
must([r["verdict"] for r in conc] == ["ATTACK SUCCEEDED", "ATTACK SUCCEEDED"], conc)
lat = REAL_LATENCY(lambda g, p, **k: {"refused": None, "end": {"reason": "exited"}, "stdout": b""}, status)
must(len(lat) == 1 and lat[0]["verdict"] == "OK" and "p95" in lat[0]["actual"], lat)
slow_clock = iter(range(0, 10000, 1))
real_monotonic = sh.time.monotonic
sh.time.monotonic = lambda: next(slow_clock) * 0.5   # every run seems to take 500 ms
try:
    lat = REAL_LATENCY(lambda g, p, **k: {"refused": None, "end": {"reason": "exited"}, "stdout": b""}, status)
finally:
    sh.time.monotonic = real_monotonic
must(lat[0]["verdict"] == "WARN" and sh.canary_summary(lat)[0] is True, lat)   # slow is a warning, not a failure
lat = REAL_LATENCY(lambda g, p, **k: {"refused": "busy", "end": None, "stdout": b""}, status)
must(lat[0]["verdict"] == "NOT RUN", lat)

# ------------------------------------------------------------------------------------------------ canary.json and status
record = sh.canary_record(table, True, counts)
text = json.dumps(record)
must(record["ok"] is True and record["at"].endswith("Z") and "failing" in record and "counts" in record, record)
for m in planted:
    must(m["content"] not in text and m["path"] not in text, "no marker in the summary")
must("refreshed-" not in text and "credential_token" not in text, "no secret in the summary")
sh.run_canary = lambda: bad
with contextlib.redirect_stdout(io.StringIO()) as out:
    code = sh.run_canary_command()
printed = out.getvalue()
must(code == 1 and "CANARY FAILED" in printed and "CANARY PASSED" not in printed and "ATTACK SUCCEEDED" in printed, printed[-400:])
saved = json.loads(sh.CANARY_FILE.read_text(encoding="utf-8"))
must(saved["ok"] is False and CHMODS[norm(sh.CANARY_FILE)] == 0o644 and CHOWNS[norm(sh.CANARY_FILE)] == (0, 0), "root-owned 0644, ok false")
must(saved["failing"] and all(set(r) == {"wall", "attack", "verdict"} for r in saved["failing"]), saved)
sh.run_canary = lambda: table
with contextlib.redirect_stdout(io.StringIO()) as out:
    code = sh.run_canary_command()
must(code == 0 and out.getvalue().rstrip().endswith("CANARY PASSED"), out.getvalue()[-200:])
must(json.loads(sh.CANARY_FILE.read_text(encoding="utf-8"))["ok"] is True, "")
with contextlib.redirect_stdout(io.StringIO()) as out:
    must(sh.show_status() == 0, "")
shown = json.loads(out.getvalue())["status"]
must(shown["canary_ok"] is True and shown["canary_at"].endswith("Z") and shown["slots_total"] >= 1 and shown["slots_used"] == 0, shown)
sh.CANARY_FILE.unlink()
with contextlib.redirect_stdout(io.StringIO()) as out:
    sh.show_status()
shown = json.loads(out.getvalue())["status"]
must(shown["canary_ok"] is False and shown["canary_at"] is None, "no canary file: not ok")
table_text = sh.format_table(table)
must("WALL" in table_text.splitlines()[0] and "VERDICT" in table_text.splitlines()[0] and len(table_text.splitlines()) == len(table) + 2, "table shape")

# ------------------------------------------------------------------------------------------------ root only, not in sudoers, never in the registry
os.geteuid = lambda: 1000
for argv in (["--selftest", "--canary"], ["--canary-launch"]):
    try:
        sh.main(argv)
        raise AssertionError(f"{argv} ran as a normal user")
    except SystemExit as exc:
        must("root" in str(exc), exc)
os.geteuid = lambda: 0
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
rule = [ln for ln in INSTALL.splitlines() if "NOPASSWD: ${SANDBOX_HELPER} --start" in ln]
must(len(rule) == 1 and "--canary" not in rule[0] and "--selftest" not in rule[0] and "--finish" not in rule[0], rule)
# the canary record is in memory: no registry file, and a registry row cannot claim it
must(not (sh.REGISTRY_ROOT / "core.canary.json").exists(), "never written to the registry")
canary = sh.canary_row()
must(canary["id"] == "core.canary" and canary["owner_module"] == "core" and canary["credential_return"] is True and canary["credential_files"] == ["auth"], canary)
must(all(canary["limits"][k] <= sh.LIMITS[k][1] for k in sh.LIMITS), "under the ceilings")
code, frames = start(header("core.canary"), hold=False)
must(frames[0]["code"] == "runner_unknown", "the real --start never runs the canary")
code_frames = io.BytesIO()
sh.start_command(io.BytesIO(json.dumps(header("ai.other")).encode() + b"\n"), canary=True, out_stream=code_frames)
must(json.loads(code_frames.getvalue().decode().splitlines()[0])["code"] == "runner_unknown", "--canary-launch runs core.canary and nothing else")
# the switch stays off
must(sh.SANDBOX_ENABLED is False and "SANDBOX_ENABLED = False" in HELPER.read_text(encoding="utf-8"), "the kill switch is still a constant and off")

# ------------------------------------------------------------------------------------------------ output parsers
ports, by_addr = sh.parse_listening("LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\nLISTEN 0 1 [::1]:631 [::]:*\nLISTEN 0 5 *:8080 *:*\ngarbage\nLISTEN 0 1 1.2.3.4:abc x\n")
must(ports == [53, 631, 8080] and by_addr["*"] == {8080} and by_addr["::1"] == {631}, (ports, by_addr))
must(sh.resolver_ports({"127.0.0.53": {53}, "*": {80}, "0.0.0.0": {443}}, "127.0.0.53") == [53, 80, 443], "wildcard binds count for the resolver address")
must(sh.parse_gateway("default via 10.1.2.3 dev eth0\n") == "10.1.2.3" and sh.parse_gateway("") == "" and sh.parse_gateway("x") == "", "gateway")

# ------------------------------------------------------------------------------------------------ the in-unit program
RUNNER = ROOT / "scripts" / "sandbox-canary-runner.py"
py_compile.compile(str(RUNNER), cfile=str(BASE / "runner.pyc"), doraise=True)
py_compile.compile(str(ROOT / "scripts" / "sandbox-launcher.py"), cfile=str(BASE / "launcher.pyc"), doraise=True)
_RSPEC = importlib.util.spec_from_file_location("canary_runner", RUNNER)
runner = importlib.util.module_from_spec(_RSPEC)
_RSPEC.loader.exec_module(runner)
must(set(runner.GROUPS) == set(sh.CANARY_GROUPS), (set(runner.GROUPS) ^ set(sh.CANARY_GROUPS)))
captured = io.StringIO()
with contextlib.redirect_stdout(captured):
    runner.row("a\tb\nc", "OK", "x\x00y\x1b[31m" + "z" * 500)
line = captured.getvalue()
must(line.count("\n") == 1 and line.count("\t") == 3 + 0 and "\x00" not in line and "\x1b" not in line and len(line) < 400, repr(line))
planted_file = BASE / "etc" / "m.txt"
planted_file.write_text("abc123", encoding="utf-8")
captured = io.StringIO()
with contextlib.redirect_stdout(captured):
    runner.g_files({"markers": [{"path": str(planted_file), "content": "abc123"}, {"path": str(planted_file), "content": "other"},
                                {"path": str(BASE / "nothing.txt"), "content": "x"}, {"path": str(planted_file), "content": None}]})
tags = [ln.split("\t")[2] for ln in captured.getvalue().splitlines()]
must(tags == ["SUCCEEDED", "OK", "OK", "SUCCEEDED"], (tags, captured.getvalue()))   # readable marker is a finding, other content or missing is not
captured = io.StringIO()
with contextlib.redirect_stdout(captured):
    must(runner.main(["bogus"]) == 64 and runner.main([]) == 64 and runner.main(["noop", "extra"]) == 64, "")
sys.stdin = io.StringIO("{not json")
with contextlib.redirect_stdout(captured):
    must(runner.main(["noop"]) == 0, "bad JSON on stdin is an empty plan, not a crash")
sys.stdin = sys.__stdin__
# the unit-side result is never trusted: the helper reads tags, not the program's own verdict
must(sh.classify_tag("OK") == "OK" and sh.parse_runner_rows(b"CANARYROW\tx\tCANARY PASSED\tyes\n")[0]["tag"] == "CANARY PASSED" and sh.classify_tag("CANARY PASSED") == "NOT RUN", "a unit cannot declare the canary passed")

# ------------------------------------------------------------------------------------------------ the wrapper script
WRAPPER = (ROOT / "tests" / "sandbox-canary-1.17.118.sh")
must(WRAPPER.is_file(), "the dev02 wrapper exists")
w = WRAPPER.read_text(encoding="utf-8")
for needle in ("ALL CANARY STEPS PASSED", "PASS", "FAIL", "--selftest --canary", "send back", "canary.json"):
    must(needle in w, needle)
must("\r" not in w, "LF only")

print("[TEST] PASS sandbox canary 1.17.118")
shutil.rmtree(BASE, ignore_errors=True)

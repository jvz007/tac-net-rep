#!/usr/bin/env python3
"""1.17.60 regression: the full module job log route (Johan, 20 October 2026: the Module Manager page showed only 40 log lines).

Covers ``tec_tac.module_job_logs.read_job_log`` on a tempdir of stub job folders, and the view ``ModuleV2JobLogView`` through the
stub harness of the 1.17.58 licensing tests (Django is not installed on this PC). Checked: the id is parsed and rebuilt before any
path exists (non-uuid, uppercase and path forms are refused); a symlinked log, a symlinked folder, a directory and a FIFO are refused;
the scrubber leaves none of a list of fake secrets and keeps a sha256 value and ordinary lines; the 5 MB head-and-tail cap with its
marker and no leak across the cut; the download name is safe for a hostile module id; the headers; a hotfix job; 404 for an unknown job
and for a job without a log; 403 for a non-manager with no file read; one audit row with no log text, and 503 with no text when the
row cannot be written; the existing log_tail code is pinned unchanged.

On this PC symlinks and FIFOs cannot be created (no privilege, no mkfifo). Where the OS refuses, the test fakes the file type that
``os.lstat`` reports, which is the check the code makes. What cannot run here: the route under a real Django, a real root-owned log
folder, and O_NOFOLLOW (Windows has none).
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "framwork"))

from tec_tac import module_job_logs as m  # noqa: E402


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


TMP = Path(tempfile.mkdtemp(prefix="tectac-joblog-"))
m.JOBS_ROOT = TMP / "jobs"
m.LOGS_ROOT = TMP / "logs"
m.HOTFIX_JOBS_ROOT = TMP / "hf" / "jobs"
m.HOTFIX_LOGS_ROOT = TMP / "hf" / "logs"
for folder in (m.JOBS_ROOT, m.LOGS_ROOT, m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT):
    folder.mkdir(parents=True)

_COUNTER = [0]


def new_id():
    _COUNTER[0] += 1
    return f"00000000-0000-4000-8000-{_COUNTER[0]:012d}"


def make_job(*, text=None, data=None, kind="module", **record):
    job_id = new_id()
    jobs, logs = (m.JOBS_ROOT, m.LOGS_ROOT) if kind == "module" else (m.HOTFIX_JOBS_ROOT, m.HOTFIX_LOGS_ROOT)
    base = {"id": job_id, "status": "failed", "action": "install", "plugin_id": "reportmanager", "created_at": "2026-10-20T10:00:00+00:00"}
    base.update(record)
    (jobs / f"{job_id}.json").write_text(json.dumps(base), encoding="utf-8")
    if text is not None:
        data = text.encode("utf-8")
    if data is not None:
        (logs / f"{job_id}.log").write_bytes(data)
    return job_id


@contextmanager
def fake_type(path_ending, mode_bits):
    """Make os.lstat report another file type for one path (where the OS cannot make a symlink or a FIFO)."""
    real = os.lstat
    ending = path_ending.replace("\\", "/")

    def lstat(path, *a, **k):
        info = real(path, *a, **k)
        if str(path).replace("\\", "/").endswith(ending):
            values = list(info)
            values[0] = mode_bits | 0o644
            return os.stat_result(values)
        return info

    os.lstat = lstat
    try:
        yield
    finally:
        os.lstat = real


def refused(job_id_value, status=None):
    try:
        m.read_job_log(job_id_value)
    except m.JobLogError as exc:
        return exc if status is None or exc.status == status else None
    return None


# ------------------------------------------------------------------ the id is checked before any file is touched
touched = []
_real_lstat, _real_open = os.lstat, os.open
os.lstat = lambda p, *a, **k: (touched.append(str(p)), _real_lstat(p, *a, **k))[1]
os.open = lambda p, *a, **k: (touched.append(str(p)), _real_open(p, *a, **k))[0]
try:
    for bad in ("not-a-uuid", "../../etc/passwd", "00000000-0000-4000-8000-000000000001/../x", "00000000-0000-4000-8000-00000000000A".upper(),
                "{00000000-0000-4000-8000-000000000001}", "urn:uuid:00000000-0000-4000-8000-000000000001", "", None, 5,
                "00000000000040008000000000000001", "00000000-0000-4000-8000-000000000001\x00.json"):
        must(refused(bad, 400), f"id {bad!r} must be refused with 400")
finally:
    os.lstat, os.open = _real_lstat, _real_open
must(not touched, f"an invalid id reached the file system: {touched}")
upper = new_id().replace("000000000001", "00000000000A")
must(refused(upper.upper(), 400), "an uppercase uuid must be refused")
print("PASS ids: non-uuid, path forms and uppercase are refused before any file access")

# ------------------------------------------------------------------ a normal log comes back whole
ordinary = "Installing module reportmanager 1.0.0\nstep 2 done\n"
jid = make_job(text=ordinary)
log = m.read_job_log(jid)
must(log.body.decode() == ordinary and log.size == len(ordinary) and not log.truncated and log.kept == "all", "a small log is whole")
must(log.kind == "module" and log.action == "install" and log.module == "reportmanager", "kind, action and module come from the job")
print("PASS a log under the cap comes back whole, truncated false")

# ------------------------------------------------------------------ files that must never be followed or read
secret_file = TMP / "outside-secret.txt"
secret_file.write_text("OUTSIDE-SECRET-CONTENT\n", encoding="utf-8")
jid = make_job(text="x\n")
link = m.LOGS_ROOT / f"{jid}.log"
link.unlink()
try:
    os.symlink(secret_file, link)
    real_symlinks = True
except (OSError, NotImplementedError):
    real_symlinks = False
    link.write_text("placeholder\n")
if real_symlinks:
    exc = refused(jid, 404)
    must(exc is not None, "a symlink named <uuid>.log must be refused, not followed")
else:
    with fake_type(f"{jid}.log", stat.S_IFLNK):
        must(refused(jid, 404) is not None, "a symlink named <uuid>.log must be refused (faked type)")
print(f"PASS a symlinked log is refused ({'real symlink' if real_symlinks else 'file type faked: no symlink privilege on this PC'})")

jid = make_job(text="inside\n")
if real_symlinks:
    other = TMP / "other-logs"
    other.mkdir()
    (other / f"{jid}.log").write_text("OUTSIDE-SECRET-CONTENT\n")
    saved = m.LOGS_ROOT
    shutil_target = TMP / "logs-link"
    os.symlink(other, shutil_target)
    m.LOGS_ROOT = shutil_target
    try:
        must(refused(jid, 404) is not None, "a symlinked logs folder must be refused")
    finally:
        m.LOGS_ROOT = saved
else:
    with fake_type("/logs", stat.S_IFLNK):
        must(refused(jid, 404) is not None, "a symlinked logs folder must be refused (faked type)")
print("PASS a symlinked logs folder is refused")

jid = make_job(text="x\n")
(m.LOGS_ROOT / f"{jid}.log").unlink()
(m.LOGS_ROOT / f"{jid}.log").mkdir()
must(refused(jid, 404) is not None, "a directory named <uuid>.log must be refused")
jid = make_job(text="x\n")
if hasattr(os, "mkfifo"):
    (m.LOGS_ROOT / f"{jid}.log").unlink()
    os.mkfifo(m.LOGS_ROOT / f"{jid}.log")
    must(refused(jid, 404) is not None, "a FIFO named <uuid>.log must be refused (and must not block)")
else:
    with fake_type(f"{jid}.log", stat.S_IFIFO):
        must(refused(jid, 404) is not None, "a FIFO named <uuid>.log must be refused (faked type)")
print("PASS a directory and a FIFO named <uuid>.log are refused")

exc = refused(new_id(), 404)
must(exc is not None and "not found" in str(exc), "an unknown job is a 404 with a plain sentence")
jid = make_job()  # a record, no log
exc = refused(jid, 404)
must(exc is not None and "No log was kept" in str(exc), "a job without a log is 404 'no log was kept'")
print("PASS unknown job 404, job without a log 404")

# ------------------------------------------------------------------ a hotfix job is found in the hotfix folders
jid = make_job(kind="hotfix", text="hotfix applied\n", action="apply", module_id="reportmanager", plugin_id=None)
log = m.read_job_log(jid)
must(log.kind == "hotfix" and log.action == "apply" and log.module == "reportmanager" and log.body == b"hotfix applied\n", "hotfix job read from the hotfix folder")
print("PASS a hotfix job is found in the hotfix folders")

# ------------------------------------------------------------------ scrubbing
HASH = "ab" * 32
KNOX = "3fa85f6457174562b3fc2c963f66afa63fa85f6457174562b3fc2c963f66afa6"
SAMPLE = f"""Installing module reportmanager 1.0.0
-----BEGIN OPENSSH PRIVATE KEY-----
FAKEKEYBODY1b3BlbnNzaC1rZXktdjEAAAAA
FAKEKEYBODY2AAAAB3NzaC1lZDI1NTE5AAAA
-----END OPENSSH PRIVATE KEY-----
publisher_trust state=trusted publisher=tfd key=abcd1234 sha256={HASH}
Authorization: Bearer FAKEBEARERHEADER0123456789
Proxy-Authorization: Basic RkFLRVBST1hZQkFTSUM=
X-API-KEY: FAKEAPIKEYHEADER99
Using Bearer FAKEBEARERINLINE12345 now
Token {KNOX}
Basic ZmFrZXVzZXI6RkFLRUJBU0lD
connecting to https://admin:FAKEURLPASS@example.com/path ok
password=FAKEPASSWORD1
passwd: FAKEPASSWD2 with more words FAKEPASSWD2B
api_key: FAKEAPIKEY3
apikey=FAKEAPIKEY4
licence key: FAKELICENCE5
license_key=FAKELICENSE6
secret_key = FAKESECRETKEY7
token_key=FAKETOKENKEY8
cookie: sessionid=FAKECOOKIE9
csrf=FAKECSRF10
session: FAKESESSION11
{{"password": "FAKEJSONPASS12 with space"}}
run --password FAKECLIPASS13 now
reading /opt/tec-tac/etc/github-token
loading /home/x/.ssh/id_rsa
reading /etc/ssl/private/server.pem
reading /opt/tec-tac/etc/tec-tac-trust/anchor
reading /srv/app/.env
Tests passed: 5
The token was refused
Basic installation complete
Finished reportmanager 1.0.0
"""
FAKES = re.findall(r"FAKE[A-Z0-9]+", SAMPLE) + [KNOX, "RkFLRVBST1hZQkFTSUM", "ZmFrZXVzZXI6RkFLRUJBU0lD", "github-token", "id_rsa", "server.pem",
                                                 "tec-tac-trust", "/srv/app/.env", "OPENSSH PRIVATE KEY", "FAKEPASSWD2B", "with space"]
out = m.scrub_text(m.clean_text(SAMPLE.encode()))
for fake in FAKES:
    must(fake not in out, f"a secret survived the scrubber: {fake!r}\n{out}")
must(f"sha256={HASH}" in out, "a package sha256 after 'sha256=' is kept")
for keep in ("Installing module reportmanager 1.0.0", "Finished reportmanager 1.0.0", "Tests passed: 5", "key=abcd1234", "The token was refused",
             "Basic installation complete"):
    must(keep in out, f"an ordinary line was damaged: {keep!r}\n{out}")
must("<redacted" in out, "the scrubber leaves a visible mark")
# a log through the real read path
jid = make_job(text=SAMPLE)
must(all(fake not in m.read_job_log(jid).body.decode() for fake in FAKES), "read_job_log scrubs")
# control bytes
dirty = b"line one\x00\x01\x1b[31mred\x1b[0m\r\nline two\x7f\xff\n"
cleaned = m.read_job_log(make_job(data=dirty)).body.decode()
must("\x00" not in cleaned and "\x1b" not in cleaned and "\r" not in cleaned and "line two" in cleaned and "red" in cleaned, "NUL, ANSI and control bytes are stripped")
import time  # noqa: E402

started = time.monotonic()
m.scrub_text("\n".join(["a_" * 150000, "a-b" * 100000, ("x" * 200 + "/") * 5000, "token " * 20000]))
must(time.monotonic() - started < 5, "scrubbing pathological lines stays fast (no catastrophic backtracking)")
must("my_password=FAKEX" not in m.scrub_text("my_password=FAKEX") and "db.password=FAKEY" not in m.scrub_text("db.password=FAKEY"), "prefixed keys are still caught")
print("PASS scrubbing leaves no fake secret, keeps sha256= and ordinary lines, strips control bytes")

# ------------------------------------------------------------------ the 5 MB cap
LINE = "ordinary log line number %08d with plain text padding to make it long enough........\n"


def filler(start, count):
    return "".join(LINE % (start + i) for i in range(count))


one_line = len(LINE % 0)
count = (12 * 1024 * 1024) // one_line
big = "FIRST LINE OF THE LOG\n" + filler(0, count) + "LAST LINE OF THE LOG\n"
jid = make_job(text=big)
log = m.read_job_log(jid)
body = log.body.decode()
must(len(log.body) <= m.MAX_LOG_BYTES + 200, f"a 12 MB log must come back at 5 MB plus the marker, got {len(log.body)}")
must(body.startswith("FIRST LINE OF THE LOG\n"), "the cut log starts with the file's first line")
must(body.endswith("LAST LINE OF THE LOG\n"), "the cut log ends with the file's last line")
must(log.truncated and log.kept == "head-and-tail" and log.size == len(big.encode()), "truncated, kept head-and-tail, original size")
marker = re.search(r"\[\.\.\. (\d+) bytes were left out of the middle of this log \.\.\.\]\n", body)
must(marker is not None, "one marker line is in the body")
head_part, tail_part = body[:marker.start()], body[marker.end():]
must(int(marker.group(1)) == log.size - len(head_part.encode()) - len(tail_part.encode()), "the marker's byte count is right")
must(head_part.endswith("\n") and tail_part.startswith("ordinary log line"), "both cuts are at line boundaries")
must(len(re.findall(r"bytes were left out", body)) == 1, "exactly one marker")
print("PASS a 12 MB log gives <= 5 MB + marker, first and last line kept, omitted bytes right")

under = "FIRST\n" + filler(0, 1000) + "LAST\n"
log = m.read_job_log(make_job(text=under))
must(log.body.decode() == under and not log.truncated and log.kept == "all", "a file under the cap is whole")
exact = ("x" * 99 + "\n") * (m.MAX_LOG_BYTES // 100)
must(len(exact) <= m.MAX_LOG_BYTES and m.read_job_log(make_job(text=exact)).truncated is False, "a file at the cap is not cut")
print("PASS a file under the cap comes back whole")

# a private key that straddles the cut: BEGIN in the head, body in the omitted middle, END inside the tail window
half = m.HALF_LOG_BYTES
part_a = "FIRST LINE\n" + filler(0, (half - 60000) // one_line) + "-----BEGIN RSA PRIVATE KEY-----\n"
part_a += "".join("KEYBODYHEAD%08d" % i + "A" * 60 + "\n" for i in range(2000))
part_mid = "".join("KEYBODYMID%08d" % i + "B" * 60 + "\n" for i in range(50000))
part_tail = "".join("KEYBODYTAIL%08d" % i + "C" * 60 + "\n" for i in range(3000)) + "-----END RSA PRIVATE KEY-----\n"
part_tail += filler(10 ** 6, (half - 80000) // one_line) + "LAST LINE\n"
split_file = part_a + part_mid + part_tail
log = m.read_job_log(make_job(text=split_file))
text = log.body.decode()
must(log.truncated, "the straddling file is cut")
must("KEYBODY" not in text and "RSA PRIVATE KEY" not in text, "a private key split across the cut must not leak")
must(text.startswith("FIRST LINE\n") and text.endswith("LAST LINE\n"), "first and last lines survive")
# a key that begins in the omitted middle and ends in the tail, and one that begins in the head and ends in the middle
only_tail = "FIRST LINE\n" + filler(0, (m.MAX_LOG_BYTES * 2) // one_line) + "".join("KEYBODYTAIL%08d" % i + "C" * 60 + "\n" for i in range(3000))
only_tail += "-----END RSA PRIVATE KEY-----\n" + filler(5 * 10 ** 6, (half - 100000) // one_line) + "LAST LINE\n"
text = m.read_job_log(make_job(text=only_tail)).body.decode()
must("KEYBODY" not in text, "a block that began in the omitted middle is redacted from the start of the tail")
print("PASS secrets split across the cut do not leak")

# ------------------------------------------------------------------ download file name
hostile = SimpleNamespace(module=m.safe_label("../../etc/passwd; rm -rf /\r\nX-Evil: 1" + "z" * 100), action=m.safe_label("Install\r\n../x"))
name = m.download_filename(hostile, datetime(2026, 10, 20, tzinfo=timezone.utc))
must(re.fullmatch(r"module-job-[a-z0-9-]{1,40}-[a-z0-9-]{1,40}-2026-10-20\.log", name), f"unsafe download name {name!r}")
must(m.safe_label("") == "unknown" and len(m.safe_label("a" * 90)) == 40, "labels are bounded")
log = m.read_job_log(make_job(text="x\n", plugin_id="../../Evil Module!!\r\nX: 1" + "q" * 80, action="install"))
must(re.fullmatch(r"module-job-[a-z0-9-]{1,40}-install-\d{4}-\d{2}-\d{2}\.log", m.download_filename(log)), "name from a hostile module id is safe")
batch = m.read_job_log(make_job(text="x\n", plugin_id=None, action="batch_install"))
must(batch.module == "batch" and m.download_filename(batch).startswith("module-job-batch-batch-install-"), "a batch job is named batch")
print("PASS the download file name is safe for a hostile module id")

# ------------------------------------------------------------------ the view (stub harness; Django is not installed here)
import licensing_harness_1_17_58 as harness  # noqa: E402

H = harness.install()
v2views = H.v2views
FakeResponse = type("FakeResponse", (), {})


class HttpResponse:
    def __init__(self, content=b"", content_type=None, status=200):
        self.content, self.content_type, self.status_code, self.headers = content, content_type, status, {}

    def __setitem__(self, key, value):
        self.headers[key] = value


harness._stub("django.http", HttpResponse=HttpResponse)
sys.modules["django"].http = sys.modules["django.http"]


def call(user=None, job_id=None, download=None):
    request = SimpleNamespace(user=user or H.User("manager"), query_params={"download": download} if download is not None else {})
    return v2views.ModuleV2JobLogView().get(request, job_id)


def allow():
    v2views._require_module_manager = lambda user: None


def deny():
    def refuse(user):
        raise H.PermissionDenied("no")
    v2views._require_module_manager = refuse


allow()
H.reset()
jid = make_job(text=SAMPLE, plugin_id="reportmanager", action="install")
resp = call(job_id=jid)
must(resp.status_code == 200 and resp.content_type == "text/plain; charset=utf-8", "inline answer is text/plain utf-8")
must(resp.headers["X-Content-Type-Options"] == "nosniff" and resp.headers["Cache-Control"] == "no-store", "nosniff and no-store")
must(resp.headers["X-Tec-Tac-Log-Truncated"] == "false" and resp.headers["X-Tec-Tac-Log-Kept"] == "all"
     and resp.headers["X-Tec-Tac-Log-Bytes"] == str(len(SAMPLE.encode())), "the three log headers")
must("Content-Disposition" not in resp.headers, "inline by default")
must(len(H.audits) == 1, "one audit row per successful read")
row = H.audits[0]
must(row["action"] == "view" and row["object_type"] == "module_job_log" and row["object_id"] == jid and row["module_id"] == "core" and row["strict"] is True,
     f"audit row shape: {row}")
must(set(row["metadata"]) == {"job_id", "kind", "action", "module", "bytes", "truncated", "download"} and row["metadata"]["download"] is False, "audit metadata")
must("reportmanager 1.0.0" not in json.dumps(row, default=str) and not any(fake in json.dumps(row, default=str) for fake in FAKES), "the audit row carries no log text")
resp = call(job_id=jid, download="1")
must(re.fullmatch(r'attachment; filename="module-job-reportmanager-install-\d{4}-\d{2}-\d{2}\.log"', resp.headers["Content-Disposition"]), "download header")
must(len(H.audits) == 2 and H.audits[1]["metadata"]["download"] is True, "the download is audited as a download")
resp = call(job_id=make_job(text=big), download="1")
must(resp.headers["X-Tec-Tac-Log-Truncated"] == "true" and resp.headers["X-Tec-Tac-Log-Kept"] == "head-and-tail"
     and int(resp.headers["X-Tec-Tac-Log-Bytes"]) == len(big.encode()), "truncated headers")
must(H.audits[-1]["metadata"]["truncated"] is True and H.audits[-1]["metadata"]["bytes"] == len(big.encode()), "truncation is in the audit counts")
print("PASS the view: text/plain, headers, download name, one audit row without log text")

resp = call(job_id=new_id())
must(resp.status_code == 404 and "not found" in resp.data["detail"], "unknown job 404")
resp = call(job_id=make_job())
must(resp.status_code == 404 and "No log was kept" in resp.data["detail"], "no log 404")
resp = call(job_id="not-a-uuid")
must(resp.status_code == 400, "a bad id the URL converter would never pass is a 400")
before = len(H.audits)
must(len(H.audits) == before, "a refusal writes no row")

H.reset()
jid = make_job(text=SAMPLE)
H.audit_fail.on = True
resp = call(job_id=jid)
must(resp.status_code == 503 and not isinstance(resp, HttpResponse), "an audit failure gives 503")
must(not any(fake in json.dumps(resp.data) for fake in FAKES) and "reportmanager 1.0.0" not in json.dumps(resp.data), "no log text with the 503")
H.reset()
print("PASS unknown job 404, no log 404, audit failure 503 with no text")

reads = []
real_read = m.read_job_log
m.read_job_log = lambda *a, **k: (reads.append(a), real_read(*a, **k))[1]
deny()
H.reset()
try:
    call(user=H.User("tech"), job_id=jid)
    raise AssertionError("a non-manager must get 403")
except H.PermissionDenied:
    pass
must(not reads and not H.audits, "a refused caller reads no file and writes no row")
allow()
m.read_job_log = real_read
print("PASS a non-manager is refused (403) before any file is read, no audit row")

# ------------------------------------------------------------------ the existing log_tail code is unchanged
src = (ROOT / "framwork" / "tec_tac" / "module_manager.py").read_text(encoding="utf-8")
tree = ast.parse(src)
PINNED = {  # sha256 of the function source as of 1.17.59
    "public_job": "0b63c95def8806f0cb64753e31caf23fa2240e8fea30037703ea108aa6883e71",
    "get_job": "68c42bf68f22b56c91da2b05b6d67ffce0ab8d559c2ce290cb9822065aa40b9e",
    "list_jobs": "676e80f43ac7a145fbd5a33a3aa81b588ce393ca64913fa9b45fc4bdbc79528e",
    "_load_job_history_rows": "824e93816d8ea6f34e4c5f8f21d96821c6baf3262e6889788fe7774f0a680d1d",
    "page_jobs": "f42907e74e997faa568f6001674c4315e7c71529a9edee8bd01bb1bab5a9c11d",
}
seen = {}
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in PINNED:
        seen[node.name] = hashlib.sha256(ast.get_source_segment(src, node).encode()).hexdigest()
must(seen == PINNED, f"module_manager.public_job, get_job and the list code must stay byte-identical to 1.17.59: {seen}")
from tec_tac import module_manager as mm  # noqa: E402

mm.LOGS_ROOT = m.LOGS_ROOT
jid = make_job(text="".join(f"line {i} password=KEEP-AS-IS\n" for i in range(60)))
shown = mm.public_job({"id": jid, "status": "failed", "action": "install"})
must(shown["log_tail"] == [f"line {i} password=KEEP-AS-IS" for i in range(20, 60)] and len(shown["log_tail"]) == 40, "log_tail is still the last 40 raw lines")
must("log_job_view" not in src and "module_job_logs" not in src, "module_manager does not import the new module")
print("PASS log_tail in the existing routes is unchanged (source pinned, output checked)")

for word in ("password", "token", "secret", "key", "session"):
    for sep in ("-", "_"):
        for tail in (" end", "", " end:"):
            line = word + (sep + "a") * 5000 + tail
            began = time.perf_counter()
            out = m.scrub_text(line)
            took = time.perf_counter() - began
            must(took < 1.0, f"scrub_text must not backtrack on {word}{sep}a*5000{tail!r}: {took:.2f}s")
began = time.perf_counter()
m.scrub_text("x" * 200000 + " password" + "-a" * 100000)
must(time.perf_counter() - began < 1.0, "a very long line is cut and scrubbed fast")
must("<redacted>" in m.scrub_text("my-api-key-name_2 = hunter2") and "hunter2" not in m.scrub_text("my-api-key-name_2 = hunter2"), "dashed key names are still redacted")
print("PASS no catastrophic backtracking in the key/value scrubber")

print("PASS module-job-logs-1.17.60")

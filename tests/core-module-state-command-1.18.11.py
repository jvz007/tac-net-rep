#!/usr/bin/env python3
"""Regression: manage.py tectac_module_state, the root-only way to switch a module on or off (Core 1.18.11, reworked in rebuilds 1 and 2).

The command is loaded with stubs (the style of tests/session-policy-command-1.18.2.py): no Django, no root, no helper.
What cannot run here: the command and the helper as root on a server (tested with stubs only)."""
import importlib.util
import json
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CMD = ROOT / "framwork" / "tec_tac" / "management" / "commands" / "tectac_module_state.py"
assert b"\r" not in CMD.read_bytes()


def must(cond, msg=""):
    if not cond:
        raise AssertionError(msg)


class CommandError(Exception):
    pass


class BaseCommand:
    def __init__(self):
        self.out = []
        self.stdout = types.SimpleNamespace(write=self.out.append)


def stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


stub("django")
stub("django.core")
stub("django.core.management")
stub("django.core.management.base", BaseCommand=BaseCommand, CommandError=CommandError)
pkg = types.ModuleType("tec_tac")
pkg.__path__ = []
sys.modules["tec_tac"] = pkg
spec = importlib.util.spec_from_file_location("tectac_module_state_t", CMD)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
must("tec_tac.audit" not in sys.modules, "lazy import: nothing from tec_tac is loaded at start-up")

ROWS, CALLS = [], []
AUDIT = stub("tec_tac.audit")
AUDIT.service_audit_actor = lambda **kw: types.SimpleNamespace(kind="service", **kw)
AUDIT.record = lambda **kw: ROWS.append(kw)
pkg.audit = AUDIT
EUID = {"value": 1000}
mod.os.geteuid = lambda: EUID["value"]
HELPER_ANSWER = {"rc": 0, "out": "", "err": ""}


def call(module_id="patching", enable=False, disable=False, cascade=False, record=""):
    command = mod.Command()
    try:
        command.handle(module_id=module_id, enable=enable, disable=disable, cascade=cascade, record_outcome=record)
    except CommandError as exc:
        return command, str(exc)
    return command, None


def outcome(**fields):
    base = {"before": True, "after": False, "cascade": False, "affected": ["patching"], "enabled_back": []}
    base.update(fields)
    return json.dumps(base)


# Rebuild 1: manage.py never runs as root and never calls the helper
EUID["value"] = 0
_, err = call(record=outcome())
must(err and err.startswith("Do not run manage.py as root") and "--server-command" in err and ROWS == [], err)
EUID["value"] = 1000
_, err = call(disable=True)
must(err and "sudo /usr/local/sbin/tec-tac-module-v2-job --server-command disable patching" in err and ROWS == [] and CALLS == [], err)
_, err = call(disable=True, cascade=True)
must(err and err.endswith("patching --cascade"), err)
_, err = call(module_id="a b; rm", record=outcome())
must(err and ROWS == [], err)
_, err = call(record="not json")
must(err and "not valid JSON" in err and ROWS == [], err)
# the audit step: one row with the command's actor
command, err = call(record=outcome())
must(err is None and len(ROWS) == 1 and CALLS == [], (err, ROWS, CALLS))
row = ROWS[0]
must(row["action"] == "modify" and row["module_id"] == "core" and row["object_type"] == "module" and row["object_id"] == "patching" and row["strict"] is False, row)
must("server command (tectac_module_state)" in row["actor"].identity and row["actor"].module_id == "core", row["actor"])
must(row["before"] == {"enabled": True} and row["after"] == {"enabled": False}, row)
must(row["metadata"]["module"] == "patching" and row["metadata"]["command"] == "tectac_module_state" and row["metadata"]["cascade"] is False, row)
del ROWS[:]
call(record=outcome(cascade=True, affected=["needs", "patching"], before=False, after=True))
must(ROWS[0]["metadata"]["cascade"] is True and ROWS[0]["metadata"]["affected"] == ["needs", "patching"] and ROWS[0]["after"] == {"enabled": True}, ROWS)

# ------------------------------------------------------------------------------------------------ the helper source
helper = (ROOT / "scripts" / "module-v2-job-helper.py").read_text(encoding="utf-8")
main = helper[helper.index('if __name__ == "__main__":'):]
must(main.index("geteuid() != 0") < main.index("--server-command"), "root is required before the server command")
# No documented or coded path runs manage.py as euid 0 (rebuild 1)
must("runuser" in helper[helper.index("def record_server_command_audit("):helper.index("def mark_failed(")], "the audit step is demoted with runuser")
audit_src = helper[helper.index("def record_server_command_audit("):helper.index("def mark_failed(")]
must('"runuser", "-u", tactical_user, "--"' in audit_src and "--record-outcome" in audit_src, "demoted manage.py call")
fn_src = helper[helper.index("def server_command_main("):helper.index("def mark_failed(")]
must("action, module_id = argv[2], argv[3]" in fn_src and "sys.argv" not in fn_src, "arguments read once")
must(fn_src.index("server_command(action, module_id") < fn_src.index("record_server_command_audit("), "audit after the change")
must("server_command_main(sys.argv)" in main, "the main block calls the function")
cmd_src = CMD.read_text(encoding="utf-8")
must("os.geteuid() == 0" in cmd_src and "geteuid() != 0" not in cmd_src and "subprocess" not in cmd_src, "the command refuses root and runs nothing")
for rel in ("docs/module-categories.md", f"RELEASE_NOTES_{(ROOT / "VERSION").read_text(encoding="utf-8").strip()}.md", "README.md", "framwork/tec_tac/contracts.py", "install.sh"):
    text = (ROOT / rel).read_text(encoding="utf-8")
    must(not re.search(r"sudo -u root[^\n]*manage\.py", text), rel)
    must("root-only manage.py" not in text, rel)
must('len(sys.argv) in (4, 5) and sys.argv[1] == "--server-command"' in main, "argv length 4 or 5")
for sudoers in re.findall(r"module-v2-job[^\n]*", (ROOT / "install.sh").read_text(encoding="utf-8")):
    must("--server-command" not in sudoers, sudoers)
install = (ROOT / "install.sh").read_text(encoding="utf-8")
must("--server-command" not in install, "install.sh never grants the server command")
must(re.search(r"MODULE_V2_SUDOERS.*\n", install) and "--dispatch *" in install, "the v2 sudoers line stays --dispatch only")
server = helper[helper.index("def server_command("):helper.index("def mark_failed(")]
must("skip_core_lock=True" in server and server.count("skip_core_lock") == 1, "only the disable skips the core lock")
must("--cascade" in server and "required by enabled module(s)" in server, "the dependants rule stays")
must("apply_enable_job(repo_root, [module_id], [], False)" in server, "enable runs the replacement rules unconfirmed")
# ------------------------------------------------------------------------------ rebuild 2: run server_command_main with stubs
import contextlib
import io

helper_path = ROOT / "scripts" / "module-v2-job-helper.py"
for _missing in ("fcntl", "pwd"):  # the helper is Linux-only; stub what Windows lacks
    if _missing not in sys.modules:
        try:
            importlib.import_module(_missing)
        except ImportError:
            stub(_missing)
hmod = types.ModuleType("module_v2_job_helper_t")
hmod.__file__ = str(helper_path)
exec(compile(helper.replace("TRUSTED_BASH = _resolve_trusted_bash()", 'TRUSTED_BASH = "/bin/bash"'), str(helper_path), "exec"), hmod.__dict__)
RUN = []
hmod.load_config = dict
hmod.privileged_env = lambda extra=None: {**(extra or {})}
hmod.subprocess.run = lambda command, **kw: (RUN.append(command), types.SimpleNamespace(returncode=0, stdout="", stderr=""))[1]
STATE = {"result": {"changed": True, "before": True, "after": False, "affected": ["patching", "needs"], "enabled_back": []}}
hmod.server_command = lambda action, module_id, cascade=False, log=None: dict(STATE["result"])


def run_main(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = hmod.server_command_main(argv)
    return rc, buf.getvalue().splitlines()


rc, lines = run_main(["x", "--server-command", "disable", "patching"])
must(rc == 0 and len(RUN) == 1, (rc, RUN))
cmd = RUN[0]
must(cmd[cmd.index("tectac_module_state") + 1] == "patching" and "disable" not in cmd, cmd)
must(lines[0].startswith("patching is now off.") and not any(line.startswith("disable is") for line in lines), lines)
must("Also switched off: needs." in lines, lines)
recorded = json.loads(cmd[cmd.index("--record-outcome") + 1])
del ROWS[:]
call(module_id=cmd[cmd.index("tectac_module_state") + 1], record=json.dumps(recorded))
must(len(ROWS) == 1 and ROWS[0]["metadata"]["module"] == "patching" and ROWS[0]["object_id"] == "patching", ROWS)
del RUN[:]
STATE["result"] = {"changed": False, "after": True}
rc, lines = run_main(["x", "--server-command", "enable", "patching", "--cascade"])
must(rc == 0 and RUN == [] and lines == ["patching is already on. Nothing changed."], (rc, RUN, lines))

# the checklist uses the forms the helper accepts
notes = (ROOT / f"RELEASE_NOTES_{(ROOT / "VERSION").read_text(encoding="utf-8").strip()}.md").read_text(encoding="utf-8")
must("--server-command enable" in notes and "--server-command disable" in notes, "checklist forms")
for line in notes.splitlines():
    must(not ("module-v2-job" in line and re.search(r"\s--(enable|disable)\b", line)), line)

# the rebuild number stays out of source (promotion refuses it); tests/ and docs/ are exempt
rebuild = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
must(re.fullmatch(r"\d+\.\d+\.\d+-\d+", rebuild), rebuild)
allowed = {"VERSION", "tec_tac_package.json", f"RELEASE_NOTES_{rebuild}.md"}
skip_dirs = {".git", "tests", "docs", "node_modules", "__pycache__"}
for path in ROOT.rglob("*"):
    rel = path.relative_to(ROOT)
    if not path.is_file() or skip_dirs & set(rel.parts[:-1]) or rel.as_posix() in allowed:
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    must(rebuild not in text, f"{rebuild} found in {rel}")
print("[TEST] PASS core module state command 1.18.11")

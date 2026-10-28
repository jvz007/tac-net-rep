#!/usr/bin/env python3
"""1.17.90 regression: the test-only load seed command tectac_endpoint_agent_loadseed. Refuses without the setting and with it False;
with it True creates N prefixed rows (tokens only in the --out file, mode 0600); cleanup removes only prefixed rows and never touches
others; the command text prints no token. Fake models, the real command file."""
from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile
import types
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
path = ROOT / "framwork" / "tec_tac" / "management" / "commands" / "tectac_endpoint_agent_loadseed.py"
spec = importlib.util.spec_from_file_location("loadseed_under_test", path)
cmd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cmd)


def must(condition, message="check failed"):
    if not condition:
        raise AssertionError(message)


class Table:
    def __init__(self, field):
        self.rows, self.field = [], field

    def filter(self, **kw):
        (key, value), = kw.items()
        name, _, op = key.partition("__")
        match = [r for r in self.rows if (str(getattr(r, name, "")).startswith(value) if op == "startswith" else getattr(r, name, None) == value)]
        table = self

        class Q:
            def delete(_self):
                for r in match:
                    table.rows.remove(r)
                return (len(match), {})

        return Q()

    def create(self, **kw):
        row = types.SimpleNamespace(**kw)
        row.key = f"tok{len(self.rows):036d}"
        self.rows.append(row)
        return row

    def get_or_create(self, **kw):
        for r in self.rows:
            if all(getattr(r, k, None) == v for k, v in kw.items()):
                return r, False
        return self.create(**kw), True

    def create_user(self, **kw):
        kw.pop("password", None)
        return self.create(**kw)


class M:
    def __init__(self, field):
        self.objects = Table(field)


User, Agent, TokenM, Client, Site = M("username"), M("agent_id"), M("key"), M("name"), M("name")
# the Site filter in cleanup uses a related-name lookup; the fake keeps sites by name only
Site.objects.filter = lambda **kw: types.SimpleNamespace(delete=lambda: (0, {}))
models = (User, Agent, TokenM, Client, Site)
User.objects.create(username="real-person")
Agent.objects.create(agent_id="real-agent-1")

# refusal: the setting is absent, False, or merely truthy
settings = types.SimpleNamespace()
sys.modules["django.conf"] = types.SimpleNamespace(settings=settings)
must(cmd.allowed() is False, "absent setting refuses")
settings.TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST = False
must(cmd.allowed() is False, "False refuses")
settings.TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST = "yes"
must(cmd.allowed() is False, "only True allows")
c = cmd.Command()
settings.TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST = False
try:
    c.handle(count=3, out="x", cleanup=False)
    raise AssertionError("handle must refuse")
except cmd.CommandError as exc:
    must("Refused" in str(exc) and cmd.SETTING in str(exc), str(exc))
must(len(User.objects.rows) == 1, "nothing was created")

# allowed: N prefixed rows, tokens only in the 0600 file
settings.TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST = True
cmd._models = lambda: models
out = Path(tempfile.mkdtemp()) / "tokens.txt"
printed: list = []
c.stdout = types.SimpleNamespace(write=printed.append)
c.handle(count=3, out=str(out), cleanup=False)
must([r.username for r in User.objects.rows if r.username.startswith("loadtest-ea-")] == ["loadtest-ea-00001", "loadtest-ea-00002", "loadtest-ea-00003"], "prefixed users")
must(len(Agent.objects.rows) == 4 and len(TokenM.objects.rows) == 3, "agents and tokens")
lines = out.read_text(encoding="utf-8").splitlines()
must(len(lines) == 3 and all(len(line.split()) == 2 for line in lines), lines)
if os.name == "posix":
    must(stat.S_IMODE(out.stat().st_mode) == 0o600, oct(out.stat().st_mode))
must(not any(row.key in "".join(printed) for row in TokenM.objects.rows), "no token printed")
must("loadtest-ea-00001" in "".join(printed), "ids are printed")

# the cap and the required file
for bad in (0, cmd.MAX_COUNT + 1):
    try:
        c.handle(count=bad, out=str(out), cleanup=False)
        raise AssertionError("count out of range must fail")
    except cmd.CommandError:
        pass
try:
    c.handle(count=2, out="", cleanup=False)
    raise AssertionError("--out is required")
except cmd.CommandError:
    pass

# cleanup removes exactly the prefixed rows
printed.clear()
c.handle(count=0, out="", cleanup=True)
must([r.username for r in User.objects.rows] == ["real-person"], [r.username for r in User.objects.rows])
must([r.agent_id for r in Agent.objects.rows] == ["real-agent-1"], "a row without the prefix is never touched")
# cleanup also refuses without the setting
settings.TEC_TAC_ALLOW_ENDPOINT_AGENT_LOADTEST = False
try:
    c.handle(count=0, out="", cleanup=True)
    raise AssertionError("cleanup must refuse too")
except cmd.CommandError:
    pass

# the command text never prints a token
source = path.read_text(encoding="utf-8")
must("print(" not in source and "logger" not in source and "token.key" in source, "tokens go to the file only")
for call in [ln for ln in source.splitlines() if "stdout.write" in ln or "CommandError(" in ln]:
    must("key" not in call.lower().replace("keys", ""), call)
print("PASS endpoint transport loadseed 1.17.90")

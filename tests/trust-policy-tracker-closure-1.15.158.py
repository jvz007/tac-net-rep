#!/usr/bin/env python3
from __future__ import annotations
import ast, re, subprocess, tempfile, time
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
# L26: execute the production get_throttles method body with the production class shape.
p=ROOT/'framwork/tec_tac/views.py'; tree=ast.parse(p.read_text())
view=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='SystemUpdateTrustPolicyView')
method=next(n for n in view.body if isinstance(n,ast.FunctionDef) and n.name=='get_throttles')
class APIView:
    throttle_classes=[]
    def get_throttles(self): return [c() for c in self.throttle_classes]
class TrustPolicyMinThrottle: pass
class TrustPolicyDayThrottle: pass
ns={'APIView':APIView,'TrustPolicyMinThrottle':TrustPolicyMinThrottle,'TrustPolicyDayThrottle':TrustPolicyDayThrottle}
mod=ast.Module(body=[ast.ClassDef(name='SystemUpdateTrustPolicyView',bases=[ast.Name(id='APIView',ctx=ast.Load())],keywords=[],body=[ast.Assign(targets=[ast.Name(id='throttle_classes',ctx=ast.Store())],value=ast.List(elts=[ast.Name(id='TrustPolicyMinThrottle',ctx=ast.Load()),ast.Name(id='TrustPolicyDayThrottle',ctx=ast.Load())],ctx=ast.Load())),method],decorator_list=[])],type_ignores=[])
ast.fix_missing_locations(mod); exec(compile(mod,str(p),'exec'),ns)
obj=ns['SystemUpdateTrustPolicyView'](); obj.request=SimpleNamespace(method='GET'); assert obj.get_throttles()==[]
obj.request=SimpleNamespace(method='PUT'); assert [type(x) for x in obj.get_throttles()]==[TrustPolicyMinThrottle,TrustPolicyDayThrottle]
# L27: execute the exact installer immediate check with fail and hang helpers.
install=(ROOT/'install.sh').read_text()
m=re.search(r'TRUST_POLICY_CHECK_TIMEOUT_SECONDS="\$\{TEC_TAC_TRUST_POLICY_CHECK_TIMEOUT_SECONDS:-30\}".*?\nfi\nlog "Installed persistent trust-policy revert service/timer\."',install,re.S)
assert m and 'timeout --signal=TERM --kill-after=5s' in m.group(0)
assert install.index('systemctl enable --now tec-tac-trust-policy-revert.timer') < m.start()
block=m.group(0)
with tempfile.TemporaryDirectory() as raw:
    td=Path(raw)
    for name,body,limit in [('fail','exit 23\n',3.0),('hang','sleep 30\n',4.0)]:
        cli=td/name; cli.write_text('#!/bin/sh\n'+body); cli.chmod(0o755)
        s=td/(name+'.sh'); s.write_text('#!/bin/bash\nset -e\nTRUST_POLICY_CLI='+str(cli)+'\nTEC_TAC_TRUST_POLICY_CHECK_TIMEOUT_SECONDS=1\nlog(){ printf "%s\\n" "$*"; }\n'+block+'\nprintf "AFTER\\n"\n')
        t=time.monotonic(); r=subprocess.run(['bash',str(s)],text=True,capture_output=True,timeout=8); elapsed=time.monotonic()-t
        assert r.returncode==0 and 'AFTER' in r.stdout and 'persistent timer will retry' in r.stdout and elapsed<limit,(name,r.returncode,elapsed,r.stdout,r.stderr)
print('[TEST] PASS L26/L27 tracker closure 1.15.158')

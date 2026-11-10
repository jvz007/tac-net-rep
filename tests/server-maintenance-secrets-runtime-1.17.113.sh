#!/usr/bin/env bash
# Runtime check for Core 1.17.113: secret_inputs of core.server_maintenance, with the real root helper, systemd and tmpfs.
# It did NOT run on the development PC (it needs root, systemd and a Linux server). DEV SERVER ONLY, as root, after Core 1.17.113 is installed.
#
#   sudo bash tests/server-maintenance-secrets-runtime-1.17.113.sh
#
# It plays Core's part: it pipes the secret on the stdin of `--dispatch`, exactly as Core's subprocess call does. It uses a throw-away
# module id, smsec, and cleans up after itself. Run it when no module install, upgrade or Core update is running.
# It prints PASS or FAIL for each step and exits 1 when any step fails.
#
# What to send back after a FAIL: the whole output of the script, plus `ls -la /run/tec-tac/server-maintenance/secrets`,
# `findmnt -T /run` and the last 30 lines of /var/lib/tec-tac/server-maintenance/audit.jsonl. Never send the test value; it is a dummy.
set -u

HELPER=/usr/local/sbin/tec-tac-server-maintenance
STATE=${TEC_TAC_SM_STATE:-/var/lib/tec-tac/server-maintenance}
REG=${TEC_TAC_SM_REGISTRY:-/etc/tec-tac/server-maintenance/actions.d}
ACT=${TEC_TAC_SM_ACTIONS:-/usr/local/lib/tec-tac/server-maintenance/actions}
EXT=${TEC_TAC_EXTENSIONS_ROOT:-/opt/tec-tac/extensions}
SECRETS=/run/tec-tac/server-maintenance/secrets
MOD=smsec
VALUE="DUMMY-SECRET-VALUE-6d1e0b-not-real"
WORK=$(mktemp -d /root/smsec-check.XXXXXX)
FAILS=0
JOBS_STARTED=""

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }

cleanup() {
  for id in $JOBS_STARTED; do systemctl stop "tec-tac-server-maintenance-$id" >/dev/null 2>&1; rm -rf "${SECRETS:?}/${id:?}"; done
  "$HELPER" --unregister-module "$MOD" >/dev/null 2>&1
  for id in $JOBS_STARTED; do
    rm -rf "${STATE:?}/running/${id:?}" "${STATE:?}/jobs/${id:?}.json" "${STATE:?}/logs/${id:?}".*
  done
  rm -rf "${EXT:?}/${MOD:?}" "${ACT:?}/${MOD:?}" "${WORK:?}"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "FAIL this script must run as root"; exit 1; fi
[ -x "$HELPER" ] || { echo "FAIL the root helper is missing at $HELPER"; exit 1; }
grep -q 'secret_inputs' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.113: it has no secret_inputs"; exit 1; }

echo "== step 0: /run is memory"
FSTYPE=$(findmnt -n -o FSTYPE -T /run 2>/dev/null)
[ "$FSTYPE" = "tmpfs" ] && pass "0a /run is tmpfs ($FSTYPE)" || fail "0a /run is tmpfs (got '$FSTYPE')"

echo "== step 1: install the throw-away module with an action that lists secret_inputs"
mkdir -p "$EXT/$MOD/server_maintenance/actions"
cat > "$EXT/$MOD/server_maintenance/actions/use.sh" <<'PROG'
#!/bin/bash
# reads the secret file, waits 6 seconds (so the check can look at /proc and ps), then echoes the value by mistake (the scrub must catch it)
D="$TEC_TAC_SERVER_MAINTENANCE_SECRET_DIR"
echo "dir=$D"
[ -f "$D/dns-token" ] || { echo "no file"; exit 4; }
V=$(cat "$D/dns-token")
echo "length=${#V}"
sleep 6
echo "oops $V"
echo "oops again $V" >&2
exit 0
PROG
cat > "$EXT/$MOD/tec_tac.json" <<JSON
{"id": "$MOD", "type": "extension", "version": "0.1.0", "category": "server",
 "requires": {"framework": ">=1.17.113"},
 "publisher_permissions": ["server_maintenance.register"],
 "permission_groups": {"Probe": ["$MOD.run"]},
 "server_maintenance_actions": [
   {"id": "$MOD.use", "permission": "$MOD.run", "executable": "server_maintenance/actions/use.sh", "timeout_seconds": 120,
    "secret_inputs": [{"name": "dns-token", "required": true}, {"name": "api-key", "required": false}]},
   {"id": "$MOD.plain", "permission": "$MOD.run", "executable": "server_maintenance/actions/use.sh", "timeout_seconds": 120}]}
JSON
chown -R root:root "$EXT/$MOD"; chmod -R go-w "$EXT/$MOD"; chmod 755 "$EXT/$MOD/server_maintenance/actions/use.sh"
if "$HELPER" --register-module "$MOD" >"$WORK/register.out" 2>&1; then pass "1a --register-module accepts secret_inputs"; else fail "1a --register-module accepts secret_inputs: $(cat "$WORK/register.out")"; exit 1; fi
python3 - "$REG/$MOD.use.json" <<'PY' && pass "1b the registry carries the two names" || fail "1b the registry carries the two names"
import json, sys
a = json.load(open(sys.argv[1]))
assert a["secret_inputs"] == [{"name": "dns-token", "required": True}, {"name": "api-key", "required": False}], a
assert a["registered_by"] == "module-manifest", a
PY
printf '{"id": "%s.hand", "executable": "%s", "argv": [], "secret_inputs": ["x"]}' "$MOD" "$ACT/$MOD/use.sh" > "$WORK/hand.json"
if "$HELPER" --register "$WORK/hand.json" >/dev/null 2>&1; then fail "1c --register refuses secret_inputs"; else pass "1c --register refuses secret_inputs"; fi

new_job() { # new_job <action id> -> prints the job id, written as Core writes it
  python3 - "$STATE" "$1" <<'PY'
import json, sys, uuid
state, action = sys.argv[1:3]
jid = str(uuid.uuid4())
job = {"schema": 1, "id": jid, "action": action, "action_revision": "1", "action_permission": "smsec.run", "owner_module": "smsec", "status": "queued", "stage": "queued",
       "created_at": "2026-11-10T00:00:00+00:00", "started_at": None, "finished_at": None, "cancel_requested_at": None,
       "context": {"source_module": "smsec", "source_action": "smsec.run", "requested_by": "runtime-check"}, "parameters": {}, "public_parameters": {},
       "lock": {"scope": "global", "state": "pending", "acquired_at": None}, "exit_result": None, "failure": None, "secret_inputs": ["dns-token"], "signals": []}
open(f"{state}/jobs/{jid}.json", "w").write(json.dumps(job))
print(jid)
PY
}
jstatus() { python3 -c "import json,sys; print(json.load(open('$STATE/jobs/$1.json')).get(sys.argv[1], ''))" "$2"; }
wait_status() { for _ in $(seq 1 "$3"); do [ "$(jstatus "$1" status)" = "$2" ] && return 0; sleep 1; done; return 1; }
stdin_json() { python3 -c "import base64,json,sys; print(json.dumps({'dns-token': base64.b64encode(sys.argv[1].encode()).decode(), 'extra': 'ZXh0cmE='}))" "$VALUE"; }

echo "== step 2: a job with a secret, dispatched through the real helper with the value on stdin"
J=$(new_job "$MOD.use"); JOBS_STARTED="$JOBS_STARTED $J"
stdin_json | "$HELPER" --dispatch "$J" >"$WORK/dispatch.out" 2>&1 && pass "2a --dispatch with stdin exits 0" || fail "2a --dispatch with stdin exits 0: $(cat "$WORK/dispatch.out")"
wait_status "$J" running 15 && pass "2b the job is running" || fail "2b the job is running"
D="$SECRETS/$J"
[ "$(stat -c '%U:%G %a' "$D" 2>/dev/null)" = "root:root 700" ] && pass "2c the folder is root:root 0700 under /run" || fail "2c the folder is root:root 0700 under /run (got $(stat -c '%U:%G %a' "$D" 2>/dev/null))"
[ "$(stat -c '%U:%G %a' "$D/dns-token" 2>/dev/null)" = "root:root 400" ] && pass "2d the file is root:root 0400" || fail "2d the file is root:root 0400"
check "2e the extra name was dropped" test ! -e "$D/extra"
[ "$(cat "$D/dns-token" 2>/dev/null)" = "$VALUE" ] && pass "2f the file holds the value" || fail "2f the file holds the value"
[ "$(findmnt -n -o FSTYPE -T "$D" 2>/dev/null)" = "tmpfs" ] && pass "2g the folder is on tmpfs" || fail "2g the folder is on tmpfs"
if ps -eo args | grep -F -- "$VALUE" | grep -v grep >/dev/null; then fail "2h the value is not in ps"; else pass "2h the value is not in ps"; fi
LEAK=0
for pid in $(pgrep -f "tec-tac-server-maintenance|use.sh|sleep 6"); do
  if tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -F -- "$VALUE" >/dev/null; then LEAK=1; fi
  if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -F -- "$VALUE" >/dev/null; then LEAK=1; fi
done
[ "$LEAK" -eq 0 ] && pass "2i the value is not in /proc/<pid>/environ or cmdline of the helper or the program" || fail "2i the value is not in /proc/<pid>/environ or cmdline of the helper or the program"
CPID=$(pgrep -f "$ACT/$MOD" | head -1)
[ -n "$CPID" ] && tr '\0' '\n' < "/proc/$CPID/environ" 2>/dev/null | grep -q "^TEC_TAC_SERVER_MAINTENANCE_SECRET_DIR=$D\$" && pass "2j the program's environment holds only the folder path" || fail "2j the program's environment holds only the folder path"
if grep -F -- "$VALUE" "$STATE/jobs/$J.json" "$STATE/running/$J/job.json" "$STATE/audit.jsonl" >/dev/null 2>&1; then fail "2k the value is not in the job files or the helper audit file"; else pass "2k the value is not in the job files or the helper audit file"; fi
wait_status "$J" succeeded 30 && pass "2l the job succeeded" || fail "2l the job succeeded"
grep -q "length=${#VALUE}" "$STATE/logs/$J.stdout.log" && pass "2m the program read the whole value" || fail "2m the program read the whole value"
check "2n the folder is gone after the job" test ! -e "$D"
if grep -F -- "$VALUE" "$STATE/logs/$J.stdout.log" "$STATE/logs/$J.stderr.log" "$STATE/logs/$J.log" >/dev/null 2>&1; then fail "2o the value was scrubbed from the three logs"; else pass "2o the value was scrubbed from the three logs"; fi
grep -q "oops \*\*\*" "$STATE/logs/$J.stdout.log" && pass "2p stdout shows *** where the program echoed the value" || fail "2p stdout shows *** where the program echoed the value"
if journalctl -u "tec-tac-server-maintenance-$J" --no-pager 2>/dev/null | grep -F -- "$VALUE" >/dev/null; then fail "2q the value is not in the journal"; else pass "2q the value is not in the journal"; fi
if journalctl -t sudo -t tec-tac-server-maintenance --since "-10 min" --no-pager 2>/dev/null | grep -F -- "$VALUE" >/dev/null; then fail "2r the value is not in sudo or helper journal lines"; else pass "2r the value is not in sudo or helper journal lines"; fi

echo "== step 3: a required secret that is not sent, an action without secrets"
M=$(new_job "$MOD.use"); JOBS_STARTED="$JOBS_STARTED $M"
echo '{"api-key": "b3B0aW9uYWw="}' | "$HELPER" --dispatch "$M" >/dev/null 2>&1 && fail "3a a missing required secret fails the dispatch" || pass "3a a missing required secret fails the dispatch"
[ "$(jstatus "$M" status)" = "failed" ] && python3 -c "import json; assert json.load(open('$STATE/jobs/$M.json'))['failure']['classification']=='secret_missing'" && pass "3b the job failed with secret_missing" || fail "3b the job failed with secret_missing"
check "3c no folder was left" test ! -e "$SECRETS/$M"
P=$(new_job "$MOD.plain"); JOBS_STARTED="$JOBS_STARTED $P"
stdin_json | "$HELPER" --dispatch "$P" >/dev/null 2>&1
check "3d an action without secret_inputs gets no folder, whatever the job file says" test ! -e "$SECRETS/$P"
wait_status "$P" failed 30 && pass "3e it ran without the variable (the program found no file)" || fail "3e it ran without the variable"

echo "== step 4: cancel removes the folder; a leftover folder is swept; reboot safety"
C=$(new_job "$MOD.use"); JOBS_STARTED="$JOBS_STARTED $C"
stdin_json | "$HELPER" --dispatch "$C" >/dev/null 2>&1; wait_status "$C" running 15
check "4a the folder exists while the job runs" test -d "$SECRETS/$C"
"$HELPER" --cancel "$C" >/dev/null 2>&1
check "4b the folder is gone after cancel" test ! -e "$SECRETS/$C"
if grep -F -- "$VALUE" "$STATE/logs/$C.stdout.log" "$STATE/logs/$C.stderr.log" "$STATE/logs/$C.log" >/dev/null 2>&1; then fail "4c the logs of a cancelled job carry no value"; else pass "4c the logs of a cancelled job carry no value"; fi
G=$(python3 -c "import uuid; print(uuid.uuid4())")
mkdir -p "$SECRETS/$G"; chmod 700 "$SECRETS/$G"; echo leftover > "$SECRETS/$G/dns-token"
mkdir -p "$SECRETS/not-a-job"
N=$(new_job "$MOD.plain"); JOBS_STARTED="$JOBS_STARTED $N"; "$HELPER" --dispatch "$N" >/dev/null 2>&1   # any helper call runs the sweep
check "4d the folder of an unknown job was swept" test ! -e "$SECRETS/$G"
check "4e a folder that is not a job id was swept" test ! -e "$SECRETS/not-a-job"
[ "$(findmnt -n -o FSTYPE -T "$SECRETS" 2>/dev/null)" = "tmpfs" ] && pass "4f the secrets root is on tmpfs, so a reboot clears it" || fail "4f the secrets root is on tmpfs"

echo
if [ "$FAILS" -eq 0 ]; then echo "ALL PASS"; else echo "$FAILS step(s) FAILED"; exit 1; fi

#!/usr/bin/env bash
# Runtime check for Core 1.17.112: an action that waits for a person does not hold the global server-maintenance lock, with the real helper.
# It did NOT run on the development PC (it needs root, systemd, real flock and a Linux server). DEV SERVER ONLY, as root.
#
#   sudo bash tests/server-maintenance-waits-runtime-1.17.112.sh
#
# It uses a throw-away module id, smwait, and cleans up after itself. Run it when no module install, upgrade or Core update is running
# and no other server-maintenance job is queued: the check needs the global lock to be free at the start. It prints PASS or FAIL for
# each step and exits 1 when any step fails. The whole run takes about one minute.
#
# What to send back after a FAIL: the whole output of the script, plus the last 30 lines of /var/lib/tec-tac/server-maintenance/audit.jsonl.
set -u

HELPER=/usr/local/sbin/tec-tac-server-maintenance
STATE=${TEC_TAC_SM_STATE:-/var/lib/tec-tac/server-maintenance}
REG=${TEC_TAC_SM_REGISTRY:-/etc/tec-tac/server-maintenance/actions.d}
ACT=${TEC_TAC_SM_ACTIONS:-/usr/local/lib/tec-tac/server-maintenance/actions}
EXT=${TEC_TAC_EXTENSIONS_ROOT:-/opt/tec-tac/extensions}
MOD=smwait
WORK=$(mktemp -d /root/smwait-check.XXXXXX)
FAILS=0
JOBS_STARTED=""

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }

cleanup() {
  for id in $JOBS_STARTED; do systemctl stop "tec-tac-server-maintenance-$id" >/dev/null 2>&1; done
  "$HELPER" --unregister-module "$MOD" >/dev/null 2>&1
  for id in $JOBS_STARTED; do
    rm -rf "${STATE:?}/running/${id:?}" "${STATE:?}/jobs/${id:?}.json" "${STATE:?}/logs/${id:?}".*
  done
  rm -rf "${EXT:?}/${MOD:?}" "${ACT:?}/${MOD:?}" "${WORK:?}"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "FAIL this script must run as root"; exit 1; fi
[ -x "$HELPER" ] || { echo "FAIL the root helper is missing at $HELPER"; exit 1; }
grep -q 'waits_for_person' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.112: it has no waits_for_person"; exit 1; }

echo "== step 1: install the throw-away module"
mkdir -p "$EXT/$MOD/server_maintenance/actions"
# waits 8 seconds (the person), then takes the global lock itself for one second, as a real action must
cat > "$EXT/$MOD/server_maintenance/actions/wait.sh" <<'PROG'
#!/bin/bash
echo "lockvar=$TEC_TAC_SERVER_MAINTENANCE_LOCK"
sleep 8
exec 9>>"$TEC_TAC_SERVER_MAINTENANCE_LOCK"
flock -x 9
date +%s > "$TEC_TAC_SM_CHECK_MARK"
sleep 1
PROG
cat > "$EXT/$MOD/server_maintenance/actions/quick.sh" <<'PROG'
#!/bin/bash
echo "lockvar=${TEC_TAC_SERVER_MAINTENANCE_LOCK:-unset}"
sleep 1
PROG
cat > "$EXT/$MOD/tec_tac.json" <<JSON
{"id": "$MOD", "type": "extension", "version": "0.1.0", "category": "server",
 "publisher_permissions": ["server_maintenance.register"],
 "permission_groups": {"Probe": ["$MOD.run"]},
 "server_maintenance_actions": [
   {"id": "$MOD.wait", "permission": "$MOD.run", "executable": "server_maintenance/actions/wait.sh", "timeout_seconds": 120, "waits_for_person": true},
   {"id": "$MOD.quick", "permission": "$MOD.run", "executable": "server_maintenance/actions/quick.sh", "timeout_seconds": 60}]}
JSON
# the program writes its mark to a fixed path (the systemd unit has no variable for it)
sed -i "s#\$TEC_TAC_SM_CHECK_MARK#$WORK/locked.mark#" "$EXT/$MOD/server_maintenance/actions/wait.sh"
chown -R root:root "$EXT/$MOD"; chmod -R go-w "$EXT/$MOD"; chmod 755 "$EXT/$MOD/server_maintenance/actions/"*.sh
if "$HELPER" --register-module "$MOD" >"$WORK/register.out" 2>&1; then pass "1a --register-module accepts waits_for_person"; else fail "1a --register-module accepts waits_for_person: $(cat "$WORK/register.out")"; exit 1; fi
python3 - "$REG/$MOD.wait.json" "$REG/$MOD.quick.json" <<'PY' && pass "1b the registry carries waits_for_person true and false" || fail "1b the registry carries waits_for_person"
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
assert a["waits_for_person"] is True and b["waits_for_person"] is False, (a, b)
PY

new_job() { # new_job <action id>
  python3 - "$STATE" "$1" <<'PY'
import json, sys, uuid
state, action = sys.argv[1:3]
jid = str(uuid.uuid4())
job = {"schema": 1, "id": jid, "action": action, "action_revision": "1", "action_permission": "smwait.run", "owner_module": "smwait", "status": "queued", "stage": "queued",
       "created_at": "2026-11-10T00:00:00+00:00", "started_at": None, "finished_at": None, "cancel_requested_at": None,
       "context": {"source_module": "smwait", "source_action": "smwait.run", "requested_by": "runtime-check"}, "parameters": {}, "public_parameters": {},
       "lock": {"scope": "global", "state": "pending", "acquired_at": None}, "exit_result": None, "failure": None}
open(f"{state}/jobs/{jid}.json", "w").write(json.dumps(job))
print(jid)
PY
}
jfield() { python3 -c "import json,sys; d=json.load(open('$STATE/jobs/$1.json')); print(d.get(sys.argv[1]) if len(sys.argv) < 3 else (d.get(sys.argv[1]) or {}).get(sys.argv[2], ''))" "${@:2}"; }
wait_status() { for _ in $(seq 1 "$3"); do [ "$(jfield "$1" status)" = "$2" ] && return 0; sleep 1; done; return 1; }

echo "== step 2: a waiting job runs at once and does not hold the lock; an ordinary job finishes meanwhile"
W=$(new_job "$MOD.wait"); JOBS_STARTED="$JOBS_STARTED $W"
"$HELPER" --dispatch "$W" >/dev/null 2>&1
wait_status "$W" running 6 && pass "2a the waiting job is running within 6 seconds" || fail "2a the waiting job is running within 6 seconds (status $(jfield "$W" status))"
[ "$(jfield "$W" lock state)" = "program_managed" ] && pass "2b its lock state is program_managed" || fail "2b its lock state is program_managed (got $(jfield "$W" lock state))"
Q=$(new_job "$MOD.quick"); JOBS_STARTED="$JOBS_STARTED $Q"
"$HELPER" --dispatch "$Q" >/dev/null 2>&1
if wait_status "$Q" succeeded 6; then pass "2c an ordinary job finished while the waiting job was still waiting"; else fail "2c an ordinary job finished while the waiting job was still waiting (status $(jfield "$Q" status))"; fi
[ "$(jfield "$W" status)" = "running" ] && pass "2d the waiting job was still running then" || fail "2d the waiting job was still running then"
grep -q "lockvar=unset" "$STATE/logs/$Q.stdout.log" && pass "2e an ordinary child gets no lock variable" || fail "2e an ordinary child gets no lock variable"
grep -q "lockvar=$STATE/server-maintenance.lock" "$STATE/logs/$W.stdout.log" && pass "2f the waiting child got TEC_TAC_SERVER_MAINTENANCE_LOCK" || fail "2f the waiting child got TEC_TAC_SERVER_MAINTENANCE_LOCK"

echo "== step 3: the waiting job takes the lock itself, and ends released"
wait_status "$W" succeeded 30 && pass "3a the waiting job succeeded" || fail "3a the waiting job succeeded (status $(jfield "$W" status))"
check "3b its program took the lock and wrote its mark" test -s "$WORK/locked.mark"
[ "$(jfield "$W" lock state)" = "released" ] && pass "3c its lock state ends released" || fail "3c its lock state ends released (got $(jfield "$W" lock state))"

echo "== step 4: while another job holds the lock the waiting job still starts, and its program waits for the lock"
rm -f "${WORK:?}/locked.mark"
( exec 8>>"$STATE/server-maintenance.lock"; flock -x 8; sleep 14 ) &
HOLDER=$!
sleep 1
W2=$(new_job "$MOD.wait"); JOBS_STARTED="$JOBS_STARTED $W2"
"$HELPER" --dispatch "$W2" >/dev/null 2>&1
wait_status "$W2" running 6 && pass "4a it is running although the lock is held elsewhere" || fail "4a it is running although the lock is held elsewhere"
sleep 9
check "4b its program has not taken the lock yet (it is still held)" test ! -e "$WORK/locked.mark"
wait "$HOLDER"
wait_status "$W2" succeeded 30 && pass "4c once the lock is free the program takes it and the job succeeds" || fail "4c once the lock is free the program takes it and the job succeeds"
check "4d the mark was written after the lock was released" test -s "$WORK/locked.mark"

echo
if [ "$FAILS" -eq 0 ]; then echo "ALL PASS"; else echo "$FAILS step(s) FAILED"; exit 1; fi

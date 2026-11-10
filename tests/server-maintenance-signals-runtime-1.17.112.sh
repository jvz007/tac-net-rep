#!/usr/bin/env bash
# Runtime check for Core 1.17.112: the per-job input channel of core.server_maintenance (--signal), with the real root helper.
# It did NOT run on the development PC (it needs root, systemd and a Linux server). DEV SERVER ONLY, as root, after install.sh ran again
# (it adds the signal-requests folder and the `--signal *` sudoers line).
#
#   sudo bash tests/server-maintenance-signals-runtime-1.17.112.sh
#
# It uses a throw-away module id, smsig, and cleans up after itself. Run it when no module install, upgrade or Core update is running.
# It prints PASS or FAIL for each step and exits 1 when any step fails.
#
# What to send back after a FAIL: the whole output of the script, plus `ls -ld /var/lib/tec-tac/server-maintenance/signal-requests`,
# `cat /etc/sudoers.d/tec-tac-server-maintenance` and the last 30 lines of /var/lib/tec-tac/server-maintenance/audit.jsonl.
set -u

HELPER=/usr/local/sbin/tec-tac-server-maintenance
STATE=${TEC_TAC_SM_STATE:-/var/lib/tec-tac/server-maintenance}
REG=${TEC_TAC_SM_REGISTRY:-/etc/tec-tac/server-maintenance/actions.d}
ACT=${TEC_TAC_SM_ACTIONS:-/usr/local/lib/tec-tac/server-maintenance/actions}
EXT=${TEC_TAC_EXTENSIONS_ROOT:-/opt/tec-tac/extensions}
SUDOERS=/etc/sudoers.d/tec-tac-server-maintenance
MOD=smsig
WORK=$(mktemp -d /root/smsig-check.XXXXXX)
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
    rm -f "${STATE:?}/signal-requests/${id:?}".*
  done
  rm -rf "${EXT:?}/${MOD:?}" "${ACT:?}/${MOD:?}" "${WORK:?}"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "FAIL this script must run as root"; exit 1; fi
[ -x "$HELPER" ] || { echo "FAIL the root helper is missing at $HELPER"; exit 1; }
grep -q -- '--signal' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.112: it has no --signal"; exit 1; }

echo "== step 0: the install layout"
check "0a sudoers allows --signal" grep -Fq -- '--signal *' "$SUDOERS"
check "0b sudoers still allows --dispatch and --cancel" grep -Fq -- '--cancel *' "$SUDOERS"
[ -d "$STATE/signal-requests" ] && pass "0c signal-requests exists" || fail "0c signal-requests exists (run install.sh again)"
[ "$(stat -c '%U %a' "$STATE/signal-requests" 2>/dev/null)" = "root 2770" ] && pass "0d signal-requests is root, 2770" || fail "0d signal-requests is root, 2770 (got $(stat -c '%U %a' "$STATE/signal-requests" 2>/dev/null))"
[ "$(stat -c '%U:%G %a' "$STATE/running")" = "root:root 700" ] && pass "0e running is root:root 700 (the signals folders sit below it)" || fail "0e running is root:root 700"

echo "== step 1: install the throw-away module with an action that lists signals and polls for one"
mkdir -p "$EXT/$MOD/server_maintenance/actions"
cat > "$EXT/$MOD/server_maintenance/actions/poll.sh" <<'PROG'
#!/bin/bash
# waits up to 90 seconds for the signal file, then records what it saw and exits 0
echo "job=$TEC_TAC_SERVER_MAINTENANCE_JOB_ID dir=$TEC_TAC_SERVER_MAINTENANCE_SIGNAL_DIR"
for i in $(seq 1 90); do
  if [ -f "$TEC_TAC_SERVER_MAINTENANCE_SIGNAL_DIR/continue" ]; then echo "got continue"; cat "$TEC_TAC_SERVER_MAINTENANCE_SIGNAL_DIR/continue"; exit 0; fi
  sleep 1
done
echo "no signal"; exit 3
PROG
cat > "$EXT/$MOD/tec_tac.json" <<JSON
{"id": "$MOD", "type": "extension", "version": "0.1.0", "category": "server",
 "publisher_permissions": ["server_maintenance.register"],
 "permission_groups": {"Probe": ["$MOD.run"]},
 "server_maintenance_actions": [
   {"id": "$MOD.poll", "permission": "$MOD.run", "executable": "server_maintenance/actions/poll.sh", "timeout_seconds": 120, "signals": ["continue"]},
   {"id": "$MOD.plain", "permission": "$MOD.run", "executable": "server_maintenance/actions/poll.sh", "timeout_seconds": 120}]}
JSON
chown -R root:root "$EXT/$MOD"; chmod -R go-w "$EXT/$MOD"; chmod 755 "$EXT/$MOD/server_maintenance/actions/poll.sh"
if "$HELPER" --register-module "$MOD" >"$WORK/register.out" 2>&1; then pass "1a --register-module accepts signals"; else fail "1a --register-module accepts signals: $(cat "$WORK/register.out")"; exit 1; fi
python3 - "$REG/$MOD.poll.json" "$REG/$MOD.plain.json" <<'PY' && pass "1b the registry carries signals ['continue'] and none" || fail "1b the registry carries signals"
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
assert a["signals"] == ["continue"] and a["waits_for_person"] is False, a
assert b["signals"] == [], b
PY

new_job() { # new_job <action id> -> prints the job id (written as Core writes it; the caller dispatches it through the real helper)
  python3 - "$STATE" "$1" <<'PY'
import json, sys, uuid
state, action = sys.argv[1:3]
jid = str(uuid.uuid4())
job = {"schema": 1, "id": jid, "action": action, "action_revision": "1", "action_permission": "smsig.run", "owner_module": "smsig", "status": "queued", "stage": "queued",
       "created_at": "2026-11-10T00:00:00+00:00", "started_at": None, "finished_at": None, "cancel_requested_at": None,
       "context": {"source_module": "smsig", "source_action": "smsig.run", "requested_by": "runtime-check"}, "parameters": {}, "public_parameters": {},
       "lock": {"scope": "global", "state": "pending", "acquired_at": None}, "exit_result": None, "failure": None, "action_signals": ["continue", "abort"], "signals": []}
open(f"{state}/jobs/{jid}.json", "w").write(json.dumps(job))
print(jid)
PY
}
jstatus() { python3 -c "import json,sys; print(json.load(open('$STATE/jobs/$1.json')).get(sys.argv[1], ''))" "$2"; }
wait_status() { # wait_status <job> <status> <seconds>
  for _ in $(seq 1 "$3"); do [ "$(jstatus "$1" status)" = "$2" ] && return 0; sleep 1; done; return 1
}
request() { # request <job> <name>  (as Core writes it)
  printf '{"job_id": "%s", "name": "%s", "requested_at": "2026-11-10T00:00:00+00:00", "context": {"source_module": "smsig", "source_action": "smsig.run", "requested_by": "runtime-check"}}' "$1" "$2" > "$STATE/signal-requests/$1.$2.json"
}

echo "== step 2: a running job receives continue"
J=$(new_job "$MOD.poll"); JOBS_STARTED="$JOBS_STARTED $J"
"$HELPER" --dispatch "$J" >/dev/null 2>&1; wait_status "$J" running 15 && pass "2a the job is running" || fail "2a the job is running"
SD="$STATE/running/$J/signals"
[ "$(stat -c '%U %a' "$SD" 2>/dev/null)" = "root 700" ] && pass "2b the signals folder exists and is root-only 0700" || fail "2b the signals folder exists and is root-only 0700"
request "$J" abort
"$HELPER" --signal "$J" >/dev/null 2>&1
check "2c abort is refused (the root registry lists only continue)" test ! -e "$SD/abort"
check "2d the abort request file is removed" test ! -e "$STATE/signal-requests/$J.abort.json"
request "$J" continue
if "$HELPER" --signal "$J" >"$WORK/sig.out" 2>&1; then pass "2e --signal continue exits 0"; else fail "2e --signal continue exits 0: $(cat "$WORK/sig.out")"; fi
[ "$(stat -c '%U %a' "$SD/continue" 2>/dev/null)" = "root 600" ] && pass "2f the signal file is root, 0600" || fail "2f the signal file is root, 0600"
[ "$(stat -c '%s' "$SD/continue" 2>/dev/null || echo 9999)" -le 512 ] && pass "2g it is at most 512 bytes" || fail "2g it is at most 512 bytes"
check "2h the request file is removed" test ! -e "$STATE/signal-requests/$J.continue.json"
wait_status "$J" succeeded 20 && pass "2i the program saw it and the job succeeded" || fail "2i the program saw it and the job succeeded"
grep -q "got continue" "$STATE/logs/$J.stdout.log" && pass "2j the program read the signal" || fail "2j the program read the signal"
grep -q "dir=$SD" "$STATE/logs/$J.stdout.log" && pass "2k the program got TEC_TAC_SERVER_MAINTENANCE_SIGNAL_DIR" || fail "2k the program got the signal folder variable"
[ "$(python3 -c "import json; print([s['name'] for s in json.load(open('$STATE/jobs/$J.json'))['signals']])")" = "['continue']" ] && pass "2l the mirror records signals" || fail "2l the mirror records signals"

echo "== step 3: a finished job, an action without signals"
request "$J" continue
if "$HELPER" --signal "$J" >/dev/null 2>&1; then fail "3a a finished job is refused"; else pass "3a a finished job is refused"; fi
rm -f "${STATE:?}/signal-requests/${J:?}".continue.json
P=$(new_job "$MOD.plain"); JOBS_STARTED="$JOBS_STARTED $P"
"$HELPER" --dispatch "$P" >/dev/null 2>&1; wait_status "$P" running 15
request "$P" continue
"$HELPER" --signal "$P" >/dev/null 2>&1
check "3b an action with no signals gets no signal file, whatever the job file says" test ! -e "$STATE/running/$P/signals/continue"
sleep 2
if grep -q 'dir=/' "$STATE/logs/$P.stdout.log"; then fail "3c an action with no signals gets no signal folder variables"; else pass "3c an action with no signals gets no signal folder variables"; fi
systemctl stop "tec-tac-server-maintenance-$P" >/dev/null 2>&1

echo "== step 4: a symlink and a FIFO are refused, the second send is a no-op"
J2=$(new_job "$MOD.poll"); JOBS_STARTED="$JOBS_STARTED $J2"
"$HELPER" --dispatch "$J2" >/dev/null 2>&1; wait_status "$J2" running 15
SD2="$STATE/running/$J2/signals"
ln -s /etc/passwd "$STATE/signal-requests/$J2.continue.json"
timeout 15 "$HELPER" --signal "$J2" >/dev/null 2>&1
if [ -e "$STATE/signal-requests/$J2.continue.json" ] || [ -L "$STATE/signal-requests/$J2.continue.json" ]; then fail "4a a symlink request is refused and removed"; else pass "4a a symlink request is refused and removed"; fi
check "4b it created no signal" test ! -e "$SD2/continue"
mkfifo "$STATE/signal-requests/$J2.continue.json"
timeout 15 "$HELPER" --signal "$J2" >/dev/null 2>&1; rc=$?
[ "$rc" -ne 124 ] && pass "4c a FIFO request does not hang the helper" || fail "4c a FIFO request does not hang the helper (timed out)"
if [ -e "$STATE/signal-requests/$J2.continue.json" ]; then fail "4d the FIFO is removed"; else pass "4d the FIFO is removed"; fi
request "$J2" continue; "$HELPER" --signal "$J2" >/dev/null 2>&1
sum1=$(sha256sum "$SD2/continue" 2>/dev/null | cut -d' ' -f1)
request "$J2" continue; "$HELPER" --signal "$J2" >/dev/null 2>&1
sum2=$(sha256sum "$SD2/continue" 2>/dev/null | cut -d' ' -f1)
[ -n "$sum1" ] && [ "$sum1" = "$sum2" ] && pass "4e the second send did not overwrite" || fail "4e the second send did not overwrite"
wait_status "$J2" succeeded 20 && pass "4f the job still finished" || fail "4f the job still finished"

echo
if [ "$FAILS" -eq 0 ]; then echo "ALL PASS"; else echo "$FAILS step(s) FAILED"; exit 1; fi

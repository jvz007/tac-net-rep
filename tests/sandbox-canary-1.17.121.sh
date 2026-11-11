#!/usr/bin/env bash
# Runtime check for Core 1.17.121: core.sandbox Patch 2, the full canary (attack test), with the real root helper, systemd and cgroups.
# 1.17.121 changes from the 1.17.120 script: the helper guard also needs the credential pre-check (MISSING / _credential_file_ready); step 4 gains
# check 4d: the row 'another dynamic user reads the credential file' must end with OK (not NOT RUN, not ATTACK SUCCEEDED). Everything else is as in 1.17.120.
# 1.17.120 changes from the 1.17.118 script: the helper guard also needs the numeric address list; step 2 prints the DNS detail, the upstream
# resolvers and the bpf_framework row as information; step 2c proves the helper's own '$' escape against real systemd and prints how '%' arrives;
# step 4 also needs the row "another dynamic user reads the credential file". The kill switch stays OFF and is never touched here.
# It did NOT run on the development PC (it needs root, systemd, cgroup v2 and a Linux server). DEV SERVER ONLY, as root, after Core 1.17.121
# is installed. The kill switch is still OFF: this script proves it stays off and then runs the canary through the root-only path.
#
#   sudo bash tests/sandbox-canary-1.17.121.sh
#
# It runs about 3 to 6 minutes (the latency step starts 50 runs, the cancel step waits on units). Run it when no module install, upgrade
# or Core update is running. It prints PASS or FAIL for each step and ends with ALL CANARY STEPS PASSED, or the number of steps that
# failed (exit 1). The attack table is printed in full: send ALL of it back, passed or not.
#
# What to send back after a FAIL: the whole output of this script, plus `sudo /usr/local/sbin/tec-tac-sandbox --status`,
# `cat /var/lib/tec-tac/sandbox/canary.json`, `cat /var/lib/tec-tac/sandbox/status.json`, `systemctl --version`, `uname -r`,
# `cat /etc/os-release`, `cat /etc/resolv.conf` and the last 40 lines of /var/lib/tec-tac/sandbox/audit.jsonl.
# A row that says ATTACK SUCCEEDED is a real hole: do not turn the sandbox on, send the row. A row that says NOT RUN means a probe could
# not run (read its text); it fails the canary too. SKIPPED (for example no public route) is shown, never counted as a pass.
# Nothing here holds a real secret: the canary uses random dummy tokens that exist only for the run.
set -u

HELPER=/usr/local/sbin/tec-tac-sandbox
STATE=/var/lib/tec-tac/sandbox
LIB=/usr/local/lib/tec-tac/sandbox
RUN=/run/tec-tac/sandbox
FAILS=0

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); k=sys.argv[1].split(".");
for p in k: d=d[p]
print(d)' "$1" 2>/dev/null; }

if [ "$(id -u)" -ne 0 ]; then echo "FAIL this script must run as root"; exit 1; fi
[ -x "$HELPER" ] || { echo "FAIL the root helper is missing at $HELPER (is Core 1.17.121 installed?)"; exit 1; }
grep -q 'SANDBOX_ENABLED = False' "$HELPER" || { echo "FAIL the installed helper has no off kill switch constant (is it Core 1.17.121?)"; exit 1; }
grep -q -- '--canary' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.118 (no --canary)"; exit 1; }
grep -q '127.0.0.0/8' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.120 (its address filter is not the numeric list)"; exit 1; }
grep -q '_credential_file_ready' "$HELPER" && grep -q 'MISSING' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.121 (no credential file pre-check)"; exit 1; }
TACTICAL_USER=$(systemctl show rmm.service -p User --value 2>/dev/null)
[ -n "$TACTICAL_USER" ] || { echo "FAIL could not find the Tactical service user"; exit 1; }

echo "== step 1: what is installed"
echo "systemd: $(systemctl --version | head -1)"
echo "kernel:  $(uname -r)"
echo "os:      $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "resolv:  $(grep -E '^nameserver' /etc/resolv.conf | tr '\n' ' ')"
[ "$(stat -c '%U %a' "$LIB/sandbox-launcher.py" 2>/dev/null)" = "root 755" ] && pass "1a the launcher is root-owned 0755" || fail "1a the launcher is root-owned 0755 ($(stat -c '%U %a' "$LIB/sandbox-launcher.py" 2>&1))"
[ "$(stat -c '%U %a' "$LIB/canary/sandbox-canary-runner.py" 2>/dev/null)" = "root 755" ] && pass "1b the canary runner is root-owned 0755" || fail "1b the canary runner is root-owned 0755"
[ "$(stat -c '%U %a' "$LIB/canary" 2>/dev/null)" = "root 755" ] && pass "1c the canary folder is root-owned 0755" || fail "1c the canary folder is root-owned 0755"
for folder in slots secrets handoff runs; do
  [ "$(stat -c '%U %a' "$RUN/$folder" 2>/dev/null)" = "root 700" ] && pass "1d $RUN/$folder is root 0700" || echo "NOTE $RUN/$folder is created at the first run ($(stat -c '%U %a' "$RUN/$folder" 2>&1))"
done

echo "== step 2: the selftest again (it now has the pipe_streams row and slots_total)"
SELFTEST_OUT=$(mktemp)
timeout 300 "$HELPER" --selftest >"$SELFTEST_OUT" 2>&1
SELFTEST_RC=$?
python3 - "$SELFTEST_OUT" <<'PY'
import json, sys
text = open(sys.argv[1], encoding="utf-8").read().strip().splitlines()
try:
    data = json.loads(text[-1])
except Exception:
    print("could not read the selftest output:")
    print("\n".join(text[-20:]))
    raise SystemExit(0)
print("%-26s %-5s %s" % ("check", "ok", "detail"))
for name, row in data.get("checks", {}).items():
    print("%-26s %-5s %s" % (name, "yes" if row.get("ok") else "NO", row.get("detail", "")))
print("ready=%s reason=%s resolver=%s slots_total=%s" % (data.get("ready"), data.get("reason"), data.get("resolver"), data.get("slots_total")))
PY
rm -f "$SELFTEST_OUT"
echo "information: the upstream resolvers systemd-resolved forwards to (/run/systemd/resolve/resolv.conf, read only):"
cat /run/systemd/resolve/resolv.conf 2>&1 | grep -E '^(nameserver|search|options)' || echo "  (not readable or none listed)"
echo "information: the dns and bpf_framework rows of the selftest table are printed above; send them back as they are."
[ "$SELFTEST_RC" -eq 0 ] && pass "2a selftest ready (incl. pipe_streams)" || fail "2a selftest ready (exit $SELFTEST_RC: read the table above)"
[ "$(jget slots_total < "$STATE/status.json")" -ge 1 ] 2>/dev/null && pass "2b status.json carries slots_total" || fail "2b status.json carries slots_total"

echo "== step 2c: the helper's own '\$' escape against real systemd (a wrong escape fails the canary)"
ESC_FILE=$(mktemp)
python3 - "$HELPER" >"$ESC_FILE" <<'PY'
import importlib.machinery
import importlib.util
import sys
loader = importlib.machinery.SourceFileLoader("tec_tac_sandbox_helper", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
for word in ("plain", "a$HOME b${X} $$", "$$", "$1x"):
    print(module._exec_escape(word))
PY
WORDS=('plain' 'a$HOME b${X} $$' '$$' '$1x')
mapfile -t ESC <"$ESC_FILE"
rm -f "$ESC_FILE"
# the words travel to a small python program, so no printf format (and no '%') is needed to print them
PRINT_WORDS='import sys;print(*sys.argv[1:],sep=chr(10))'
if [ "${#ESC[@]}" -ne "${#WORDS[@]}" ]; then
  fail "2c the helper's _exec_escape gave ${#ESC[@]} words, not ${#WORDS[@]}"
else
  mapfile -t GOT < <(systemd-run --pipe --wait --collect --quiet -p DynamicUser=yes -- /usr/bin/python3 -I -c "$PRINT_WORDS" "${ESC[@]}" 2>&1)
  for i in "${!WORDS[@]}"; do
    if [ "${GOT[$i]-}" = "${WORDS[$i]}" ]; then pass "2c word $((i + 1)) arrives unchanged"; else fail "2c word $((i + 1)) arrived as '${GOT[$i]-}', not '${WORDS[$i]}'"; fi
  done
fi
echo "information (neither pass nor fail): does systemd expand an unescaped '\$' word?"
CONTROL=$(systemd-run --pipe --wait --collect --quiet -p DynamicUser=yes -E TECTAC_X=probe -- /usr/bin/python3 -I -c "$PRINT_WORDS" '$TECTAC_X' 2>&1)
if [ "$CONTROL" = "probe" ]; then echo "NOTE an unescaped \$TECTAC_X was expanded to 'probe': the escape is needed"; else echo "NOTE an unescaped \$TECTAC_X arrived as '$CONTROL' (not expanded here)"; fi
echo "information (Core 1.17.119 question 1; the helper refuses '%' from 1.17.120, so no pass or fail):"
for word in '%h' '%%h'; do
  GOT_PCT=$(systemd-run --pipe --wait --collect --quiet -p DynamicUser=yes -- /usr/bin/python3 -I -c "$PRINT_WORDS" "$word" 2>&1)
  echo "NOTE the unescaped word '$word' arrives as '$GOT_PCT'"
done

echo "== step 3: the kill switch is still off and the sudo rule did not change"
SUDO_LIST=$(sudo -l -U "$TACTICAL_USER" 2>&1)
SANDBOX_CMDS=$(echo "$SUDO_LIST" | grep 'tec-tac-sandbox' | tr ',' '\n' | grep -c 'tec-tac-sandbox')
[ "$SANDBOX_CMDS" -eq 3 ] && pass "3a exactly three sandbox commands for $TACTICAL_USER" || fail "3a exactly three sandbox commands (found $SANDBOX_CMDS)"
echo "$SUDO_LIST" | grep 'tec-tac-sandbox' | grep -Eq -- '--(register-module|unregister-module|selftest|canary|sweep|finish)' && fail "3b sudo shows a root-only mode" || pass "3b sudo shows no root-only mode"
START_OUT=$(echo "should-not-be-read" | runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --start 2>/dev/null); START_RC=$?
[ "$START_RC" -ne 0 ] && [ "$START_OUT" = '{"t":"refused","code":"sandbox_disabled"}' ] && pass "3c as $TACTICAL_USER, --start refuses with sandbox_disabled" || fail "3c --start refuses with sandbox_disabled (rc $START_RC, out '$START_OUT')"
runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --selftest --canary >/dev/null 2>&1 && fail "3d $TACTICAL_USER can reach --selftest --canary" || pass "3d $TACTICAL_USER cannot reach --selftest --canary"
runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --canary-launch </dev/null >/dev/null 2>&1 && fail "3e $TACTICAL_USER can reach --canary-launch" || pass "3e $TACTICAL_USER cannot reach --canary-launch"
runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --finish "$(printf 'a%.0s' $(seq 32))" >/dev/null 2>&1 && fail "3f $TACTICAL_USER can reach --finish" || pass "3f $TACTICAL_USER cannot reach --finish"

echo "== step 4: the canary (this is the attack test; it takes a few minutes)"
CANARY_OUT=$(mktemp)
timeout 900 "$HELPER" --selftest --canary >"$CANARY_OUT" 2>&1
CANARY_RC=$?
cat "$CANARY_OUT"
grep -q 'another dynamic user reads the credential file' "$CANARY_OUT" && pass "4c the table holds the row 'another dynamic user reads the credential file'" || fail "4c the table holds the row 'another dynamic user reads the credential file'"
grep -E 'another dynamic user reads the credential file' "$CANARY_OUT" | grep -Eq 'OK$' && pass "4d the row 'another dynamic user reads the credential file' ends with OK" || fail "4d the row 'another dynamic user reads the credential file' ends with OK (NOT RUN or ATTACK SUCCEEDED: read the row above)"
grep -q '^CANARY PASSED$' "$CANARY_OUT" && pass "4a the verdict line says CANARY PASSED" || fail "4a the verdict line says CANARY PASSED (exit $CANARY_RC; every ATTACK SUCCEEDED and NOT RUN row above is a finding)"
[ "$CANARY_RC" -eq 0 ] && pass "4b the canary exit code is 0" || fail "4b the canary exit code is 0 (it was $CANARY_RC)"
grep -c 'ATTACK SUCCEEDED' "$CANARY_OUT" | grep -qx '[0-9]*' && echo "rows with ATTACK SUCCEEDED in the table: $(awk '$0 ~ /ATTACK SUCCEEDED$/' "$CANARY_OUT" | wc -l)"
echo "SKIPPED rows (shown, never a pass): $(awk '$0 ~ /SKIPPED$/' "$CANARY_OUT" | wc -l)"
echo "WARN rows (latency target missed is a warning, not a failure): $(awk '$0 ~ /WARN$/' "$CANARY_OUT" | wc -l)"
rm -f "$CANARY_OUT"

echo "== step 5: what the canary left behind"
[ "$(stat -c '%U %a' "$STATE/canary.json" 2>/dev/null)" = "root 644" ] && pass "5a canary.json is root-owned 0644" || fail "5a canary.json is root-owned 0644"
[ "$(jget ok < "$STATE/canary.json")" = "True" ] && pass "5b canary.json says ok" || fail "5b canary.json says ok"
grep -Eq 'refreshed-|[0-9a-f]{32}' "$STATE/canary.json" && fail "5c canary.json holds a token-like text" || pass "5c canary.json holds no secret"
[ -z "$(ls -A "$RUN/secrets" 2>/dev/null)" ] && pass "5d $RUN/secrets is empty" || fail "5d $RUN/secrets is not empty: $(ls "$RUN/secrets")"
[ -z "$(ls -A "$RUN/handoff" 2>/dev/null)" ] && pass "5e $RUN/handoff is empty" || fail "5e $RUN/handoff is not empty"
[ -z "$(ls -A "$RUN/runs" 2>/dev/null)" ] && pass "5f $RUN/runs is empty" || fail "5f $RUN/runs is not empty"
[ -z "$(systemctl list-units 'tectac-sbx-*' --no-legend --all 2>/dev/null)" ] && pass "5g no tectac-sbx unit is left" || fail "5g a tectac-sbx unit is left: $(systemctl list-units 'tectac-sbx-*' --no-legend --all)"
[ -z "$(find / -xdev -name '.tectac-canary-*' 2>/dev/null | head -1)" ] && pass "5h no planted marker file is left on the server" || fail "5h a planted marker file is left: $(find / -xdev -name '.tectac-canary-*' 2>/dev/null | head -3)"
[ ! -e "$LIB/registry/core.canary.json" ] && pass "5i the canary record was never written to the registry" || fail "5i the canary record is in the registry"
grep -q '"event": "canary"' "$STATE/audit.jsonl" && pass "5j the helper's audit log has the canary row" || fail "5j the helper's audit log has the canary row"
STATUS_JSON=$(runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --status 2>/dev/null)
[ "$(echo "$STATUS_JSON" | jget status.canary_ok)" = "True" ] && pass "5k --status reports canary_ok true" || fail "5k --status reports canary_ok true"
[ "$(echo "$STATUS_JSON" | jget status.enabled)" = "False" ] && pass "5l --status still says enabled false" || fail "5l --status still says enabled false"
echo "slots: total=$(echo "$STATUS_JSON" | jget status.slots_total) used=$(echo "$STATUS_JSON" | jget status.slots_used)"
START_OUT=$(echo "x" | runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --start 2>/dev/null)
[ "$START_OUT" = '{"t":"refused","code":"sandbox_disabled"}' ] && pass "5m after the canary, --start still refuses with sandbox_disabled" || fail "5m after the canary, --start still refuses"

echo "== step 6: YOURS (not scripted)"
echo "   Say whether the Tactical web page and an agent check-in still work after the canary (it makes no change to either)."
echo "   Then send back the whole table from step 4. The sandbox stays OFF until the next patch flips the switch."

echo
if [ "$FAILS" -eq 0 ]; then echo "ALL CANARY STEPS PASSED"; exit 0; else echo "$FAILS STEP(S) FAILED"; exit 1; fi

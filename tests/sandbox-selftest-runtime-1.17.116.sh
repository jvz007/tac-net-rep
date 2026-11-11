#!/usr/bin/env bash
# Runtime check for Core 1.17.116: core.sandbox Patch 1 (the foundation), with the real root helper, systemd and cgroups.
# It did NOT run on the development PC (it needs root, systemd, cgroup v2 and a Linux server). DEV SERVER ONLY, as root, after Core 1.17.116
# is installed.
#
#   sudo bash tests/sandbox-selftest-runtime-1.17.116.sh
#
# It prints the selftest table, the systemd version (plan section 10 expects 249, 252 or 255), what `sudo -l` shows for the Tactical account,
# what status() says, and it registers and unregisters a throw-away runner (module id sbprobe) and leaves nothing behind. Run it when no
# module install, upgrade or Core update is running. It prints PASS or FAIL for each step and exits 1 when any step fails.
# Step 6 is yours: install and upgrade an unrelated module in the browser and say whether both worked.
#
# What to send back after a FAIL: the whole output of the script, plus `sudo /usr/local/sbin/tec-tac-sandbox --status`,
# `systemctl --version`, `uname -r`, `cat /etc/os-release` and the last 30 lines of /var/lib/tec-tac/sandbox/audit.jsonl.
# Nothing here holds a real secret. The probe credential is a dummy that is never written to a log.
set -u

HELPER=/usr/local/sbin/tec-tac-sandbox
STATE=/var/lib/tec-tac/sandbox
LIB=/usr/local/lib/tec-tac/sandbox
EXT=${TEC_TAC_EXTENSIONS_ROOT:-/opt/tec-tac/extensions}
TACTICAL_ROOT=${TACTICAL_ROOT:-/rmm}
MOD=sbprobe
PROBE_RUNTIME="$LIB/probe-runtime/$MOD"
FAILS=0

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); k=sys.argv[1].split(".");
for p in k: d=d[p]
print(d)' "$1" 2>/dev/null; }

cleanup() {
  "$HELPER" --unregister-module "$MOD" >/dev/null 2>&1
  rm -rf "${EXT:?}/${MOD:?}" "${LIB:?}/probe-runtime" "${LIB:?}/runners/${MOD:?}"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "FAIL this script must run as root"; exit 1; fi
[ -x "$HELPER" ] || { echo "FAIL the root helper is missing at $HELPER (is Core 1.17.116 installed?)"; exit 1; }
grep -q 'SANDBOX_ENABLED = False' "$HELPER" || { echo "FAIL the installed helper is not the Core 1.17.116 helper (no kill switch constant)"; exit 1; }
TACTICAL_USER=$(systemctl show rmm.service -p User --value 2>/dev/null)
[ -n "$TACTICAL_USER" ] || { echo "FAIL could not find the Tactical service user"; exit 1; }

echo "== step 1: the selftest, as root, and the real versions"
echo "systemd: $(systemctl --version | head -1)"
echo "kernel:  $(uname -r)"
echo "os:      $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "cgroup:  $(stat -fc %T /sys/fs/cgroup)"
echo "resolv:  $(grep -E '^nameserver' /etc/resolv.conf | tr '\n' ' ')"
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
print("ready=%s reason=%s systemd=%s address_filter_ok=%s dns_ok=%s resolver=%s enabled=%s" % (
    data.get("ready"), data.get("reason"), data.get("systemd_version"), data.get("address_filter_ok"), data.get("dns_ok"), data.get("resolver"), data.get("enabled")))
PY
rm -f "$SELFTEST_OUT"
[ "$SELFTEST_RC" -eq 0 ] && pass "1a selftest ready" || fail "1a selftest ready (exit $SELFTEST_RC: read the table above; a failed row names the wall that did not hold)"
VERSION_NUM=$(systemctl --version | head -1 | awk '{print $2}')
case "$VERSION_NUM" in 249|252|255) pass "1b systemd $VERSION_NUM is one of the versions plan section 10 expects (249, 252, 255)";; *) echo "NOTE systemd $VERSION_NUM is not one of 249, 252, 255: record it for the plan";; esac
[ "$(stat -c '%U %a' $STATE/status.json 2>/dev/null)" = "root 644" ] && pass "1c status.json is root-owned 0644" || fail "1c status.json is root-owned 0644 ($(stat -c '%U %a' $STATE/status.json 2>&1))"
[ -z "$(ls -A /run/tec-tac/sandbox 2>/dev/null)" ] && pass "1d no selftest folder is left in /run/tec-tac/sandbox" || fail "1d no selftest folder is left in /run/tec-tac/sandbox"

echo "== step 2: what sudo shows for $TACTICAL_USER"
SUDO_LIST=$(sudo -l -U "$TACTICAL_USER" 2>&1)
SANDBOX_LINES=$(echo "$SUDO_LIST" | grep -c 'tec-tac-sandbox')
echo "$SUDO_LIST" | grep 'tec-tac-sandbox'
SANDBOX_CMDS=$(echo "$SUDO_LIST" | grep 'tec-tac-sandbox' | tr ',' '\n' | grep -c 'tec-tac-sandbox')
[ "$SANDBOX_CMDS" -eq 3 ] && pass "2a exactly three sandbox commands" || fail "2a exactly three sandbox commands (found $SANDBOX_CMDS on $SANDBOX_LINES line(s))"
for flag in --start --stop --status; do
  echo "$SUDO_LIST" | grep 'tec-tac-sandbox' | grep -q -- "tec-tac-sandbox $flag" && pass "2b sudo allows $flag" || fail "2b sudo allows $flag"
done
echo "$SUDO_LIST" | grep 'tec-tac-sandbox' | grep -Eq -- '--(register-module|unregister-module|selftest|sweep|finish)' && fail "2c sudo shows a root-only mode" || pass "2c sudo shows no root-only mode"
echo "$SUDO_LIST" | grep 'tec-tac-sandbox' | grep -q '\*' && fail "2d a wildcard is in the sandbox rule" || pass "2d no wildcard in the sandbox rule"
check "2e as $TACTICAL_USER, sudo --status works" runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --status
STATUS_JSON=$(runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --status 2>/dev/null)
[ "$(echo "$STATUS_JSON" | jget status.ready)" = "True" ] && pass "2f --status says ready" || fail "2f --status says ready (reason: $(echo "$STATUS_JSON" | jget status.reason))"
[ "$(echo "$STATUS_JSON" | jget status.enabled)" = "False" ] && pass "2g --status says enabled false" || fail "2g --status says enabled false"
START_OUT=$(echo "should-not-be-read" | runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --start 2>/dev/null); START_RC=$?
[ "$START_RC" -ne 0 ] && [ "$START_OUT" = '{"t":"refused","code":"sandbox_disabled"}' ] && pass "2h as $TACTICAL_USER, --start refuses with sandbox_disabled" || fail "2h as $TACTICAL_USER, --start refuses with sandbox_disabled (rc $START_RC, out '$START_OUT')"
STOP_OUT=$(runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --stop 2>/dev/null); STOP_RC=$?
[ "$STOP_RC" -ne 0 ] && [ "$STOP_OUT" = '{"t":"refused","code":"sandbox_disabled"}' ] && pass "2i as $TACTICAL_USER, --stop refuses with sandbox_disabled" || fail "2i as $TACTICAL_USER, --stop refuses with sandbox_disabled"
runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --register-module "$MOD" >/dev/null 2>&1 && fail "2j $TACTICAL_USER can reach --register-module" || pass "2j $TACTICAL_USER cannot reach --register-module"
runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --selftest >/dev/null 2>&1 && fail "2k $TACTICAL_USER can reach --selftest" || pass "2k $TACTICAL_USER cannot reach --selftest"
runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --sweep >/dev/null 2>&1 && fail "2l $TACTICAL_USER can reach --sweep" || pass "2l $TACTICAL_USER cannot reach --sweep"

echo "== step 3: the layout, the slice and the sweep timer"
for path in "$LIB" "$LIB/runners" "$LIB/registry" "$STATE"; do
  [ "$(stat -c '%U %a' "$path" 2>/dev/null)" = "root 755" ] && pass "3a $path is root 0755" || fail "3a $path is root 0755 ($(stat -c '%U %a' "$path" 2>&1))"
done
[ -L "$HELPER" ] && [ "$(stat -c %U "$(readlink -f "$HELPER")")" = "root" ] && pass "3b the helper is a symlink to a root-owned file" || fail "3b the helper is a symlink to a root-owned file"
[ "$(stat -c %a /etc/sudoers.d/tec-tac-sandbox 2>/dev/null)" = "440" ] && pass "3c the sudoers file is 0440" || fail "3c the sudoers file is 0440"
visudo -cf /etc/sudoers.d/tec-tac-sandbox >/dev/null 2>&1 && pass "3d visudo accepts the sudoers file" || fail "3d visudo accepts the sudoers file"
systemctl is-enabled tec-tac-sandbox-sweep.timer >/dev/null 2>&1 && pass "3e the sweep timer is enabled" || fail "3e the sweep timer is enabled"
systemctl is-active tec-tac-sandbox-sweep.timer >/dev/null 2>&1 && pass "3f the sweep timer is active" || fail "3f the sweep timer is active"
echo "slice: MemoryMax=$(systemctl show tec-tac-sandbox.slice -p MemoryMax --value) TasksMax=$(systemctl show tec-tac-sandbox.slice -p TasksMax --value)"
[ "$(systemctl show tec-tac-sandbox.slice -p TasksMax --value)" = "2048" ] && pass "3g the slice drop-in is loaded (TasksMax 2048)" || fail "3g the slice drop-in is loaded (TasksMax 2048)"

echo "== step 4: status() from the Core side"
STATUS_PY=$(runuser -u "$TACTICAL_USER" -- bash -lc "cd '$TACTICAL_ROOT/api/tacticalrmm' && '$TACTICAL_ROOT/api/env/bin/python' manage.py shell -c \"from tec_tac.sandbox import status; import json; print(json.dumps(status()))\"" 2>/dev/null | tail -1)
echo "status(): $STATUS_PY"
[ "$(echo "$STATUS_PY" | jget ready)" = "True" ] && pass "4a status() says ready" || fail "4a status() says ready (reason: $(echo "$STATUS_PY" | jget reason))"
[ "$(echo "$STATUS_PY" | jget enabled)" = "False" ] && pass "4b status() says enabled false" || fail "4b status() says enabled false"
[ "$(echo "$STATUS_PY" | jget reason)" = "ready" ] && pass "4c the reason is plain" || fail "4c the reason is plain"
[ "$(echo "$STATUS_PY" | jget address_filter_ok)" = "True" ] && [ "$(echo "$STATUS_PY" | jget dns_ok)" = "True" ] && pass "4d address_filter_ok and dns_ok are true" || fail "4d address_filter_ok and dns_ok are true"

echo "== step 5: register and unregister a throw-away runner ($MOD)"
mkdir -p "$EXT/$MOD/sandbox/runners" "$PROBE_RUNTIME/bin"
printf '#!/bin/sh\necho probe\n' > "$EXT/$MOD/sandbox/runners/probe.sh"
printf 'probe runtime\n' > "$PROBE_RUNTIME/bin/tool"
TOOL_SUM=$(sha256sum "$PROBE_RUNTIME/bin/tool" | awk '{print $1}')
printf '%s  bin/tool\n' "$TOOL_SUM" > "$EXT/$MOD/sandbox/probe.sha256"
cat > "$EXT/$MOD/tec_tac.json" <<JSON
{"id": "$MOD", "type": "extension", "version": "0.1.0", "category": "premium",
 "requires": {"framework": ">=1.17.116"}, "publisher_permissions": ["sandbox.register"],
 "sandbox_runners": [{"id": "$MOD.probe", "description": "Throw-away probe", "executable": "sandbox/runners/probe.sh",
   "runtime_roots": [{"path": "$PROBE_RUNTIME", "tree_sha256_file": "sandbox/probe.sha256"}],
   "credential_files": ["auth"], "limits": {"memory_mb": 512}}]}
JSON
chown -R root:root "$EXT/$MOD" "$LIB/probe-runtime"
chmod -R go-w "$EXT/$MOD" "$LIB/probe-runtime"
"$HELPER" --register-module "$MOD" >/dev/null 2>&1 && pass "5a --register-module accepted the manifest" || fail "5a --register-module accepted the manifest"
REG="$LIB/registry/$MOD.probe.json"
[ "$(stat -c '%U %a' "$REG" 2>/dev/null)" = "root 644" ] && pass "5b the registry file is root 0644" || fail "5b the registry file is root 0644"
COPY="$LIB/runners/$MOD/probe.sh"
[ "$(stat -c '%U %a' "$COPY" 2>/dev/null)" = "root 755" ] && pass "5c the program was copied root 0755" || fail "5c the program was copied root 0755"
[ "$(sha256sum "$COPY" 2>/dev/null | awk '{print $1}')" = "$(jget executable_sha256 < "$REG")" ] && pass "5d the recorded SHA-256 matches the copy" || fail "5d the recorded SHA-256 matches the copy"
[ "$(jget runtime_verified < "$REG")" = "True" ] && pass "5e the runtime matched its signed listing" || fail "5e the runtime matched its signed listing"
[ "$(jget limits.memory_mb < "$REG")" = "512" ] && [ "$(jget limits.run_seconds < "$REG")" = "240" ] && pass "5f limits: the declared value and the default" || fail "5f limits: the declared value and the default"
LISTED=$(runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --status 2>/dev/null | python3 -c 'import json,sys; print(",".join(r["id"] for r in json.load(sys.stdin)["runners"]))')
[ "$LISTED" = "$MOD.probe" ] && pass "5g --status lists the runner" || fail "5g --status lists the runner (got '$LISTED')"
# a tampered runtime is noticed by the sweep
echo "changed" >> "$PROBE_RUNTIME/bin/tool"
"$HELPER" --sweep >/dev/null 2>&1
[ "$(jget runtime_verified < "$REG")" = "False" ] && pass "5h the sweep marks a changed runtime unverified" || fail "5h the sweep marks a changed runtime unverified"
echo "reason: $(jget runtime_reason < "$REG")"
# a manifest that declares allowed_hosts is refused and changes nothing
python3 - "$EXT/$MOD/tec_tac.json" <<'PY'
import json, sys
p = sys.argv[1]
m = json.load(open(p))
m["sandbox_runners"][0]["allowed_hosts"] = ["api.example.com"]
json.dump(m, open(p, "w"))
PY
chown root:root "$EXT/$MOD/tec_tac.json"; chmod 644 "$EXT/$MOD/tec_tac.json"
"$HELPER" --register-module "$MOD" >/dev/null 2>&1 && fail "5i allowed_hosts was accepted" || pass "5i allowed_hosts is refused"
[ -f "$REG" ] && pass "5j the earlier registration is untouched by the refused one" || fail "5j the earlier registration is untouched by the refused one"
# a group-writable manifest is refused
python3 - "$EXT/$MOD/tec_tac.json" <<'PY'
import json, sys
p = sys.argv[1]
m = json.load(open(p))
del m["sandbox_runners"][0]["allowed_hosts"]
json.dump(m, open(p, "w"))
PY
chmod 664 "$EXT/$MOD/tec_tac.json"
"$HELPER" --register-module "$MOD" >/dev/null 2>&1 && fail "5k a group-writable manifest was accepted" || pass "5k a group-writable manifest is refused"
chmod 644 "$EXT/$MOD/tec_tac.json"
# a manifest without runners drops the runner (an upgrade)
python3 - "$EXT/$MOD/tec_tac.json" <<'PY'
import json, sys
p = sys.argv[1]
m = json.load(open(p))
del m["sandbox_runners"]
json.dump(m, open(p, "w"))
PY
"$HELPER" --register-module "$MOD" >/dev/null 2>&1 && pass "5l an upgrade to a manifest with no runners is accepted" || fail "5l an upgrade to a manifest with no runners is accepted"
[ ! -e "$REG" ] && [ ! -e "$LIB/runners/$MOD" ] && pass "5m the stale runner and its program are gone" || fail "5m the stale runner and its program are gone"
"$HELPER" --unregister-module "$MOD" >/dev/null 2>&1 && pass "5n --unregister-module works" || fail "5n --unregister-module works"
rm -rf "${EXT:?}/${MOD:?}" "${LIB:?}/probe-runtime"
[ -z "$(ls -A "$LIB/registry" 2>/dev/null)" ] && pass "5o nothing is left in the registry" || fail "5o nothing is left in the registry: $(ls "$LIB/registry")"
[ ! -e "$LIB/runners/$MOD" ] && pass "5p nothing is left in runners" || fail "5p nothing is left in runners"
grep -q '"runner.registered"' "$STATE/audit.jsonl" && grep -q '"runner.removed"' "$STATE/audit.jsonl" && pass "5q the helper's own audit log has the registration and the removal" || fail "5q the helper's own audit log has the registration and the removal"
grep -q 'DUMMY' "$STATE/audit.jsonl" && fail "5r a credential-like text is in the audit log" || pass "5r the audit log holds no credential"

echo "== step 6: YOURS (not scripted)"
echo "   In the browser, install a module that has nothing to do with the sandbox, then upgrade it. Both must finish without an error."
echo "   Write PASS or FAIL for each. If one fails, send the job log from the Modules page (it names the stage: sandbox-runners, or another)."

echo
if [ "$FAILS" -eq 0 ]; then echo "ALL SCRIPTED STEPS PASSED"; exit 0; else echo "$FAILS STEP(S) FAILED"; exit 1; fi

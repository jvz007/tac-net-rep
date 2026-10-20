#!/usr/bin/env bash
# Runtime check for Core 1.17.62 R-23: the root helper keeps no runnable path for a surviving hand registration after a module is uninstalled.
# It did NOT run on the development PC (it needs the real root helper, root-owned files and a Linux server). DEV SERVER ONLY, as root.
#
#   sudo bash tests/server-maintenance-uninstall-runtime-1.17.62.sh
#
# It uses a throw-away module id, smuninst, and cleans up after itself. It never touches another module's registrations. Run it when no
# module install, upgrade or Core update is running. It prints PASS or FAIL for each step and exits 1 when any step fails.
#
# What to send back after a FAIL: the whole output of the script, plus `ls -l /etc/tec-tac/server-maintenance/actions.d` and the last 30 lines
# of /var/lib/tec-tac/server-maintenance/audit.jsonl (or wherever your layout keeps the helper's audit log).
set -u

HELPER=/usr/local/sbin/tec-tac-server-maintenance
REG=${TEC_TAC_SM_REGISTRY:-/etc/tec-tac/server-maintenance/actions.d}
ACT=${TEC_TAC_SM_ACTIONS:-/usr/local/lib/tec-tac/server-maintenance/actions}
EXT=${TEC_TAC_EXTENSIONS_ROOT:-/opt/tec-tac/extensions}
MOD=smuninst
WORK=$(mktemp -d /root/smuninst-check.XXXXXX)
FAILS=0

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }
check() { # check "name" command...
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

cleanup() {
  "$HELPER" --unregister-module "$MOD" >/dev/null 2>&1
  for id in "$MOD.hand" "$MOD.ownerless" "$MOD.link" "$MOD.fresh" "$MOD.echo"; do rm -f "$REG/$id.json"; done
  rm -rf "$EXT/$MOD" "$ACT/$MOD" "$ACT/${MOD}-own" "$WORK"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "FAIL this script must run as root"; exit 1; fi
[ -x "$HELPER" ] || { echo "FAIL the root helper is missing at $HELPER (update Core to 1.17.62 first)"; exit 1; }
grep -q "_disable_surviving_hand_registrations" "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.62: it has no R-23 code"; exit 1; }

# a python probe that loads the real helper and calls load_action, the one door of dispatch and run
probe() { # probe <action id> -> prints OK, or the refusal text
  python3 - "$HELPER" "$1" <<'PY'
import importlib.machinery, importlib.util, sys
loader = importlib.machinery.SourceFileLoader("smh", sys.argv[1])
spec = importlib.util.spec_from_loader("smh", loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
try:
    module.load_action(sys.argv[2])
    print("OK")
except Exception as exc:
    print(str(exc))
PY
}

write_module() { # write_module <action id> <executable name>
  rm -rf "$EXT/$MOD"
  mkdir -p "$EXT/$MOD/server_maintenance/actions"
  printf '#!/bin/sh\necho probe\n' > "$EXT/$MOD/server_maintenance/actions/$2"
  cat > "$EXT/$MOD/tec_tac.json" <<JSON
{"id": "$MOD", "type": "extension", "version": "0.1.0", "category": "server",
 "publisher_permissions": ["server_maintenance.register"],
 "permission_groups": {"Probe": ["$MOD.run"]},
 "server_maintenance_actions": [{"id": "$1", "permission": "$MOD.run", "executable": "server_maintenance/actions/$2", "timeout_seconds": 30}]}
JSON
  chown -R root:root "$EXT/$MOD"
  chmod -R go-w "$EXT/$MOD"
  chmod 755 "$EXT/$MOD/server_maintenance/actions/$2"
}

hand_manifest() { # hand_manifest <file> <action id> <executable> [owner_module]
  python3 - "$@" <<'PY'
import json, sys
path, action_id, executable = sys.argv[1:4]
payload = {"id": action_id, "revision": "1", "executable": executable, "argv": [], "parameters": {}, "timeout_seconds": 30,
           "success_exit_codes": [0], "enabled": True, "permission": "smuninst.run"}
if len(sys.argv) > 4:
    payload["owner_module"] = sys.argv[4]
open(path, "w").write(json.dumps(payload))
PY
}

jget() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get(sys.argv[2], ''))" "$1" "$2"; }

echo "== step 1: install the throw-away module (a real --register-module as root)"
write_module "$MOD.echo" echo.sh
"$HELPER" --register-module "$MOD" >"$WORK/register.out" 2>&1
check "1a registry file of the module's own action exists" test -f "$REG/$MOD.echo.json"
[ "$(jget "$REG/$MOD.echo.json" registered_by)" = "module-manifest" ] && pass "1b it is registered_by module-manifest" || fail "1b it is registered_by module-manifest"
[ "$(stat -c '%U:%G %a' "$ACT/$MOD/echo.sh")" = "root:root 755" ] && pass "1c the copied executable is root:root 755" || fail "1c the copied executable is root:root 755"

echo "== step 2: two real hand registrations, and one that belongs to nobody"
hand_manifest "$WORK/hand.json" "$MOD.hand" "$ACT/$MOD/echo.sh" "$MOD"
"$HELPER" --register "$WORK/hand.json" >/dev/null 2>&1
check "2a the hand registration exists" test -f "$REG/$MOD.hand.json"
[ -z "$(jget "$REG/$MOD.hand.json" registered_by)" ] && pass "2b it carries no registered_by (a hand registration)" || fail "2b it carries no registered_by"
mkdir -p "$ACT/${MOD}-own"; printf '#!/bin/sh\necho own\n' > "$ACT/${MOD}-own/prog"; chown root:root "$ACT/${MOD}-own/prog"; chmod 755 "$ACT/${MOD}-own/prog"
hand_manifest "$WORK/own.json" "$MOD.ownerless" "$ACT/${MOD}-own/prog"
"$HELPER" --register "$WORK/own.json" >/dev/null 2>&1
OWN_SUM=$(sha256sum "$REG/$MOD.ownerless.json" | cut -d' ' -f1)
[ "$(probe "$MOD.hand")" = "OK" ] && pass "2c the hand registration runs before the uninstall (load_action accepts it)" || fail "2c the hand registration runs before the uninstall"

echo "== step 3: uninstall (a real --unregister-module as root)"
"$HELPER" --unregister-module "$MOD" >"$WORK/unregister.out" 2>&1
check "3a the module's own registry file is gone" test ! -e "$REG/$MOD.echo.json"
check "3b the module's action folder is gone" test ! -e "$ACT/$MOD"
check "3c the hand registration is still on disk" test -f "$REG/$MOD.hand.json"
[ "$(jget "$REG/$MOD.hand.json" enabled)" = "False" ] && pass "3d it is enabled: false" || fail "3d it is enabled: false"
[ "$(jget "$REG/$MOD.hand.json" disabled_reason)" = "module removed" ] && pass "3e disabled_reason is 'module removed'" || fail "3e disabled_reason is 'module removed'"
[ "$(stat -c '%U:%G %a' "$REG/$MOD.hand.json")" = "root:root 644" ] && pass "3f the rewritten file is root:root 644" || fail "3f the rewritten file is root:root 644 (got $(stat -c '%U:%G %a' "$REG/$MOD.hand.json"))"
[ "$(sha256sum "$REG/$MOD.ownerless.json" | cut -d' ' -f1)" = "$OWN_SUM" ] && pass "3g the registration that belongs to nobody is byte-for-byte unchanged" || fail "3g the ownerless registration was changed"

echo "== step 4: dispatch and run refuse it"
OUT=$(probe "$MOD.hand")
case "$OUT" in *"module removed"*) pass "4a load_action refuses with 'module removed' ($OUT)";; *) fail "4a load_action refused with: $OUT";; esac
[ "$(probe "$MOD.ownerless")" = "OK" ] && pass "4b the registration that belongs to nobody still runs" || fail "4b the ownerless registration no longer runs"

echo "== step 5: a later package under the same module id fills the path"
write_module "$MOD.fresh" echo.sh
"$HELPER" --register-module "$MOD" >/dev/null 2>&1
check "5a the new package registered its own action" test -f "$REG/$MOD.fresh.json"
check "5b the old hand registration's path is filled again" test -f "$ACT/$MOD/echo.sh"
OUT=$(probe "$MOD.hand")
case "$OUT" in *"module removed"*) pass "5c the old hand registration is still refused";; *) fail "5c the old hand registration ran or failed differently: $OUT";; esac

echo "== step 6: a registry file that is a symlink is not followed"
printf '{"id": "%s.link", "owner_module": "%s", "enabled": true, "executable": "/bin/true"}' "$MOD" "$MOD" > "$WORK/link-target.json"
LINK_SUM=$(sha256sum "$WORK/link-target.json" | cut -d' ' -f1)
ln -sf "$WORK/link-target.json" "$REG/$MOD.link.json"
"$HELPER" --unregister-module "$MOD" >/dev/null 2>&1
[ "$(sha256sum "$WORK/link-target.json" | cut -d' ' -f1)" = "$LINK_SUM" ] && pass "6a the file behind the link is unchanged" || fail "6a the file behind the link was rewritten"
check "6b the link is still a link" test -L "$REG/$MOD.link.json"
rm -f "$REG/$MOD.link.json"

echo "== step 7: registering it again knowingly makes it runnable"
write_module "$MOD.echo" echo.sh
"$HELPER" --register-module "$MOD" >/dev/null 2>&1
hand_manifest "$WORK/hand2.json" "$MOD.hand" "$ACT/$MOD/echo.sh" "$MOD"
"$HELPER" --register "$WORK/hand2.json" >/dev/null 2>&1
[ "$(jget "$REG/$MOD.hand.json" enabled)" = "True" ] && pass "7a the fresh file is enabled again" || fail "7a the fresh file is enabled again"
[ "$(probe "$MOD.hand")" = "OK" ] && pass "7b it runs again" || fail "7b it runs again"

echo
if [ "$FAILS" -eq 0 ]; then echo "ALL PASS (R-23 on the real helper)"; exit 0; fi
echo "$FAILS step(s) FAILED. Send back the whole output, the listing of $REG and the helper's audit log tail."
exit 1

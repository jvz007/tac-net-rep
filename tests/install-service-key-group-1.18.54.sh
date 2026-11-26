#!/usr/bin/env bash
# 1.18.54: daphne, celery and celerybeat get the Tactical group like rmm, so every service that can call the secret store can read the master key.
# 1.18.55: the live process check moved into service_group_check (tests/install-service-key-group-1.18.55.sh); this test reads the function and the loop together.
#
# install.sh needs root and systemd, so this test cannot run it. It extracts the drop-in function by its own text, runs it against a temporary
# folder with a fake systemctl and chown, and asserts on the text of the post-install check and of uninstall.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="${ROOT}/install.sh"
UNINSTALL="${ROOT}/uninstall.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
fail() { echo "[TEST] FAIL: $*" >&2; exit 1; }
ok() { echo "       $*"; }

bash -n "${INSTALL}" || fail "bash -n install.sh"
bash -n "${UNINSTALL}" || fail "bash -n uninstall.sh"
ok "bash -n passes on install.sh and uninstall.sh"
for f in "${INSTALL}" "${UNINSTALL}"; do
    if grep -q $'\r' "${f}"; then fail "$(basename "${f}") must keep LF line endings"; fi
done
grep -q 'SupplementaryGroups=${TACTICAL_GROUP}' "${INSTALL}" || fail "the literal SupplementaryGroups=\${TACTICAL_GROUP} text is missing"

line_of() { grep -n -F -m1 -- "$2" "$1" | cut -d: -f1; }
LIST_LINE="$(line_of "${INSTALL}" 'KEY_GROUP_SERVICES="rmm daphne celery celerybeat"')"
FN_START="$(line_of "${INSTALL}" 'install_service_group_dropin() {')"
[[ -n "${LIST_LINE}" && -n "${FN_START}" ]] || fail "service list or function not found"
FN_END="$(awk -v s="${FN_START}" 'NR>s && /^}/ {print NR; exit}' "${INSTALL}")"
{ sed -n "${LIST_LINE}p" "${INSTALL}"; sed -n "${FN_START},${FN_END}p" "${INSTALL}"; } > "${TMP}/fn.sh"
[[ "$(grep -c 'install_service_group_dropin "' "${INSTALL}")" == "1" ]] || fail "the function is called exactly once, with the systemd folder"
grep -q 'install_service_group_dropin "/etc/systemd/system"' "${INSTALL}" || fail "the function is not called with /etc/systemd/system"
[[ "$(grep -c 'systemctl daemon-reload' "${TMP}/fn.sh")" == "1" ]] || fail "one daemon-reload after the loop"

# fakes
mkdir -p "${TMP}/bin"
printf '#!/bin/sh\necho "$@" >> "%s/systemctl.log"\n' "${TMP}" > "${TMP}/bin/systemctl"
printf '#!/bin/sh\nexit 0\n' > "${TMP}/bin/chown"
chmod +x "${TMP}/bin/systemctl" "${TMP}/bin/chown"

run_function() {
    PATH="${TMP}/bin:${PATH}" TACTICAL_GROUP=tactical bash -c 'log() { echo "LOG: $*"; }; source "$1"; install_service_group_dropin "$2"' _ "${TMP}/fn.sh" "${TMP}/systemd" > "${TMP}/out.txt"
}
EXPECTED=$'[Service]\nSupplementaryGroups=tactical'

# Johan's manual file already exists on dev02
mkdir -p "${TMP}/systemd/daphne.service.d"
printf '[Service]\nSupplementaryGroups=tactical\n' > "${TMP}/systemd/daphne.service.d/tec-tac-groups.conf"
cp "${TMP}/systemd/daphne.service.d/tec-tac-groups.conf" "${TMP}/manual.before"

run_function
for svc in rmm daphne celery celerybeat; do
    f="${TMP}/systemd/${svc}.service.d/tec-tac.conf"
    [[ -f "${f}" ]] || fail "${svc}: tec-tac.conf not written"
    [[ "$(cat "${f}")" == "${EXPECTED}" ]] || fail "${svc}: wrong content"
    [[ "$(stat -c %a "${f}")" == "644" ]] || fail "${svc}: mode is $(stat -c %a "${f}"), not 644"
    grep -q "LOG: Installed ${svc}.service supplementary-group drop-in" "${TMP}/out.txt" || fail "${svc}: no log line"
done
[[ "$(grep -c '^LOG:' "${TMP}/out.txt")" == "4" ]] || fail "one log line per service"
[[ "$(grep -c 'daemon-reload' "${TMP}/systemctl.log")" == "1" ]] || fail "one daemon-reload per run"
cmp -s "${TMP}/manual.before" "${TMP}/systemd/daphne.service.d/tec-tac-groups.conf" || fail "the manual tec-tac-groups.conf was changed"
ok "all four services get tec-tac.conf (content, mode 0644, log line); the manual daphne file is untouched"

# a second run changes nothing
for svc in rmm daphne celery celerybeat; do cp "${TMP}/systemd/${svc}.service.d/tec-tac.conf" "${TMP}/${svc}.before"; done
run_function
for svc in rmm daphne celery celerybeat; do
    cmp -s "${TMP}/${svc}.before" "${TMP}/systemd/${svc}.service.d/tec-tac.conf" || fail "${svc}: second run changed the file"
done
cmp -s "${TMP}/manual.before" "${TMP}/systemd/daphne.service.d/tec-tac-groups.conf" || fail "the manual file changed on the second run"
ok "a second run is idempotent"

# a stale drop-in is rewritten
printf 'junk\n' > "${TMP}/systemd/celery.service.d/tec-tac.conf"
run_function
[[ "$(cat "${TMP}/systemd/celery.service.d/tec-tac.conf")" == "${EXPECTED}" ]] || fail "a stale drop-in was not rewritten"
ok "an existing drop-in is rewritten"

# nothing opens the key
if sed -n "${FN_START},${FN_END}p" "${INSTALL}" | grep -q 'master.key\|www-data'; then fail "the function must not touch the key or grant www-data"; fi
[[ "$(sed -n "${FN_START},${FN_END}p" "${INSTALL}" | grep -c 'chmod')" == "1" ]] || fail "the function sets one mode only"

# the post-install check covers every service, in both tests, and names the service
CHECK_START="$(line_of "${INSTALL}" 'service_group_check() {')"
LOOP_START="$(line_of "${INSTALL}" 'for key_svc in ${KEY_GROUP_SERVICES}; do')"
[[ -n "${CHECK_START}" && -n "${LOOP_START}" ]] || fail "check function or loop not found"
[[ -n "${CHECK_START}" ]] || fail "post-install check loop not found"
CHECK_END="$(awk -v s="${LOOP_START}" 'NR>s && /^done$/ {print NR; exit}' "${INSTALL}")"
sed -n "${CHECK_START},${CHECK_END}p" "${INSTALL}" > "${TMP}/check.sh"
grep -q 'systemctl show "${key_svc}.service" -p SupplementaryGroups --value' "${TMP}/check.sh" || fail "check does not read SupplementaryGroups"
grep -q 'systemctl show "${svc}.service" -p MainPID --value' "${TMP}/check.sh" || fail "check does not read MainPID"
grep -q '${PROC_ROOT}/${pid}/status' "${TMP}/check.sh" || fail "check does not read /proc status"
grep -q '^Groups:\|/\^Groups:/' "${TMP}/check.sh" || fail "check does not read the Groups line"
grep -q '${key_svc}.service did not load required supplementary group' "${TMP}/check.sh" || fail "failure message does not name the service"
grep -q 'Nothing was changed on the key' "${TMP}/check.sh" || fail "failure message lacks the key note"
# the guard must be able to fail: the extended-regex pattern has to match a sample that touches the key (1.18.55: the old basic-regex pattern read | as a literal)
KEY_GUARD='master\.key|www-data|chmod'
echo 'chmod 660 master.key' > "${TMP}/bad-sample.sh"
grep -Eq "${KEY_GUARD}" "${TMP}/bad-sample.sh" || fail "the key guard does not match a sample that changes the key mode"
if grep -Eq "${KEY_GUARD}" "${TMP}/check.sh"; then fail "the check must not read the key"; fi
ok "the post-install check covers rmm, daphne, celery and celerybeat by systemctl and by /proc Groups"

# uninstall removes all four and still reloads systemd
for svc in rmm daphne celery celerybeat; do
    grep -q "/etc/systemd/system/${svc}.service.d/tec-tac.conf" "${UNINSTALL}" || fail "uninstall.sh does not remove the ${svc} drop-in"
done
grep -q 'systemctl daemon-reload' "${UNINSTALL}" || fail "uninstall.sh does not reload systemd"
if grep -q 'tec-tac-groups.conf' "${UNINSTALL}" "${INSTALL}"; then fail "the manual file must not be touched by the scripts"; fi
ok "uninstall.sh removes the four drop-ins and reloads systemd"

echo "[TEST] PASS install service key group 1.18.54"

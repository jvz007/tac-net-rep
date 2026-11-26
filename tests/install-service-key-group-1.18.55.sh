#!/usr/bin/env bash
# 1.18.55: the post-install check no longer guesses systemd's MainPID. service_group_check uses a usable MainPID, and otherwise the processes in the
# unit's control group that run as the service user.
#
# install.sh needs root and systemd, so this test cannot run it. It extracts service_group_check by its own text (like the 1.18.54 test), sources it
# with a fake systemctl, and points PROC_ROOT and CGROUP_ROOT at fake trees in a temporary folder. Real systemd behaviour is proved on dev02.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="${ROOT}/install.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
fail() { echo "[TEST] FAIL: $*" >&2; exit 1; }
ok() { echo "       $*"; }

bash -n "${INSTALL}" || fail "bash -n install.sh"
bash -n "${BASH_SOURCE[0]}" || fail "bash -n of this test"
for f in "${INSTALL}" "${BASH_SOURCE[0]}"; do
    if grep -q $'\r' "${f}"; then fail "$(basename "${f}") must keep LF line endings"; fi
done
ok "bash -n passes and there are no CR bytes"

line_of() { grep -n -F -m1 -- "$2" "$1" | cut -d: -f1; }
FN_START="$(line_of "${INSTALL}" 'service_group_check() {')"
[[ -n "${FN_START}" ]] || fail "service_group_check not found"
FN_END="$(awk -v s="${FN_START}" 'NR>s && /^}/ {print NR; exit}' "${INSTALL}")"
sed -n "${FN_START},${FN_END}p" "${INSTALL}" > "${TMP}/fn.sh"
[[ "$(grep -c 'service_group_check "${key_svc}"' "${INSTALL}")" == "1" ]] || fail "the loop calls the function once per service"
if grep -Eq 'master\.key|www-data|chmod' "${TMP}/fn.sh"; then fail "the function must not touch the key"; fi

SERVICE_UID="$(id -u)"
OTHER_UID="$((SERVICE_UID + 1))"
GID=1500
mkdir -p "${TMP}/bin" "${TMP}/proc" "${TMP}/cgroup/system.slice/celery.service"
cat > "${TMP}/bin/systemctl" <<'FAKE'
#!/bin/sh
# systemctl show <unit> -p <Property> --value, answered from the environment
prop=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-p" ]; then prop="$2"; fi
    shift
done
case "${prop}" in
    MainPID) printf '%s\n' "${FAKE_MAINPID:-0}" ;;
    ControlGroup) printf '%s\n' "${FAKE_CGROUP:-}" ;;
    User) printf '%s\n' "${FAKE_USER:-}" ;;
esac
FAKE
chmod +x "${TMP}/bin/systemctl"

# a fake process: proc <pid> <uid> <groups...>
proc() {
    local pid="$1" uid="$2"; shift 2
    mkdir -p "${TMP}/proc/${pid}"
    printf 'Name:\tfake\nUid:\t%s\t%s\t%s\t%s\nGid:\t%s\t%s\t%s\t%s\nGroups:\t%s \n' "${uid}" "${uid}" "${uid}" "${uid}" "${GID}" "${GID}" "${GID}" "${GID}" "$*" > "${TMP}/proc/${pid}/status"
}
cgroup_procs() { printf '%s\n' "$@" > "${TMP}/cgroup/system.slice/celery.service/cgroup.procs"; }

# run <expected: pass|fail> <label> : runs the function in a subshell with the fakes; prints the output on a failure
run_case() {
    local expect="$1" label="$2" status=0
    PATH="${TMP}/bin:${PATH}" PROC_ROOT="${TMP}/proc" CGROUP_ROOT="${TMP}/cgroup" FAKE_USER="$(id -un)" \
        bash -c 'log() { echo "LOG: $*"; }; fail() { echo "FAIL: $*"; exit 1; }; source "$1"; service_group_check celery "$2" tactical' _ "${TMP}/fn.sh" "${GID}" > "${TMP}/out.txt" 2>&1 || status=$?
    if [[ "${expect}" == "pass" && "${status}" -ne 0 ]]; then cat "${TMP}/out.txt" >&2; fail "${label}: expected a pass"; fi
    if [[ "${expect}" == "fail" && "${status}" -eq 0 ]]; then cat "${TMP}/out.txt" >&2; fail "${label}: expected a failure"; fi
}
reset_trees() { rm -rf "${TMP}/proc"; mkdir -p "${TMP}/proc"; : > "${TMP}/cgroup/system.slice/celery.service/cgroup.procs"; unset FAKE_MAINPID FAKE_CGROUP; }

# 1. a usable MainPID with the group passes; without it fails (as in 1.18.54)
reset_trees
proc 4100 "${SERVICE_UID}" 10 "${GID}"
export FAKE_MAINPID=4100
run_case pass "good MainPID"
grep -q "LOG: Verified live celery process has Tec-Tac runtime group tactical (gid ${GID})" "${TMP}/out.txt" || fail "no verified line"
proc 4100 "${SERVICE_UID}" 10 11
run_case fail "MainPID without the group"
grep -q "Live celery process is missing Tec-Tac runtime group tactical (gid ${GID})" "${TMP}/out.txt" || fail "the missing-group message names the service"
ok "a usable MainPID is checked as before"

# 2. MainPID 0 and a cgroup of three processes that all carry the gid passes
reset_trees
export FAKE_MAINPID=0 FAKE_CGROUP=/system.slice/celery.service
for p in 4201 4202 4203; do proc "${p}" "${SERVICE_UID}" 10 "${GID}"; done
cgroup_procs 4201 4202 4203
run_case pass "MainPID 0, three good processes"
ok "MainPID 0 with three good processes in the cgroup passes"

# 3. one of them lacks the gid: fails, naming the service
proc 4203 "${SERVICE_UID}" 10 11
run_case fail "one process lacks the gid"
grep -q "Live celery process is missing" "${TMP}/out.txt" || fail "the failure names the service"
ok "one process without the gid fails"

# 4. a root helper (another uid) without the gid is ignored
proc 4203 "${SERVICE_UID}" 10 "${GID}"
proc 4300 "${OTHER_UID}" 0
cgroup_procs 4201 4202 4203 4300
run_case pass "root helper ignored"
ok "a helper process of another user without the gid is ignored"

# 5. MainPID 0 and an empty or unreadable cgroup: could not inspect
cgroup_procs
run_case fail "empty cgroup"
grep -q "Could not inspect live celery process after restart." "${TMP}/out.txt" || fail "empty cgroup message"
rm -f "${TMP}/cgroup/system.slice/celery.service/cgroup.procs"
run_case fail "missing cgroup file"
grep -q "Could not inspect live celery process after restart." "${TMP}/out.txt" || fail "missing cgroup message"
cgroup_procs 4300
run_case fail "only a helper of another user"
grep -q "Could not inspect" "${TMP}/out.txt" || fail "only foreign processes: nothing inspected"
FAKE_CGROUP="" run_case fail "no ControlGroup"
ok "an empty, missing or foreign-only cgroup fails with 'Could not inspect'"

# 6. a process that vanishes mid-read is skipped
cgroup_procs 4201 4999 4202
run_case pass "a vanished process"
ok "a process that exited is skipped"

# 7. a MainPID that is wrong (not readable) falls back to the cgroup
export FAKE_MAINPID=777777
run_case pass "an unreadable MainPID"
export FAKE_MAINPID=1
run_case pass "MainPID 1"
ok "an unreadable MainPID or 1 falls back to the cgroup"

# 8. the loop still checks the SupplementaryGroups text first, and the function is the only live check
grep -q 'did not load required supplementary group' "${INSTALL}" || fail "the SupplementaryGroups check is gone"
if grep -n 'MainPID' "${INSTALL}" | grep -v 'service_group_check\|PROC_ROOT\|^.*#' | grep -q 'SVC_PID'; then fail "the old inline MainPID guess is still there"; fi
ok "the SupplementaryGroups text check stays first"

echo "[TEST] PASS install service key group 1.18.55"

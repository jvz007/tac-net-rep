#!/usr/bin/env bash
# 1.18.29 regression: the install-time canary block of install.sh, run for real with stubs.
#
# The block between "# --- sandbox canary begin (1.18.29) ---" and "# --- sandbox canary end ---" is cut out of install.sh and run under
# `set -euo pipefail` in a temp folder with a stub `timeout`, a stub helper (--status) and no network, no systemd and no root. Cases:
#   pass -> "Sandbox: active"; canary exit 1 -> "Sandbox: not active: the canary failed: <failing ids>"; timeout (124) -> the did-not-finish line;
#   a crash -> the failed line with the status; selftest not ready -> the canary is skipped with the selftest reason; SECONDS forced high -> skipped
#   with the time reason; SECONDS partly used -> the bound is reduced to 1700 - SECONDS; an unreadable status -> a plain reason.
# Every case must leave the script alive (exit status 0, the line after the block runs). What cannot run here: the real canary, a real install.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "[TEST] FAIL: $*" >&2; exit 1; }

PY=""
for candidate in python3 python; do
    if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -c 'import json' >/dev/null 2>&1; then PY="${candidate}"; break; fi
done
[[ -n "${PY}" ]] || fail "no python to stand in for /usr/bin/python3"

T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
BLOCK="${T}/block.sh"
awk '/^# --- sandbox canary begin \(1\.18\.29\) ---$/{on=1} on{print} /^# --- sandbox canary end ---$/{on=0}' "${ROOT}/install.sh" > "${BLOCK}"
[[ "$(grep -c '^# --- sandbox canary ' "${BLOCK}")" -eq 2 ]] || fail "could not cut out the canary block"
# the stub python stands in for the server's /usr/bin/python3 (the block names that path on purpose)
sed -i "s#/usr/bin/python3#${PY}#g" "${BLOCK}"

# usage: run_case <name> <ready 1|0> <scenario pass|fail|hang|crash|garbage> [forced SECONDS]
run_case() {
    local name="$1" ready="$2" scenario="$3" forced="${4:-0}"
    local case_dir="${T}/${name}"
    mkdir -p "${case_dir}/lib"
    echo "${ready}" > "${case_dir}/ready"
    echo 0 > "${case_dir}/canary"
    echo "${scenario}" > "${case_dir}/scenario"
    cat > "${case_dir}/helper" <<'HELPER'
#!/usr/bin/env bash
D="$(cd "$(dirname "$0")" && pwd)"
[[ "$1" == "--status" ]] || exit 2
[[ "$(cat "$D/scenario")" == "garbage" ]] && { echo 'not json'; exit 0; }
if [[ "$(cat "$D/ready")" == "1" ]]; then R=true; REASON=ready; else R=false; REASON='the selftest found the private network wrong: caf\u00e9 \u0007bell'; fi
if [[ "$(cat "$D/canary")" == "1" ]]; then C=true; else C=false; fi
printf '{"status": {"ready": %s, "reason": "%s", "canary_ok": %s, "enabled": true}, "runners": []}\n' "$R" "$REASON" "$C"
HELPER
    chmod +x "${case_dir}/helper"
    cat > "${case_dir}/run.sh" <<RUNNER
set -euo pipefail
log() { printf '[TEC-TAC] %s\n' "\$*"; }
D="${case_dir}"
SANDBOX_HELPER="\${D}/helper"
SANDBOX_LIB="\${D}/lib"
# stub timeout: the canary call is recorded and decided by the scenario; every other call (the --status read) runs for real
timeout() {
    local bound="\$1"; shift
    if [[ "\$*" == *--canary* ]]; then
        echo "\${bound}" > "\${D}/budget"
        echo "\$*" > "\${D}/canary-argv"
        case "\$(cat "\${D}/scenario")" in
            pass) echo "ROW network-private OK"; echo "ROW read-tectac-canary OK"; echo 1 > "\${D}/canary"; return 0 ;;
            fail) echo "ROW network-private OK"; echo "ROW egress-leak ATTACK SUCCEEDED"; echo "ROW unix-door NOT RUN (reason)"; return 1 ;;
            hang) return 124 ;;
            crash) return 139 ;;
        esac
        return 0
    fi
    "\$@"
}
SECONDS=${forced}
${BLOCK_PRELUDE:-}
source "${BLOCK}"
echo "AFTER_BLOCK_REACHED"
RUNNER
    bash "${case_dir}/run.sh" > "${case_dir}/out" 2>&1 || fail "${name}: the block ended the script with status $? (it must never fail the install): $(cat "${case_dir}/out")"
    grep -q '^AFTER_BLOCK_REACHED$' "${case_dir}/out" || fail "${name}: the script did not continue after the block"
    local lines
    lines="$(grep -c '^\[TEC-TAC\] Sandbox: ' "${case_dir}/out" || true)"
    [[ "${lines}" -eq 1 ]] || fail "${name}: expected exactly one Sandbox result line, got ${lines}: $(cat "${case_dir}/out")"
    echo "${case_dir}"
}

result_line() { grep '^\[TEC-TAC\] Sandbox: ' "$1/out" | sed 's/^\[TEC-TAC\] //'; }
expect_line() { [[ "$(result_line "$1")" == "$2" ]] || fail "$3: got '$(result_line "$1")', wanted '$2'"; }
expect_ran() { [[ -f "$1/budget" ]] || fail "$2: the canary did not run"; }
expect_skipped() { [[ ! -f "$1/budget" ]] || fail "$2: the canary ran but must be skipped"; }

# 1. ready + canary passes
d="$(run_case pass 1 pass)"
expect_line "${d}" "Sandbox: active" "pass"
expect_ran "${d}" "pass"
[[ "$(cat "${d}/budget")" == "900s" ]] || fail "pass: bound $(cat "${d}/budget"), wanted 900s"
[[ "$(cat "${d}/canary-argv")" == *"-I ${d}/lib/sandbox-selftest.py --selftest --canary" ]] || fail "pass: argv $(cat "${d}/canary-argv")"

# 2. canary exit 1: the failing row ids, never an OK row, the script lives
d="$(run_case failed 1 fail)"
expect_line "${d}" "Sandbox: not active: the canary failed: egress-leak,unix-door" "failed"

# 3. timeout
d="$(run_case hang 1 hang)"
expect_line "${d}" "Sandbox: not active: the canary did not finish in 900 s" "hang"

# 4. crash with no rows
d="$(run_case crash 1 crash)"
expect_line "${d}" "Sandbox: not active: the canary failed: it ended with status 139" "crash"

# 5. selftest not ready: the canary is skipped, the selftest reason (printable ASCII only) is the line
d="$(run_case notready 0 pass)"
expect_skipped "${d}" "notready"
line="$(result_line "${d}")"
[[ "${line}" == "Sandbox: not active: the selftest found the private network wrong: "* ]] || fail "notready: ${line}"
[[ "${#line}" -le 340 ]] || fail "notready: line too long"
LC_ALL=C grep -q '[^ -~]' <<<"${line}" && fail "notready: line is not printable ASCII" || true

# 6. SECONDS forced high: skipped with the time reason
d="$(run_case late 1 pass 1650)"
expect_skipped "${d}" "late"
expect_line "${d}" "Sandbox: not active: not enough install time left to run the canary" "late"

# 7. SECONDS partly used: the bound is reduced to 1700 - SECONDS
d="$(run_case reduced 1 pass 1000)"
expect_ran "${d}" "reduced"
bound="$(tr -d 's\n' < "${d}/budget")"
[[ "${bound}" -le 700 && "${bound}" -ge 695 ]] || fail "reduced: bound ${bound}, wanted about 700"
expect_line "${d}" "Sandbox: active" "reduced"

# 8. an unreadable status: a plain reason, no canary, script alive
d="$(run_case garbage 1 garbage)"
expect_skipped "${d}" "garbage"
expect_line "${d}" "Sandbox: not active: the sandbox status could not be read" "garbage"

echo "[TEST] PASS sandbox install canary block 1.18.29"

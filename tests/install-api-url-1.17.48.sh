#!/usr/bin/env bash
# 1.17.48: install.sh and scripts/migrate-layout.sh keep TEC_TAC_API_URL in tec-tac.conf (request "From UI 0.12.113", Johan chose option b).
#
# install.sh needs root, systemd and Tactical, so this test cannot run it. It extracts the config loader, the caller-value capture and the
# config-write section from the scripts by their own text, runs them against a temporary conf, and also asserts on the script text.
# Core only keeps the key. The UI installer owns the address order and the format check.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="${ROOT}/install.sh"
MIGRATE="${ROOT}/scripts/migrate-layout.sh"
HELPER="${ROOT}/scripts/system-update-helper.py"
PY=python3
"${PY}" -c "" >/dev/null 2>&1 || PY=python  # a Windows host can have a python3 stub that does not run
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
fail() { echo "[TEST] FAIL: $*" >&2; exit 1; }
ok() { echo "       $*"; }

bash -n "${INSTALL}" || fail "bash -n install.sh"
bash -n "${MIGRATE}" || fail "bash -n migrate-layout.sh"
ok "bash -n passes on install.sh and scripts/migrate-layout.sh"

# ------------------------------------------------------------------------------------------------ extract the pieces by their text
line_of() { grep -n -F -m1 -- "$2" "$1" | cut -d: -f1; }

LOADER_START="$(line_of "${INSTALL}" 'load_tec_tac_config() {')"
CAPTURE_START="$(line_of "${INSTALL}" 'CALLER_API_URL="${TEC_TAC_API_URL-}"')"
[[ -n "${LOADER_START}" && -n "${CAPTURE_START}" ]] || fail "install.sh: loader or caller capture not found"
# the loader runs from its first line to the first closing brace in column 0
LOADER_END="$(awk -v s="${LOADER_START}" 'NR>s && /^}/ {print NR; exit}' "${INSTALL}")"
# the capture block runs from the capture line to the "fi" that follows the load
CAPTURE_END="$(awk -v s="${CAPTURE_START}" 'NR>s && /^fi$/ {print NR; exit}' "${INSTALL}")"
sed -n "${LOADER_START},${LOADER_END}p" "${INSTALL}" > "${TMP}/loader.sh"
sed -n "${CAPTURE_START},${CAPTURE_END}p" "${INSTALL}" > "${TMP}/capture.sh"
grep -q 'load_tec_tac_config "${TEC_TAC_CONFIG_FILE}" || exit 1' "${TMP}/capture.sh" || fail "the capture block does not contain the load"
[[ "${CAPTURE_START}" -lt "$(line_of "${INSTALL}" 'load_tec_tac_config "${TEC_TAC_CONFIG_FILE}" || exit 1')" ]] || fail "the caller value is not captured before the config is loaded"

WRITE_START="$(line_of "${INSTALL}" 'for config_value in \')"
WRITE_END="$(line_of "${INSTALL}" 'chmod 0644 "${MODULE_CONFIG}"')"
[[ -n "${WRITE_START}" && -n "${WRITE_END}" && "${WRITE_START}" -lt "${WRITE_END}" ]] || fail "install.sh: config write section not found"
sed -n "${WRITE_START},${WRITE_END}p" "${INSTALL}" > "${TMP}/write.sh"

M_START="$(line_of "${MIGRATE}" 'mkdir -p "${CONFIG_DIR}"')"
M_END="$(line_of "${MIGRATE}" 'chmod 0644 "${CONFIG_FILE}"')"
[[ -n "${M_START}" && -n "${M_END}" && "${M_START}" -lt "${M_END}" ]] || fail "migrate-layout.sh: config write section not found"
sed -n "${M_START},${M_END}p" "${MIGRATE}" > "${TMP}/migrate-write.sh"

VARS="TEC_TAC_ROOT TEC_TAC_SOURCE_ROOT SOURCE_ROOT TEC_TAC_UI_SOURCE FRAMEWORK_DIR EXTENSIONS_DIR REPORTSETS_DIR RUNTIME_SCRIPTS_DIR MODULE_STATE_ROOT TRUSTED_PUBLISHERS_ROOT TEC_TAC_UI_ROOT TACTICAL_ROOT BACKEND_DIR VENV_PYTHON TACTICAL_USER TEC_TAC_INSTALLATION_ID"
MVARS="RUNTIME_ROOT SOURCE_ROOT FRAMEWORK_SOURCE UI_SOURCE STATE_ROOT UI_DEPLOY_ROOT TACTICAL_ROOT BACKEND_ROOT TACTICAL_PYTHON CONFIG_DIR"

# run_install <conf text or "-" for no file> <env value or "-" for unset>   -> exit status; the conf is TMP/etc/tec-tac.conf
run_install() {
    local conf="$1" envval="$2"
    rm -rf "${TMP}/etc"; mkdir -p "${TMP}/etc"
    if [[ "${conf}" != "-" ]]; then printf '%s' "${conf}" > "${TMP}/etc/tec-tac.conf"; fi
    {
        echo 'set -euo pipefail'
        echo "TEC_TAC_CONFIG_FILE='${TMP}/etc/tec-tac.conf'"
        for v in ${VARS}; do echo "${v}=/x/${v}"; done
        echo "TEC_TAC_UI_ROOT=/x/ui"
        cat "${TMP}/loader.sh" "${TMP}/capture.sh"
        echo "MODULE_CONFIG='${TMP}/etc/tec-tac.conf'"
        echo 'chown() { :; }; chmod() { :; }'
        echo 'fail() { printf "[TEC-TAC] ERROR: %s\n" "$*" >&2; exit 1; }'
        cat "${TMP}/write.sh"
    } > "${TMP}/harness.sh"
    if [[ "${envval}" == "-" ]]; then
        env -u TEC_TAC_API_URL bash "${TMP}/harness.sh" > "${TMP}/out.txt" 2>&1
    else
        TEC_TAC_API_URL="${envval}" bash "${TMP}/harness.sh" > "${TMP}/out.txt" 2>&1
    fi
}
api_lines() { grep -c '^TEC_TAC_API_URL=' "${TMP}/etc/tec-tac.conf" || true; }
api_value() { grep '^TEC_TAC_API_URL=' "${TMP}/etc/tec-tac.conf" | head -1 | cut -d= -f2-; }

# 1. no env and no key: no line
run_install - - || fail "first install without a URL failed: $(cat "${TMP}/out.txt")"
[[ "$(api_lines)" == 0 ]] || fail "a TEC_TAC_API_URL line was written with no value"
cp "${TMP}/etc/tec-tac.conf" "${TMP}/baseline.conf"
grep -q '^TEC_TAC_ROOT=' "${TMP}/baseline.conf" && grep -q '^UI_REPOSITORY=' "${TMP}/baseline.conf" || fail "the baseline conf lost its keys"
ok "no env and no key in the conf: no TEC_TAC_API_URL line"

# 2. a key in the conf survives a rewrite unchanged
run_install $'TEC_TAC_API_URL=https://api.example.com/x?a=1&b=$HOME\n' - || fail "rewrite with a conf key failed: $(cat "${TMP}/out.txt")"
[[ "$(api_lines)" == 1 && "$(api_value)" == 'https://api.example.com/x?a=1&b=$HOME' ]] || fail "the conf key did not survive: $(api_value)"
ok "a key in the conf survives a rewrite unchanged (shell characters stay literal)"

# 3. the env value on a first install is written
run_install - 'https://tec.example.com' || fail "first install with env failed: $(cat "${TMP}/out.txt")"
[[ "$(api_lines)" == 1 && "$(api_value)" == 'https://tec.example.com' ]] || fail "the env value was not written"
ok "the env value on a first install is written"

# 4. the env value wins over a different conf value
run_install $'TEC_TAC_API_URL=https://old.example.com\n' 'https://new.example.com' || fail "env over conf failed"
[[ "$(api_lines)" == 1 && "$(api_value)" == 'https://new.example.com' ]] || fail "the caller did not win: $(api_value)"
ok "the env value wins over a different conf value (the caller wins, as in the UI installer)"

# 5. CR or LF is refused before the conf is touched
for bad in $'https://a.example.com\rX' $'https://a.example.com\nTEC_TAC_ROOT=/evil'; do
    run_install $'TEC_TAC_ROOT=/keep\n' "${bad}" && fail "a value with CR or LF was accepted"
    grep -q 'may not contain CR/LF' "${TMP}/out.txt" || fail "the refusal message is missing: $(cat "${TMP}/out.txt")"
    [[ "$(cat "${TMP}/etc/tec-tac.conf")" == 'TEC_TAC_ROOT=/keep' ]] || fail "the conf was touched by a refused value"
done
run_install $'TEC_TAC_API_URL=https://a.example.com\r\n' - && fail "a CR in the conf value was accepted"
grep -q 'may not contain CR/LF' "${TMP}/out.txt" || fail "a CR in the conf value gave no refusal message"
ok "a value with CR or LF is refused with the same message before the conf is touched"

# 6. the rest of the conf is unchanged by the key
run_install - 'https://tec.example.com' || fail "run with URL"
grep -v '^TEC_TAC_API_URL=' "${TMP}/etc/tec-tac.conf" > "${TMP}/without.conf"
cmp -s "${TMP}/without.conf" "${TMP}/baseline.conf" || fail "the other keys changed: $(diff "${TMP}/without.conf" "${TMP}/baseline.conf" | head -5)"
[[ "$(grep -c '' "${TMP}/etc/tec-tac.conf")" == "$(( $(grep -c '' "${TMP}/baseline.conf") + 1 ))" ]] || fail "exactly one line must be added"
ok "every existing key is written as before; exactly one line is added"

# script text: mode and owner stay, the line is written as data and never sourced
CHOWN_L="$(line_of "${INSTALL}" 'chown root:root "${MODULE_CONFIG}"')"
PRINTF_L="$(line_of "${INSTALL}" "printf 'TEC_TAC_API_URL=%s\\n' \"\${TEC_TAC_API_URL}\" >> \"\${MODULE_CONFIG}\"")"
[[ -n "${PRINTF_L}" && -n "${CHOWN_L}" && "${PRINTF_L}" -lt "${CHOWN_L}" ]] || fail "the TEC_TAC_API_URL line is not appended before the chown"
grep -q 'chmod 0644 "${MODULE_CONFIG}"' "${INSTALL}" || fail "mode 0644 is gone"
[[ "$(grep -c -F 'TEC_TAC_API_URL=${' "${INSTALL}")" == 0 ]] || fail "the key is expanded inside an unquoted heredoc"
if grep -nE '^[[:space:]]*(source|\.)[[:space:]].*(MODULE_CONFIG|TEC_TAC_CONFIG_FILE)' "${INSTALL}" "${MIGRATE}"; then fail "the conf is sourced"; fi
ok "the line is appended with printf as data, before chown root:root and chmod 0644, and the conf is never sourced"

# ------------------------------------------------------------------------------------------------ migrate-layout.sh
run_migrate() {
    local conf="$1" envval="$2"
    rm -rf "${TMP}/m"; mkdir -p "${TMP}/m"
    if [[ "${conf}" != "-" ]]; then printf '%s' "${conf}" > "${TMP}/m/tec-tac.conf"; fi
    {
        echo 'set -euo pipefail'
        for v in ${MVARS}; do echo "${v}=/x/${v}"; done
        echo "CONFIG_DIR='${TMP}/m'"
        echo "CONFIG_FILE='${TMP}/m/tec-tac.conf'"
        echo 'chown() { :; }; chmod() { :; }'
        echo "log() { :; }; clone_local_repo() { :; }"
        echo "fail(){ printf '[TEC-TAC-LAYOUT] ERROR: %s\n' \"\$*\" >&2; exit 1; }"
        cat "${TMP}/migrate-write.sh"
    } > "${TMP}/mharness.sh"
    if [[ "${envval}" == "-" ]]; then
        env -u TEC_TAC_API_URL bash "${TMP}/mharness.sh" > "${TMP}/mout.txt" 2>&1
    else
        TEC_TAC_API_URL="${envval}" bash "${TMP}/mharness.sh" > "${TMP}/mout.txt" 2>&1
    fi
}
m_lines() { grep -c '^TEC_TAC_API_URL=' "${TMP}/m/tec-tac.conf" || true; }
m_value() { grep '^TEC_TAC_API_URL=' "${TMP}/m/tec-tac.conf" | head -1 | cut -d= -f2-; }

run_migrate - - || fail "migrate without a URL failed: $(cat "${TMP}/mout.txt")"
[[ "$(m_lines)" == 0 ]] || fail "migrate wrote a line with no value"
run_migrate $'TEC_TAC_ROOT=/old\nTEC_TAC_API_URL=https://old.example.com\nTEC_TAC_API_URL=https://second.example.com\n' - || fail "migrate with old conf failed"
[[ "$(m_lines)" == 1 && "$(m_value)" == 'https://old.example.com' ]] || fail "migrate lost the old key: $(m_value)"
grep -q '^TEC_TAC_ROOT=/x/RUNTIME_ROOT$' "${TMP}/m/tec-tac.conf" || fail "migrate no longer rewrites the layout keys"
run_migrate $'TEC_TAC_API_URL=https://old.example.com\n' 'https://env.example.com' || fail "migrate with env failed"
[[ "$(m_lines)" == 1 && "$(m_value)" == 'https://env.example.com' ]] || fail "migrate: the env value must win: $(m_value)"
run_migrate - 'https://env.example.com' || fail "migrate first run with env failed"
[[ "$(m_value)" == 'https://env.example.com' ]] || fail "migrate did not write the env value"
for bad in $'https://a.example.com\rX' $'https://a.example.com\nTEC_TAC_ROOT=/evil'; do
    run_migrate $'TEC_TAC_ROOT=/keep\n' "${bad}" && fail "migrate accepted CR or LF"
    [[ "$(cat "${TMP}/m/tec-tac.conf")" == 'TEC_TAC_ROOT=/keep' ]] || fail "migrate touched the conf for a refused value"
done
run_migrate $'TEC_TAC_API_URL=https://a.example.com\r\n' - && fail "migrate accepted a CR from the old conf"
ok "migrate-layout.sh keeps the key from the old conf and from the env (env wins), writes nothing for no value, refuses CR/LF before the rewrite"

# ------------------------------------------------------------------------------------------------ the helpers are unchanged
"${PY}" -I - "${HELPER}" <<'PYEOF' || fail "privileged_env no longer strips TEC_TAC_*"
import ast, os, sys
source = open(sys.argv[1], encoding="utf-8").read()
tree = ast.parse(source)
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "privileged_env")
ns = {"os": os}
exec(compile(ast.Module([fn], []), "privileged_env", "exec"), ns)
os.environ["TEC_TAC_API_URL"] = "https://caller.example.com"
os.environ["TEC_TAC_ROOT"] = "/evil"
os.environ["PATH_KEPT"] = "yes"
env = ns["privileged_env"]({"TEC_TAC_EXTRA": "x"})
assert "TEC_TAC_API_URL" not in env and "TEC_TAC_ROOT" not in env, env.keys()
assert env["PATH_KEPT"] == "yes" and env["TEC_TAC_EXTRA"] == "x"
PYEOF
grep -q 'opt/tec-tac/etc/' "${ROOT}/scripts/server-backup-helper.py" || fail "server-backup-helper.py no longer restores opt/tec-tac/etc/"
ok "system-update-helper privileged_env still strips every TEC_TAC_* variable; the backup restore still extracts opt/tec-tac/etc/"

grep -q 'TEC_TAC_API_URL' "${ROOT}/README.md" || fail "README does not document the key"
ok "the README documents the key"
echo "[TEST] PASS install API URL 1.17.48"

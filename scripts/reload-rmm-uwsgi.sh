#!/usr/bin/env bash
set -euo pipefail

SERVICE="${TEC_TAC_RMM_SERVICE:-rmm}"
TIMEOUT="${TEC_TAC_UWSGI_RELOAD_TIMEOUT:-60}"

log()  { printf '[TEC-TAC] %s\n' "$*"; }
fail() { printf '[TEC-TAC] ERROR: %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || fail "Run this reload helper as root."
systemctl is-active --quiet "${SERVICE}" || fail "${SERVICE} is not active."

MASTER_PID="$(systemctl show "${SERVICE}" -p MainPID --value)"
[[ "${MASTER_PID}" =~ ^[0-9]+$ ]] || fail "Could not determine ${SERVICE} MainPID."
[[ "${MASTER_PID}" -gt 1 ]] || fail "Invalid ${SERVICE} MainPID: ${MASTER_PID}"
[[ -r "/proc/${MASTER_PID}/cmdline" ]] || fail "${SERVICE} MainPID ${MASTER_PID} is not running."

CMDLINE="$(tr '\0' ' ' < "/proc/${MASTER_PID}/cmdline")"
[[ "${CMDLINE}" == *uwsgi* ]] || fail "${SERVICE} MainPID ${MASTER_PID} does not appear to be uWSGI: ${CMDLINE}"

children() {
    pgrep -P "$1" 2>/dev/null | sort -n | tr '\n' ' ' || true
}

BEFORE_CHILDREN="$(children "${MASTER_PID}")"
log "Gracefully reloading Tactical Django via uWSGI SIGHUP (master PID ${MASTER_PID})."
kill -HUP "${MASTER_PID}"

DEADLINE=$((SECONDS + TIMEOUT))
while (( SECONDS < DEADLINE )); do
    sleep 1
    systemctl is-active --quiet "${SERVICE}" || continue
    CURRENT_PID="$(systemctl show "${SERVICE}" -p MainPID --value)"
    [[ "${CURRENT_PID}" =~ ^[0-9]+$ ]] || continue
    [[ "${CURRENT_PID}" -gt 1 ]] || continue
    [[ -r "/proc/${CURRENT_PID}/cmdline" ]] || continue
    AFTER_CHILDREN="$(children "${CURRENT_PID}")"
    if [[ -n "${AFTER_CHILDREN}" && ( "${CURRENT_PID}" != "${MASTER_PID}" || "${AFTER_CHILDREN}" != "${BEFORE_CHILDREN}" ) ]]; then
        log "uWSGI graceful reload completed; active worker set changed."
        exit 0
    fi
done

fail "Timed out after ${TIMEOUT}s waiting for uWSGI workers to reload."

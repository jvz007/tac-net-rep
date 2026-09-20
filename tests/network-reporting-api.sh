#!/usr/bin/env bash
set -euo pipefail

: "${TEC_TAC_API_BASE:?Set TEC_TAC_API_BASE, e.g. https://api.example.com}"
: "${TEC_TAC_API_KEY:?Set TEC_TAC_API_KEY to a Tactical API key with tfdreporting.networkavailability.manage}"

BASE="${TEC_TAC_API_BASE%/}"
URL="${BASE}/api/tfd/reporting/network-availability/"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
FUTURE="$(date -u -d '+20 minutes' +%Y-%m-%dT%H:%M:%SZ)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

request() {
    local name="$1" expected="$2" payload="$3"
    local headers="$TMP/${name}.headers" body="$TMP/${name}.body"
    local status
    status="$(curl -sS -D "$headers" -o "$body" -w '%{http_code}' \
        -H "X-API-KEY: ${TEC_TAC_API_KEY}" \
        -H 'Content-Type: application/json' \
        -X POST "$URL" \
        --data "$payload")"
    if [[ "$status" == "$expected" ]]; then
        printf '[TEST] PASS %-24s HTTP %s\n' "$name" "$status"
        pass=$((pass + 1))
    else
        printf '[TEST] FAIL %-24s expected %s got %s\n' "$name" "$expected" "$status" >&2
        cat "$body" >&2 || true
        fail=$((fail + 1))
    fi
}

KEY="tec-tac-${RUN_ID}"
VALID="{\"client_name\":\"Tec-Tac Test\",\"site_name\":\"POC\",\"device_name\":\"test-device-${RUN_ID}\",\"source\":\"tec-tac-test\",\"timestamp\":\"${NOW}\",\"status\":\"up\",\"availability_pct\":100,\"latency_ms\":1.250,\"packet_loss_pct\":0,\"idempotency_key\":\"${KEY}\"}"

request valid_ingest 201 "$VALID"
request exact_replay 200 "$VALID"
if grep -qi '^X-TFD-Idempotent-Replay:[[:space:]]*true' "$TMP/exact_replay.headers"; then
    printf '[TEST] PASS %-24s header present\n' "replay_header"
    pass=$((pass + 1))
else
    printf '[TEST] FAIL %-24s missing X-TFD-Idempotent-Replay: true\n' "replay_header" >&2
    fail=$((fail + 1))
fi

CONFLICT="{\"client_name\":\"Tec-Tac Test\",\"site_name\":\"POC\",\"device_name\":\"DIFFERENT\",\"source\":\"tec-tac-test\",\"timestamp\":\"${NOW}\",\"status\":\"up\",\"idempotency_key\":\"${KEY}\"}"
request conflicting_replay 409 "$CONFLICT"
request bad_status 400 "{\"client_name\":\"Tec-Tac Test\",\"site_name\":\"POC\",\"device_name\":\"test\",\"source\":\"tec-tac-test\",\"timestamp\":\"${NOW}\",\"status\":\"broken\"}"
request negative_latency 400 "{\"client_name\":\"Tec-Tac Test\",\"site_name\":\"POC\",\"device_name\":\"test\",\"source\":\"tec-tac-test\",\"timestamp\":\"${NOW}\",\"status\":\"up\",\"latency_ms\":-1}"
request availability_over_100 400 "{\"client_name\":\"Tec-Tac Test\",\"site_name\":\"POC\",\"device_name\":\"test\",\"source\":\"tec-tac-test\",\"timestamp\":\"${NOW}\",\"status\":\"up\",\"availability_pct\":101}"
request packet_loss_over_100 400 "{\"client_name\":\"Tec-Tac Test\",\"site_name\":\"POC\",\"device_name\":\"test\",\"source\":\"tec-tac-test\",\"timestamp\":\"${NOW}\",\"status\":\"up\",\"packet_loss_pct\":101}"
request future_timestamp 400 "{\"client_name\":\"Tec-Tac Test\",\"site_name\":\"POC\",\"device_name\":\"test\",\"source\":\"tec-tac-test\",\"timestamp\":\"${FUTURE}\",\"status\":\"up\"}"

printf '\n[TEST] Summary: %d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]

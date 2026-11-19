#!/usr/bin/env bash
# Runtime check for Core 1.18.24: core.sandbox, the full canary (attack test), with the real root helper, systemd and cgroups.
# 1.18.24 changes from the 1.18.23 script (every step id is kept):
#   * Patch B (AD-65): a run has its own, empty network space and one proxy door. Step 5t is flipped to the Patch B EXIT LIST: the 12 former ATTACK rows
#     (pb-public-tcp-443-1-1-1-1, pb-public-tcp-80-1-1-1-1, pb-public-tcp-443-9-9-9-9, pb-direct-allowed-host-443, pb-dns-resolv-conf-listed,
#     pb-dns-getaddrinfo, pb-dns-listed-server-answers, pb-dns-public-9-9-9-9-answers, pb-proc-net-tcp, pb-proc-net-udp, pb-interfaces-beyond-lo,
#     pb-default-route) must all read OK; the 7 proxy rows (pb-proxy-allowed-443 with a positive 200, pb-proxy-refuse-host, -ip-literal, -private,
#     -own-address, -port-80, -port-22) must all read OK; pb-listener-from-host and pb-ping-socket-echo must read OK; every other row OK; 0 NOT RUN;
#     0 ATTACK SUCCEEDED; a SKIPPED row only where the host has no control for THAT row (pb-tcp-443-ipv6 on a server with no IPv6 route);
#   * the guards need the installed helper to hold PrivateNetwork=yes, the installed egress program and the two template units, and refuse an older
#     installed runner ("update Core first"); the guard that refused AF_UNIX now requires AF_INET AF_UNIX; the resolv_conf_bind marker is gone;
#   * step 4: the four 'unix socket creation refused' rows are retired, the new row 'unix door path without a door' must read OK; the dns and public
#     rows are retired (the network group covers them); no row of the normal table may be SKIPPED;
#   * step 2 prints the network_private and egress_proxy rows of the selftest; the audit check allows the egress keys of run.ended and, after 5t, 5u
#     proves that the run with a door wrote run.egress BEFORE run.ended; 5v proves no egress unit or door folder is left;
#   * mode `network`: the guards, the selftest and step 5t only. Run it with:  sudo bash tests/sandbox-canary-1.18.24.sh network
# Enforcement, unit properties and the kill switch: the switch stays OFF and is never touched here.
# 1.18.23 changes from the 1.18.22 script (every earlier step and check is kept):
#   * canary rows first for Patch B (AD-65): new step 5t runs the Patch B network rows (tests/sandbox-canary-network-1.18.23.py, which starts the group
#     patchb_network of the installed canary runner through the helper's own launch). Before Patch B the rows that Patch B changes must show ATTACK
#     SUCCEEDED, the rows that already hold must show OK (they become regression guards) and the seven proxy rows must show NOT RUN (no proxy yet).
#     Step 5t passes when the table is as expected; it fails when an expected-OK row shows ATTACK SUCCEEDED (a real hole today), when an
#     expected-ATTACK row shows OK (the row proves nothing) or when a row other than a proxy row is NOT RUN. These rows are not counted by 4k, 4l and
#     4m (they come from a separate output file);
#   * new mode `network`: the guards, the selftest and step 5t only (about 1 to 2 minutes);
#   * the helper guard also needs the installed canary runner to hold patchb_network (an older runner is refused: update Core first) and refuses a
#     helper that already has PrivateNetwork=yes (this is the before-Patch-B run);
#   * after the usual verdict line the script prints the expected-before-Patch-B list.
# Enforcement, unit properties and the kill switch are unchanged from 1.18.22.
# 1.18.22 changes from the 1.18.17 script (every earlier step is kept):
#   * the helper guard also needs the marker detail_lines (a helper from before 1.18.22 is refused);
#   * step 4u reads the DETAIL line of the memory row (`DETAIL memory-beyond-memorymax <full actual text>`): the table cuts the actual column at
#     140 characters, so the '; proof: ...' never reached the grep. 4u passes on a named proof OR on 'ended oom' + 'unit result oom-kill' +
#     'evidence unit_result' (step 4h still needs the row to end OK, so NOT RUN and ATTACK SUCCEEDED never pass);
#   * the counters of 4k, 4l and 4m ignore DETAIL lines like ROW lines.
# 1.18.17 changes from the 1.18.16 script (every earlier step is kept):
#   * the helper guard also needs the markers read_unit_result and reset_failed_units (a helper from before 1.18.17 is refused);
#   * step 4u accepts the memory row when its text names `proof: systemd unit result oom-kill` (the run unit is no longer collected, the helper
#     reads systemd's own Result; the row shows `killed by signal 9` and `unit result oom-kill`, not systemd-run's `exit 1`);
#   * new step 5r: the plain systemd-run allocation loop from the dev02 diagnostic, started WITHOUT --collect as tectac-plantest-<hex>, must end
#     with Result=oom-kill, ExecMainCode 2 (killed) and ExecMainStatus 9, and the unit is then reset with reset-failed;
#   * new step 5s: after the canary and one --sweep, `systemctl list-units --state=failed 'tectac-*'` is empty (no run unit is left failed).
# 1.18.16 changes from the 1.18.15 script (every earlier step is kept):
#   * the helper guard also needs the markers memory_events and parse_run_seen (a helper from before 1.18.16 is refused);
#   * step 4u accepts the memory row when its text names its proof: `proof: oom_kill N (memory.events)`, `proof: memory.events max N, peak X MiB
#     <= Y MiB` or `proof: probe MemoryError at N MiB` (the row also prints the kernel counters and the probe's first stderr line);
#   * step 5o also fails when one run id has two run.ended rows (the sweep no longer writes a second one);
#   * step 4v is unchanged; the next run now answers `CANARYRUNSEEN 1|0` instead of listing /run, and the step never reads a listing.
# 1.18.15 changes from the 1.18.14 script (every earlier step is kept):
#   * the canary prints, after the table, one machine line per row `ROW <id> <verdict>`; every step 4x verdict is read from those lines by id
#     (the printed label is cut at 60 characters, an id is not: step 4t failed on a row that was OK); the table stays for people and for the
#     steps that check what a row says (the MiB, the oom_kills, the listener counts);
#   * new step 4v: the row `write /run` is OK and says `private per-run /run` (the marker the probe left in /run is not in the skeleton and
#     not seen by the next run); new step 5q: no marker file is in the skeleton's run/ folder;
#   * step 5o accepts a `run.ended` with reason `swept` (the run the canary kills the helper of) and prints how many swept rows it saw;
#   * new step 5p: no `run.credentials_lingered` row in the audit rows of this run (a healthy server shows none);
#   * the memory probe allocates in 4 MiB steps up to twice MemoryMax and names a refused allocation (`MemoryError at N MiB`).
# 1.18.14 changes from the 1.18.8 script (every earlier step is kept): the helper guard also needs remove_credentials_when_active; no unit
# property runs a command any more (the `+` commands could not see the host on systemd 255), so the helper removes the credential folder itself
# and the memory evidence comes only from its own cgroup poll; step 4 now also shows the rows "credential source folder is gone while the run is
# still active" and "no host command property on the live unit"; step 5 still needs secrets, handoff and runs empty after the runs.
# 1.18.8 changes from the 1.17.124 script (every earlier step is kept):
#   * a `before` mode: `sudo bash tests/sandbox-canary-1.18.16.sh before` runs the new rootview and marker rows against the INSTALLED 1.18.7
#     (it installs nothing and never touches the kill switch; see tests/sandbox-canary-1.18.8-before.py);
#   * the helper guard needs the 1.18.8 markers (RootDirectory=, view_plan, rootview, run.started, CgroupWatch, SANDBOX_ROOT) and refuses an
#     installed helper without them;
#   * step 1 also checks the sandbox root folder (root 0755), step 2 prints the sandbox_root row, step 4 needs the rootview rows (one per
#     folder and `/ lists only the allowed set`), the stand-in folder marker row, the credential rows, and a memory row that shows the kernel's
#     oom_kills or a refused allocation; step 5 checks the root audit log (run.started and run.ended for the canary runs, no credential, no input,
#     no output, no path) and that no /tectac-canary-* folder is left.
# It did NOT run on the development PC (it needs root, systemd, cgroup v2 and a Linux server): the dev02 run is the proof.
# Runtime check for Core 1.17.124: core.sandbox Patch 2, the full canary (attack test), with the real root helper, systemd and cgroups.
# 1.17.124 changes from the 1.17.123 script: the helper guard also needs the new markers (CANARYEND, oom_kills, fit_abstract_names) and refuses
# an installed helper that still says 'AF_INET AF_UNIX'; step 2 prints, as information, the unit's RestrictAddressFamilies value and the host's
# abstract listener names (names only); step 4 needs the new rows: 'unix socket creation refused' for stream, dgram and seqpacket, 'unix pathname
# socket refused', the three positive controls (socketpair round trip, pipe round trip, child process with stdio pipes), the abstract row with its
# listed and left-out counts, the memory row with its MiB, how it ended, oom_kills and the peak, and loopback 127.0.0.53 on all six ports; it
# still needs 0 ATTACK SUCCEEDED, 0 NOT RUN and no security row SKIPPED (only 'public tcp 443' may be). The padding-safe patterns are kept. It
# never enables the kill switch and holds no real secret. 1.18.14: there is no ExecStopPost and no finish_run; the memory row's oom_kills and
# peak come only from the helper's live cgroup poll (the old --finish never ran on dev02).
# SEND BACK THE WHOLE OUTPUT of this script, passed or not.
# 1.17.123 changes from the 1.17.122 script: the helper guard needs the new markers (MemoryZSwapMax, local_deny, parse_abstract_sockets,
# resolv_conf_bind) and refuses an older installed helper; step 2 prints the selftest rows for the resolvers (the upstream list and Core's own
# resolv.conf), this server's own addresses and its gateway, and the memory property choice, as information; step 4 checks that the table has
# the new rows (own address tcp 22/80/443 and udp, gateway tcp and udp, loopback 127.0.0.53 on the six ports, the memory row with its MiB, the
# abstract row with its count, the credential frame row) and that 0 rows are ATTACK SUCCEEDED, 0 are NOT RUN and no security row is SKIPPED
# (only 'public tcp 443' may be); it prints the host's abstract listener names (names only, no content) and the upstream resolvers as
# information. Steps 1, 2c, 3, 5 and 6 are as in 1.17.122, the padding-safe patterns are kept. It never enables the kill switch and holds no
# real secret.
# 1.17.122 changes from the 1.17.121 script: the helper guard also needs the credential ACL decoder (_PROBE_ACL); step 2 prints the credential
# row of the selftest on its own line (owner, group, mode and every ACL entry of the file); the shell patterns that read the attack table are
# padding-safe: 4d is grep -Eq 'OK[[:space:]]*$' on the row picked out by its exact attack text, and the three awk counters end in
# [[:space:]]*$ (the 1.17.121 pattern 'OK$' could never match a row that format_table padded). Everything else is as in 1.17.121.
# 1.17.121 changes from the 1.17.120 script: the helper guard also needs the credential pre-check (MISSING / _credential_file_ready); step 4 gains
# check 4d: the row 'another dynamic user reads the credential file' must end with OK (not NOT RUN, not ATTACK SUCCEEDED). Everything else is as in 1.17.120.
# 1.17.120 changes from the 1.17.118 script: the helper guard also needs the numeric address list; step 2 prints the DNS detail, the upstream
# resolvers and the bpf_framework row as information; step 2c proves the helper's own '$' escape against real systemd and prints how '%' arrives;
# step 4 also needs the row "another dynamic user reads the credential file". The kill switch stays OFF and is never touched here.
# It did NOT run on the development PC (it needs root, systemd, cgroup v2 and a Linux server). DEV SERVER ONLY, as root, after Core 1.18.24
# is installed. The kill switch is still OFF: this script proves it stays off and then runs the canary through the root-only path.
#
#   sudo bash tests/sandbox-canary-1.18.24.sh            (after Core 1.18.24 is installed: the full canary and step 5t, the Patch B exit list)
#   sudo bash tests/sandbox-canary-1.18.24.sh network    (the guards, the selftest and step 5t only)
#   sudo bash tests/sandbox-canary-1.18.24.sh before     (before the update, against the installed 1.18.7: the new rows must show ATTACK SUCCEEDED)
#
# It runs about 3 to 6 minutes (the latency step starts 50 runs, the cancel step waits on units). Run it when no module install, upgrade
# or Core update is running. It prints PASS or FAIL for each step and ends with ALL CANARY STEPS PASSED, or the number of steps that
# failed (exit 1). The attack table is printed in full: send ALL of it back, passed or not.
#
# What to send back after a FAIL: the whole output of this script, plus `sudo /usr/local/sbin/tec-tac-sandbox --status`,
# `cat /var/lib/tec-tac/sandbox/canary.json`, `cat /var/lib/tec-tac/sandbox/status.json`, `systemctl --version`, `uname -r`,
# `cat /etc/os-release`, `cat /etc/resolv.conf`, `ip -o addr show`, `ip route show default` and the last 40 lines of /var/lib/tec-tac/sandbox/audit.jsonl.
# A row that says ATTACK SUCCEEDED is a real hole: do not turn the sandbox on, send the row. A row that says NOT RUN means a probe could
# not run (read its text); it fails the canary too. SKIPPED (for example no public route) is shown, never counted as a pass.
# Nothing here holds a real secret: the canary uses random dummy tokens that exist only for the run.
set -u

HELPER=/usr/local/sbin/tec-tac-sandbox
STATE=/var/lib/tec-tac/sandbox
LIB=/usr/local/lib/tec-tac/sandbox
RUN=/run/tec-tac/sandbox
FAILS=0
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
MODE=${1:-full}

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS + 1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
# 1.18.15: the id of a table label (same rule as the helper's row_slug: lower case, other runs of characters become one '-', at most 40 characters)
slug() { printf '%s' "$1" | tr 'A-Z' 'a-z' | sed -e 's/[^a-z0-9][^a-z0-9]*/-/g' -e 's/^-//' -e 's/-$//' | cut -c1-40 | sed -e 's/-$//'; }
row_ok() { grep -Fxq "ROW $1 OK" "$CANARY_OUT"; }
row_ok_label() { row_ok "$(slug "$1")"; }
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); k=sys.argv[1].split(".");
for p in k: d=d[p]
print(d)' "$1" 2>/dev/null; }
# 1.18.24: step 5t, the Patch B exit list. A function, so the `network` mode and the full run use the same lines. The rows come from a separate output
# file (NET_OUT), so the counters of 4k, 4l and 4m never see them. Exit 0 of the driver: every row is OK (a row may be SKIPPED only where the host has no
# control for that row).
network_step_5t() {
  echo "== step 5t: the Patch B exit list: the 12 former ATTACK rows OK, the 7 proxy rows OK (positive control 200), 0 NOT RUN, 0 ATTACK SUCCEEDED"
  [ -f "$SCRIPT_DIR/sandbox-canary-network-1.18.24.py" ] || { fail "5t the driver tests/sandbox-canary-network-1.18.24.py is not next to this script (copy the whole tests folder)"; return; }
  NET_AUDIT_BEFORE=$(wc -l < "$STATE/audit.jsonl" 2>/dev/null || echo 0)
  NET_OUT=$(mktemp)
  python3 "$SCRIPT_DIR/sandbox-canary-network-1.18.24.py" >"$NET_OUT" 2>&1
  NET_RC=$?
  cat "$NET_OUT"
  if [ "$NET_RC" -eq 0 ]; then pass "5t the Patch B exit list: every network row is OK (the 12 former ATTACK rows, the 7 proxy rows, the listener and ping rows)"; else fail "5t the Patch B exit list is not met (driver exit $NET_RC: read the FAIL lines above; ATTACK SUCCEEDED is a real hole, NOT RUN means a probe or the proxy door did not work)"; fi
  rm -f "$NET_OUT"
  # 5u: the run with a door wrote its egress audit row BEFORE run.ended, and the egress counts are numbers
  NET_AUDIT=$(python3 - "$STATE/audit.jsonl" "$NET_AUDIT_BEFORE" <<'PY'
import json, sys
path, skip = sys.argv[1], int(sys.argv[2])
rows = []
for number, line in enumerate(open(path, encoding="utf-8"), 1):
    if number > skip:
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
events = [r.get("event") for r in rows]
problems = []
if "run.egress" not in events:
    problems.append("no run.egress row")
else:
    egress = events.index("run.egress")
    after = [k for k, e in enumerate(events) if e == "run.ended" and k > egress]
    if not after:
        problems.append("no run.ended after run.egress")
    detail = rows[egress].get("detail") or {}
    for key in ("allowed", "refused", "bytes"):
        if not isinstance(detail.get(key), int):
            problems.append("run.egress %s is not a number" % key)
    if detail.get("refused", 0) < 6:
        problems.append("run.egress counts look wrong: refused=%s (the six refusal rows alone make 6)" % detail.get("refused"))
    text = json.dumps(detail)
    if "Authorization" in text or "Bearer" in text:
        problems.append("run.egress holds a header")
    ended = rows[after[0]].get("detail") or {} if after else {}
    for key in ("egress_allowed", "egress_refused", "egress_bytes"):
        if not isinstance(ended.get(key), int):
            problems.append("run.ended %s is not a number" % key)
print("events=%s problems=%d" % (",".join(e for e in events if e in ("run.started", "run.egress", "run.ended")), len(problems)))
for item in problems[:10]:
    print("  " + item)
PY
)
  echo "information: the root audit rows of the exit-list run: $(echo "$NET_AUDIT" | head -1)"
  echo "$NET_AUDIT" | tail -n +2
  echo "$NET_AUDIT" | head -1 | grep -q 'problems=0$' && pass "5u run.egress was written before run.ended for the run with a door, with numbers only" || fail "5u run.egress was written before run.ended for the run with a door, with numbers only (see the lines above)"
  # 5v: nothing is left of the egress door
  LEFT_EGRESS=$(systemctl list-units 'tec-tac-sandbox-egress@*' --all --no-legend --no-pager 2>/dev/null)
  if [ -z "$LEFT_EGRESS" ] && [ -z "$(ls -A "$RUN/egress-door" 2>/dev/null)" ] && [ -z "$(ls -A "$RUN/egress-config" 2>/dev/null)" ] && [ -z "$(ls -A /run/tec-tac-sbx-egress 2>/dev/null)" ]; then pass "5v no egress unit, door folder, configuration or audit state is left"; else echo "$LEFT_EGRESS"; ls -la "$RUN/egress-door" "$RUN/egress-config" /run/tec-tac-sbx-egress 2>&1 | sed 's/^/  /'; fail "5v something of the egress door is left (listed above)"; fi
}
# 1.18.24: the verdict line first, then the Patch B exit list.
finish() {
  echo
  if [ "$FAILS" -eq 0 ]; then echo "ALL CANARY STEPS PASSED"; FINISH_RC=0; else echo "$FAILS STEP(S) FAILED"; FINISH_RC=1; fi
  echo "Patch B exit list (all must be OK, 0 NOT RUN, 0 ATTACK SUCCEEDED): the 12 former ATTACK rows pb-public-tcp-443-1-1-1-1, pb-public-tcp-80-1-1-1-1, pb-public-tcp-443-9-9-9-9, pb-direct-allowed-host-443, pb-dns-resolv-conf-listed, pb-dns-getaddrinfo, pb-dns-listed-server-answers, pb-dns-public-9-9-9-9-answers, pb-proc-net-tcp, pb-proc-net-udp, pb-interfaces-beyond-lo, pb-default-route; the 7 proxy rows pb-proxy-allowed-443, pb-proxy-refuse-host, pb-proxy-refuse-ip-literal, pb-proxy-refuse-private, pb-proxy-refuse-own-address, pb-proxy-refuse-port-80, pb-proxy-refuse-port-22; rows pb-listener-from-host and pb-ping-socket-echo; every other row OK; SKIPPED only where the host has no control for that row (pb-tcp-443-ipv6 on a server with no IPv6 route)"
  echo "full log: send the whole output, passed or not"
  exit "$FINISH_RC"
}

if [ "$(id -u)" -ne 0 ]; then echo "FAIL this script must run as root"; exit 1; fi
if [ "$MODE" != "full" ] && [ "$MODE" != "before" ] && [ "$MODE" != "network" ]; then echo "FAIL unknown mode '$MODE' (use no argument, or: before, network)"; exit 1; fi
[ -x "$HELPER" ] || { echo "FAIL the root helper is missing at $HELPER (is Core installed?)"; exit 1; }
grep -q 'SANDBOX_ENABLED = False' "$HELPER" || { echo "FAIL the installed helper has no off kill switch constant"; exit 1; }
if [ "$MODE" = "before" ]; then
  # The before run installs nothing and never enables the sandbox: it takes the unit properties of the INSTALLED helper (Core 1.18.7) and runs
  # the new 1.18.8 rows in a unit built exactly like a 1.18.7 run. The 1.18.8 source tree is the folder above tests/ (copy tests/ and scripts/).
  [ -f "$SOURCE_DIR/scripts/sandbox-helper.py" ] && [ -f "$SOURCE_DIR/scripts/sandbox-canary-runner.py" ] && [ -f "$SCRIPT_DIR/sandbox-canary-1.18.8-before.py" ] || { echo "FAIL the 1.18.8 files are not next to this script: copy tests/sandbox-canary-1.18.16.sh, tests/sandbox-canary-1.18.8-before.py, scripts/sandbox-canary-runner.py and scripts/sandbox-helper.py keeping the tests/ and scripts/ folders"; exit 1; }
  grep -q 'RootDirectory=' "$HELPER" && { echo "FAIL the installed helper is already Core 1.18.8 or newer: a before run only makes sense against 1.18.7"; exit 1; }
  grep -q -- '--canary' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.118 (no --canary)"; exit 1; }
  echo "== before run: the new rows against the installed helper ($(ls -l "$HELPER" | awk '{print $NF}'))"
  /usr/bin/python3 "$SCRIPT_DIR/sandbox-canary-1.18.8-before.py" "$SOURCE_DIR"
  BEFORE_RC=$?
  if [ "$BEFORE_RC" -eq 0 ]; then echo "PASS before run: the new rows prove something (they fail on the installed Core)"; else echo "FAIL before run: the new rows prove nothing (exit $BEFORE_RC): send the whole output and stop"; fi
  exit "$BEFORE_RC"
fi
grep -q -- '--canary' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.118 (no --canary)"; exit 1; }
grep -q '127.0.0.0/8' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.120 (its address filter is not the numeric list)"; exit 1; }
grep -q '_credential_file_ready' "$HELPER" && grep -q 'MISSING' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.121 (no credential file pre-check)"; exit 1; }
grep -q '_PROBE_ACL' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.122 (no credential ACL check)"; exit 1; }
for marker in MemoryZSwapMax local_deny parse_abstract_sockets egress_start; do
  grep -q "$marker" "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.123 (no $marker)"; exit 1; }
done
for marker in CANARYEND oom_kills fit_abstract_names; do
  grep -q "$marker" "$HELPER" || { echo "FAIL the installed helper is older than Core 1.17.124 (no $marker)"; exit 1; }
done
for marker in 'RootDirectory=' view_plan rootview run.started CgroupWatch SANDBOX_ROOT; do
  grep -q "$marker" "$HELPER" || { echo "FAIL the installed helper is older than Core 1.18.8 (no $marker): update Core first, or run the before mode"; exit 1; }
done
for marker in remove_credentials_when_active in_memory_handoff credential_cleanup_rows; do
  grep -q "$marker" "$HELPER" || { echo "FAIL the installed helper is older than Core 1.18.14 (no $marker): update Core first"; exit 1; }
done
for marker in row_lines remove_credentials_noted note_swept_run table_private_run; do
  grep -q "$marker" "$HELPER" || { echo "FAIL the installed helper is older than Core 1.18.16 (no $marker): update Core first"; exit 1; }
done
for marker in memory_events parse_run_seen; do
  grep -q "$marker" "$HELPER" || { echo "FAIL the installed helper is older than Core 1.18.16 (no $marker): update Core first"; exit 1; }
done
for marker in read_unit_result reset_failed_units; do
  grep -q "$marker" "$HELPER" || { echo "FAIL the installed helper is older than Core 1.18.17 (no $marker): update Core first"; exit 1; }
done
grep -q 'detail_lines' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.18.22 (no detail_lines): update Core first"; exit 1; }
grep -q 'PrivateNetwork=yes' "$HELPER" || { echo "FAIL the installed helper is older than Core 1.18.24 (no PrivateNetwork=yes): update Core first"; exit 1; }
grep -q 'AF_INET AF_UNIX' "$HELPER" || { echo "FAIL the installed helper does not allow AF_UNIX for the egress door (it is older than Core 1.18.24): update Core first"; exit 1; }
grep -q 'patchb_network' "$LIB/canary/sandbox-canary-runner.py" || { echo "FAIL the installed canary runner is older than Core 1.18.23 (no patchb_network): update Core first"; exit 1; }
grep -q 'door_row' "$LIB/canary/sandbox-canary-runner.py" || { echo "FAIL the installed canary runner is older than Core 1.18.24 (no door_row): update Core first"; exit 1; }
[ -f "$LIB/sandbox-egress.py" ] && [ "$(stat -c '%U %a' "$LIB/sandbox-egress.py" 2>/dev/null)" = "root 755" ] || { echo "FAIL the egress program $LIB/sandbox-egress.py is missing or not root-owned 0755: update Core first"; exit 1; }
[ -f /etc/systemd/system/tec-tac-sandbox-egress@.socket ] && [ -f /etc/systemd/system/tec-tac-sandbox-egress@.service ] || { echo "FAIL the egress template units are not installed (/etc/systemd/system/tec-tac-sandbox-egress@.socket and .service): update Core first"; exit 1; }
TACTICAL_USER=$(systemctl show rmm.service -p User --value 2>/dev/null)
[ -n "$TACTICAL_USER" ] || { echo "FAIL could not find the Tactical service user"; exit 1; }

if [ "$MODE" != "network" ]; then
echo "== step 1: what is installed"
echo "systemd: $(systemctl --version | head -1)"
echo "kernel:  $(uname -r)"
echo "os:      $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "resolv:  $(grep -E '^nameserver' /etc/resolv.conf | tr '\n' ' ')"
[ "$(stat -c '%U %a' "$LIB/sandbox-launcher.py" 2>/dev/null)" = "root 755" ] && pass "1a the launcher is root-owned 0755" || fail "1a the launcher is root-owned 0755 ($(stat -c '%U %a' "$LIB/sandbox-launcher.py" 2>&1))"
[ "$(stat -c '%U %a' "$LIB/canary/sandbox-canary-runner.py" 2>/dev/null)" = "root 755" ] && pass "1b the canary runner is root-owned 0755" || fail "1b the canary runner is root-owned 0755"
[ "$(stat -c '%U %a' "$LIB/canary" 2>/dev/null)" = "root 755" ] && pass "1c the canary folder is root-owned 0755" || fail "1c the canary folder is root-owned 0755"
[ "$(stat -c '%U %a' "$LIB/root" 2>/dev/null)" = "root 755" ] && pass "1e the sandbox root folder is root-owned 0755" || fail "1e the sandbox root folder is root-owned 0755 ($(stat -c '%U %a' "$LIB/root" 2>&1))"
echo "information: the sandbox root folder (mount points only; send it back):"
ls -la "$LIB/root" 2>&1 | sed 's/^/  /'
for folder in slots secrets handoff runs; do
  [ "$(stat -c '%U %a' "$RUN/$folder" 2>/dev/null)" = "root 700" ] && pass "1d $RUN/$folder is root 0700" || echo "NOTE $RUN/$folder is created at the first run ($(stat -c '%U %a' "$RUN/$folder" 2>&1))"
done

fi
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
cred = data.get("checks", {}).get("credential", {})
print("information: credential row (owner, group, mode, ACL as found): %s | %s" % ("yes" if cred.get("ok") else "NO", cred.get("detail", "")))
for key in ("sandbox_root", "filesystem_view", "network_private", "egress_proxy", "local_addresses", "memory_zswap"):
    row = data.get("checks", {}).get(key, {})
    print("information: %s row: %s | %s" % (key, "yes" if row.get("ok") else "NO", row.get("detail", "(no such row: is the helper older than Core 1.18.8?)")))
print("ready=%s reason=%s resolver=%s resolvers=%s dns_method=%s slots_total=%s" % (data.get("ready"), data.get("reason"), data.get("resolver"), ",".join(data.get("resolvers", [])), data.get("dns_method"), data.get("slots_total")))
print("information: selftest time %s ms (9 probe units and the egress proxy check; send it back, the install-speed request depends on it)" % data.get("selftest_ms"))
PY
rm -f "$SELFTEST_OUT"
echo "information: the upstream resolvers systemd-resolved forwards to (/run/systemd/resolve/resolv.conf, read only; the egress proxy resolves names on the host through the stub 127.0.0.53):"
cat /run/systemd/resolve/resolv.conf 2>&1 | grep -E '^(nameserver|search|options)' || echo "  (not readable or none listed)"
echo "information: the network_private and egress_proxy rows of the selftest table are printed above; send them back as they are."
echo "information: this server's own addresses and default routes, as the helper reads them at each start:"
ip -o addr show 2>&1 | awk '{print "  " $2 " " $3 " " $4}'
ip route show default 2>&1 | sed 's/^/  /'
ip -6 route show default 2>&1 | sed 's/^/  /'
echo "information: /etc/resolv.conf as the host has it (a run has no resolv.conf at all; only the egress proxy resolves names, on the host):"
grep -E '^nameserver' /etc/resolv.conf 2>&1 | sed 's/^/  /'
echo "information: the memory limit and the property choice follow the systemd version above (MemoryZSwapMax=0 from systemd 255)."
echo "information: the address families a run gets (the helper's unit property; 1.18.24 expects AF_INET AF_UNIX, the second only for the egress door):"
grep -o 'RestrictAddressFamilies=[A-Za-z_ ]*' "$HELPER" | sed 's/^/  /'
echo "information: the host's abstract unix listeners as root sees them (names only, never any content; a run cannot create the sockets to reach them):"
python3 - "$HELPER" <<'PY'
import importlib.machinery
import importlib.util
import sys
loader = importlib.machinery.SourceFileLoader("tec_tac_sandbox_helper", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
names = module.read_abstract_names()
if names is None:
    print("  (root could not read /proc/net/unix)")
else:
    print("  %d listed" % len(names))
    for name in names[:50]:
        print("  @" + "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in name))
PY
[ "$SELFTEST_RC" -eq 0 ] && pass "2a selftest ready (incl. pipe_streams)" || fail "2a selftest ready (exit $SELFTEST_RC: read the table above)"
[ "$(jget slots_total < "$STATE/status.json")" -ge 1 ] 2>/dev/null && pass "2b status.json carries slots_total" || fail "2b status.json carries slots_total"
if [ "$MODE" = "network" ]; then network_step_5t; finish; fi

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
AUDIT_LINES_BEFORE=$(wc -l < "$STATE/audit.jsonl" 2>/dev/null || echo 0)
timeout 900 "$HELPER" --selftest --canary >"$CANARY_OUT" 2>&1
CANARY_RC=$?
cat "$CANARY_OUT"
grep -q 'another dynamic user reads the credential file' "$CANARY_OUT" && pass "4c the table holds the row 'another dynamic user reads the credential file'" || fail "4c the table holds the row 'another dynamic user reads the credential file'"
row_ok_label 'another dynamic user reads the credential file' && pass "4d the row 'another dynamic user reads the credential file' ends with OK" || fail "4d the row 'another dynamic user reads the credential file' ends with OK (NOT RUN or ATTACK SUCCEEDED: read the row above)"
# 1.17.123: the table must hold the new rows. A missing row is a failed step here and NOT RUN in the table itself.
OWN_ROWS=$(grep -Ec 'own address [0-9.]+ (tcp 22|tcp 80|tcp 443|udp)[[:space:]]' "$CANARY_OUT")
[ "$OWN_ROWS" -ge 4 ] && pass "4e the table holds the own-address rows (tcp 22, 80, 443 and udp: $OWN_ROWS rows)" || fail "4e the table holds the own-address rows (found $OWN_ROWS, need 4 or more)"
for port in 22 80 443; do
  grep -Eq "own address [0-9.]+ tcp $port[[:space:]]" "$CANARY_OUT" && pass "4e own address tcp $port is in the table" || fail "4e own address tcp $port is in the table"
done
grep -Eq 'own address [0-9.]+ udp[[:space:]]' "$CANARY_OUT" && pass "4e own address udp is in the table" || fail "4e own address udp is in the table"
if ip -4 route show default 2>/dev/null | grep -q ' via '; then
  for port in 80 443; do
    grep -Eq "gateway [0-9.]+ tcp $port[[:space:]]" "$CANARY_OUT" && pass "4f gateway tcp $port is in the table" || fail "4f gateway tcp $port is in the table"
  done
  grep -Eq 'gateway [0-9.]+ udp[[:space:]]' "$CANARY_OUT" && pass "4f gateway udp is in the table" || fail "4f gateway udp is in the table"
else
  echo "NOTE 4f this server has no IPv4 default route with a next hop, so no gateway rows are expected"
fi
for port in 22 80 443 1024 4430 4433; do
  row_ok_label "loopback 127.0.0.53:$port" && pass "4g loopback 127.0.0.53:$port is refused (OK)" || fail "4g loopback 127.0.0.53:$port is refused (the row is missing, NOT RUN or ATTACK SUCCEEDED)"
done
grep -F 'memory beyond MemoryMax' "$CANARY_OUT" | grep -Eq 'allocated [0-9]+ MiB, ended .*oom_kills [0-9a-z]+.*peak' && pass "4h the memory row names the MiB, how the run ended, oom_kills and the peak" || fail "4h the memory row names the MiB, how the run ended, oom_kills and the peak"
row_ok_label 'memory beyond MemoryMax' && pass "4h the memory row ends with OK" || fail "4h the memory row ends with OK (read the row above)"
grep -E 'abstract sockets \([0-9]+ listed\)' "$CANARY_OUT" | grep -Eq '[0-9]+ listed, [0-9]+ left out' && pass "4i the abstract row says how many listeners were listed and left out" || fail "4i the abstract row says how many listeners were listed and left out"
grep -Eq '^ROW abstract-sockets-[0-9]+-listed OK$' "$CANARY_OUT" && pass "4i the abstract row ends with OK" || fail "4i the abstract row ends with OK (a reachable host listener is a Medium finding R1: send the row)"
# 1.18.24: AF_UNIX is allowed for the egress door; the four 'unix socket creation refused' rows are retired. The new row proves a run with no door cannot reach the door path.
row_ok_label 'unix door path without a door' && pass "4n the row 'unix door path without a door' ends with OK" || fail "4n the row 'unix door path without a door' ends with OK (the row is missing, NOT RUN or ATTACK SUCCEEDED: a door exists for a run that declares no allowed_hosts)"
UNIX_HOST_ROWS=$(grep -Ec '^ROW unix-(var|run|rmm)-' "$CANARY_OUT")
[ "$UNIX_HOST_ROWS" -ge 10 ] && pass "4o the 13 host-path unix socket rows are in the table ($UNIX_HOST_ROWS ids matched) and the 4k/4l counters cover their verdicts" || fail "4o the host-path unix socket rows are in the table (found $UNIX_HOST_ROWS, need 10 or more)"
for control in 'socketpair round trip' 'pipe round trip' 'child process with stdio pipes'; do
  row_ok_label "$control" && pass "4p control '$control' works (OK)" || fail "4p control '$control' works (the row is missing or NOT RUN: a runner may need AF_UNIX, send the table)"
done
for folder in / /etc /var /opt /opt/tec-tac /opt/tec-tac/runtimes /run /usr/local /usr/local/lib /usr/local/lib/tec-tac /usr/local/lib/tec-tac/sandbox; do
  row_ok_label "view $folder" && pass "4q the view of $folder shows only allowed names (OK)" || fail "4q the view of $folder shows only allowed names (the row is missing, NOT RUN or ATTACK SUCCEEDED: it names what is visible)"
done
row_ok_label '/ lists only the allowed set' && pass "4r the unit's own / lists only the allowed set (OK)" || fail "4r the unit's own / lists only the allowed set (the row is missing, NOT RUN or ATTACK SUCCEEDED)"
grep -Eq '^ROW read-tectac-canary-[0-9a-f]{12}[a-z0-9-]* OK$' "$CANARY_OUT" && pass "4s the stand-in folder marker is not readable (OK)" || fail "4s the stand-in folder marker is not readable (the row is missing, NOT RUN or ATTACK SUCCEEDED)"
row_ok credential-source-gone && pass "4t the credential source folder is gone while the run is still active (OK)" || fail "4t the credential source folder is gone while the run is still active (not OK)"
row_ok no-host-command-property && pass "4u the live unit has no host command property (OK)" || fail "4u the live unit has no host command property (not OK)"
for credrow in 'credential arrives' 'credential mode' 'credential not in environment'; do
  row_ok_label "$credrow" && pass "4t credential row '$credrow' ends with OK" || fail "4t credential row '$credrow' ends with OK (the slot symlink may have broken the runner: send the row)"
done
MEMDETAIL=$(grep -E '^DETAIL memory-beyond-memorymax ' "$CANARY_OUT" | head -n 1); [ -n "$MEMDETAIL" ] || MEMDETAIL=$(grep -F 'memory beyond MemoryMax' "$CANARY_OUT" | grep -v '^ROW ' | head -n 1)
if printf '%s\n' "$MEMDETAIL" | grep -Eq 'proof: (oom_kill|memory\.events max|probe|systemd unit result oom-kill)' || { printf '%s\n' "$MEMDETAIL" | grep -Fq 'ended oom' && printf '%s\n' "$MEMDETAIL" | grep -Fq 'unit result oom-kill' && printf '%s\n' "$MEMDETAIL" | grep -Fq 'evidence unit_result'; }; then pass "4u the memory row names its proof (proof text, or ended oom with unit result oom-kill and evidence unit_result)"; else fail "4u the memory row names its proof (no proof: send the DETAIL memory-beyond-memorymax line, the memory row and the unit cgroup path)"; fi
row_ok_label 'credential frame stripped from output' && pass "4j the credential frame row ends with OK" || fail "4j the credential frame row ends with OK (it names which check found what)"
grep -F 'write /run' "$CANARY_OUT" | grep -Fq 'private per-run /run' && row_ok_label 'write /run' && pass "4v the row 'write /run' is OK and says 'private per-run /run'" || fail "4v the row 'write /run' is OK and says 'private per-run /run' (the marker may be in the skeleton or seen by the next run, or the check could not be made: send the row)"
ATTACKS=$(awk '$0 ~ /ATTACK SUCCEEDED[[:space:]]*$/ && $0 !~ /^ROW / && $0 !~ /^DETAIL /' "$CANARY_OUT" | wc -l)
NOTRUN=$(awk '$0 ~ /NOT RUN[[:space:]]*$/ && $0 !~ /^ROW / && $0 !~ /^DETAIL /' "$CANARY_OUT" | wc -l)
SKIPPED_SECURITY=$(awk '$0 ~ /SKIPPED[[:space:]]*$/ && $0 !~ /^ROW / && $0 !~ /^DETAIL /' "$CANARY_OUT" | wc -l)
[ "$ATTACKS" -eq 0 ] && pass "4k 0 rows are ATTACK SUCCEEDED" || fail "4k 0 rows are ATTACK SUCCEEDED ($ATTACKS found)"
[ "$NOTRUN" -eq 0 ] && pass "4l 0 rows are NOT RUN" || fail "4l 0 rows are NOT RUN ($NOTRUN found)"
[ "$SKIPPED_SECURITY" -eq 0 ] && pass "4m no row of the normal table is SKIPPED (1.18.24: the 'public tcp 443' row is retired)" || fail "4m no row of the normal table is SKIPPED ($SKIPPED_SECURITY found)"
echo "information: the host's abstract unix listeners as root sees them (names only, never any content), and what the canary tried:"
python3 - "$HELPER" <<'PY'
import importlib.machinery
import importlib.util
import sys
loader = importlib.machinery.SourceFileLoader("tec_tac_sandbox_helper", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
names = module.read_abstract_names()
if names is None:
    print("  (root could not read /proc/net/unix)")
else:
    print("  %d listed" % len(names))
    for name in names[:50]:
        print("  @" + "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in name))
PY
echo "information: a run has no resolv.conf and no name server (1.18.24); the proxy resolves names on the host:"
ls -la "$RUN/resolv.conf" 2>&1 | sed 's/^/  /'
grep -q '^CANARY PASSED$' "$CANARY_OUT" && pass "4a the verdict line says CANARY PASSED" || fail "4a the verdict line says CANARY PASSED (exit $CANARY_RC; every ATTACK SUCCEEDED and NOT RUN row above is a finding)"
[ "$CANARY_RC" -eq 0 ] && pass "4b the canary exit code is 0" || fail "4b the canary exit code is 0 (it was $CANARY_RC)"
grep -c 'ATTACK SUCCEEDED' "$CANARY_OUT" | grep -qx '[0-9]*' && echo "rows with ATTACK SUCCEEDED in the table: $(awk '$0 ~ /ATTACK SUCCEEDED[[:space:]]*$/ && $0 !~ /^ROW / && $0 !~ /^DETAIL /' "$CANARY_OUT" | wc -l)"
echo "SKIPPED rows (shown, never a pass): $(awk '$0 ~ /SKIPPED[[:space:]]*$/ && $0 !~ /^ROW / && $0 !~ /^DETAIL /' "$CANARY_OUT" | wc -l)"
echo "WARN rows (latency target missed is a warning, not a failure): $(awk '$0 ~ /WARN[[:space:]]*$/ && $0 !~ /^ROW / && $0 !~ /^DETAIL /' "$CANARY_OUT" | wc -l)"
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
[ -z "$(find / -maxdepth 1 -name 'tectac-canary-*' 2>/dev/null | head -1)" ] && pass "5n no /tectac-canary-* stand-in folder is left" || fail "5n a stand-in folder is left: $(find / -maxdepth 1 -name 'tectac-canary-*' 2>/dev/null | head -3)"
LINGERED=$(tail -n +"$((AUDIT_LINES_BEFORE + 1))" "$STATE/audit.jsonl" 2>/dev/null | grep -c 'run.credentials_lingered')
[ "$LINGERED" -eq 0 ] && pass "5p no run.credentials_lingered row in the audit rows of this run" || fail "5p $LINGERED run.credentials_lingered row(s) in the audit rows of this run (a unit never showed its credential copy within 15 s: send those rows and the journal)"
[ -z "$(find "$LIB/root/run" -name '.tectac-run-marker-*' 2>/dev/null | head -1)" ] && pass "5q no /run marker file is in the skeleton's run/ folder" || fail "5q a /run marker file is in the skeleton: $(find "$LIB/root/run" -name '.tectac-run-marker-*' 2>/dev/null | head -3)"
AUDIT_REPORT=$(python3 - "$STATE/audit.jsonl" "$AUDIT_LINES_BEFORE" <<'PY'
import json, re, sys
path, skip = sys.argv[1], int(sys.argv[2])
allowed_started = {"runner", "run_id", "person", "canary"}
allowed_ended = allowed_started | {"reason", "exit", "ms", "bytes_out", "bytes_err", "peak_mb", "oom_kills", "evidence", "egress_allowed", "egress_refused", "egress_bytes"}
persons = {"canary", "canary-hold", "canary-peer", "canary-cred"}
started, ended, problems = {}, {}, []
swept = 0
for number, line in enumerate(open(path, encoding="utf-8"), 1):
    if number <= skip:
        continue
    try:
        row = json.loads(line)
    except ValueError:
        problems.append("line %d is not json" % number)
        continue
    event, detail = row.get("event"), row.get("detail") or {}
    if event not in ("run.started", "run.ended"):
        continue
    allowed = allowed_started if event == "run.started" else allowed_ended
    if not set(detail) <= allowed:
        problems.append("%s has unexpected keys %s" % (event, sorted(set(detail) - allowed)))
    text = json.dumps(detail)
    if "refreshed-" in text or "/work" in text or "/run/" in text or any(p == detail.get("person") for p in persons):
        problems.append("%s holds a credential, a path or a person text" % event)
    if not re.fullmatch(r"[0-9a-f]{32}", str(detail.get("person", ""))):
        problems.append("%s person is not a key" % event)
    if event == "run.ended" and detail.get("reason") == "swept":
        swept += 1  # 1.18.15: the sweep wrote the ended row of a run whose helper was killed; it counts as that run's ended row
    if event == "run.ended" and detail.get("run_id") in ended:
        problems.append("run %s has a second run.ended" % str(detail.get("run_id"))[:8])  # 1.18.16: the sweep must not contradict the run's own row
    (started if event == "run.started" else ended)[detail.get("run_id")] = detail
if len(started) < 10:
    problems.append("only %d run.started rows for the canary runs" % len(started))
for run_id in started:
    if run_id not in ended:
        problems.append("run %s has no run.ended" % run_id[:8])
    elif ended[run_id].get("canary") is not True or started[run_id].get("canary") is not True:
        problems.append("run %s is not marked canary" % run_id[:8])
print("started=%d ended=%d swept=%d problems=%d" % (len(started), len(ended), swept, len(problems)))
for item in problems[:10]:
    print("  " + item)
PY
)
echo "information: root audit rows of the canary runs (swept = ended rows written by the sweep for the run whose helper the canary killed): $(echo "$AUDIT_REPORT" | head -1)"
echo "$AUDIT_REPORT" | tail -n +2
echo "$AUDIT_REPORT" | head -1 | grep -q 'problems=0$' && pass "5o audit.jsonl holds run.started and run.ended for the canary runs and no credential, input, output or path" || fail "5o audit.jsonl holds run.started and run.ended for the canary runs and no credential, input, output or path"
STATUS_JSON=$(runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --status 2>/dev/null)
[ "$(echo "$STATUS_JSON" | jget status.canary_ok)" = "True" ] && pass "5k --status reports canary_ok true" || fail "5k --status reports canary_ok true"
[ "$(echo "$STATUS_JSON" | jget status.enabled)" = "False" ] && pass "5l --status still says enabled false" || fail "5l --status still says enabled false"
echo "slots: total=$(echo "$STATUS_JSON" | jget status.slots_total) used=$(echo "$STATUS_JSON" | jget status.slots_used)"
START_OUT=$(echo "x" | runuser -u "$TACTICAL_USER" -- sudo -n "$HELPER" --start 2>/dev/null)
[ "$START_OUT" = '{"t":"refused","code":"sandbox_disabled"}' ] && pass "5m after the canary, --start still refuses with sandbox_disabled" || fail "5m after the canary, --start still refuses"

echo "== step 5r: plain systemd-run without --collect: the unit record stays and says oom-kill (the dev02 diagnostic, now a step)"
PLAN_UNIT="tectac-plantest-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
ZSWAP_PROP=""
SYSTEMD_NUMBER=$(systemctl --version | awk 'NR==1 {print $2}')
if [ "${SYSTEMD_NUMBER:-0}" -ge 255 ] 2>/dev/null; then ZSWAP_PROP="-p MemoryZSwapMax=0"; fi
# shellcheck disable=SC2086
timeout 60 systemd-run --wait --pipe --quiet --unit="$PLAN_UNIT" -p MemoryMax=128M -p MemorySwapMax=0 $ZSWAP_PROP -p OOMPolicy=kill \
  python3 -c 'import time
held = []
count = 0
while True:
    held.append(b"x" * (4 * 1024 * 1024))
    count += 4
    print(count, flush=True)
    time.sleep(0.02)' >/dev/null 2>&1
PLAN_RC=$?
PLAN_RESULT=$(systemctl show "$PLAN_UNIT.service" -p Result --value 2>/dev/null)
PLAN_CODE=$(systemctl show "$PLAN_UNIT.service" -p ExecMainCode --value 2>/dev/null)
PLAN_STATUS=$(systemctl show "$PLAN_UNIT.service" -p ExecMainStatus --value 2>/dev/null)
PLAN_LOAD=$(systemctl show "$PLAN_UNIT.service" -p LoadState --value 2>/dev/null)
echo "information: systemd-run exit $PLAN_RC, LoadState=$PLAN_LOAD Result=$PLAN_RESULT ExecMainCode=$PLAN_CODE ExecMainStatus=$PLAN_STATUS (systemd-run's own code is not the program's)"
[ "$PLAN_LOAD" = "loaded" ] && pass "5r the unit is still loaded after --wait (no --collect)" || fail "5r the unit is not loaded after --wait (send the information line above)"
[ "$PLAN_RESULT" = "oom-kill" ] && pass "5r Result=oom-kill" || fail "5r Result is '$PLAN_RESULT', expected oom-kill (send the information line above and systemctl --version)"
{ [ "$PLAN_CODE" = "2" ] || [ "$PLAN_CODE" = "killed" ]; } && [ "$PLAN_STATUS" = "9" ] && pass "5r ExecMainCode killed, ExecMainStatus 9" || fail "5r ExecMainCode '$PLAN_CODE' status '$PLAN_STATUS', expected killed (2) and 9"
systemctl reset-failed "$PLAN_UNIT.service" >/dev/null 2>&1
[ "$(systemctl show "$PLAN_UNIT.service" -p LoadState --value 2>/dev/null)" != "loaded" ] && pass "5r reset-failed removed the plain test unit" || fail "5r the plain test unit is still loaded after reset-failed"

echo "== step 5s: no tectac unit is left failed after the canary and one sweep"
"$HELPER" --sweep >/dev/null 2>&1
LEFT_FAILED=$(systemctl list-units --state=failed --plain --no-legend --no-pager 'tectac-*' 2>/dev/null)
if [ -z "$LEFT_FAILED" ]; then pass "5s systemctl list-units --state=failed 'tectac-*' is empty"; else echo "$LEFT_FAILED"; fail "5s tectac units are left failed (listed above; send them and the last 40 audit rows)"; fi

network_step_5t

echo "== step 6: YOURS (not scripted)"
echo "   Say whether the Tactical web page and an agent check-in still work after the canary (it makes no change to either)."
echo "   Then send back the whole table from step 4. The sandbox stays OFF until the last patch flips the switch."

finish

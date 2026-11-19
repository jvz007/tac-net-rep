# Core sandbox

Core 1.17.116 (AD-63), launch path built in 1.17.118, allow-list file view and helper audit rows added in 1.18.8. Capability `core.sandbox` 1.0.0. Python only: `tec_tac.sandbox`, plus two routes (below).

Some modules need to run a program they did not write: a command line tool from an AI provider, for example. Core can run that program in a sandbox. A sandbox is a small, locked room. The program can do its work, and it cannot see the server's files or reach the server itself.

**Nothing runs in Core 1.17.118 either.** 1.17.116 added the foundation: the manifest key, the publisher permission, the root helper that registers programs and tests the server, and the contract. 1.17.118 builds the launch path (below) and the full attack test (the canary). The switch that lets a program run is still off. A later Core release turns it on, after the canary passes in full on a real server. Until then `start`, `run` and `cancel` refuse with `sandbox_disabled` before they read anything.

## What a run will be

- It runs as a throw-away user that exists only for that run. Two runs never share an account.
- It sees only what Core gives it: its own program, a read-only runtime folder you declare, and a private scratch folder. It cannot see Tactical's or Tec-Tac's files, the database, or any other module's files.
- It has no extra privileges and a limited set of system calls.
- It has fixed limits for memory, CPU time, tasks, run time, output and scratch space.
- Its login data, if any, is handed in for that one run, readable only by that run, and deleted when it ends.

## The smaller sandbox (what the network rule is)

The network rule is deliberately small. Core uses systemd's address filter (a built-in kernel feature that drops traffic to chosen addresses). A run cannot reach:

- the server itself: loopback, and (from 1.17.123) every address of every local network interface and the default gateway(s), read again at each start,
- link-local addresses, which include the cloud metadata address 169.254.169.254,
- multicast,
- private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 and fc00::/7.

Public HTTPS stays open. There is no host list and no proxy. We accept that a run can reach any public site, because it has no files to read and no tools to act with.

Name lookup still works, and nothing on the server is allowed for it (1.17.123). At each start Core writes its own `resolv.conf` (root-owned, mode 0644, at most three IPv4 `nameserver` lines) and the unit binds it read only over `/etc/resolv.conf`. The lines come from the server's real upstream name servers in `/run/systemd/resolve/resolv.conf` (when that file is missing, from `/etc/resolv.conf`, but only a regular file, never the link to the `127.0.0.53` stub). A public upstream needs no allow, so a run cannot reach the `127.0.0.53` stub on any port. If an upstream name server is loopback, private, link-local, carrier-grade NAT, one of the server's own addresses or its gateway, the sandbox stays off with a plain reason that names the address. Core never allows it automatically. IPv6 upstreams are skipped, because a run has IPv4 only.

The filter judges the destination address, not the next hop, so the public internet keeps working while the server's own public address and its gateway are refused. Known limit: an address that appears after a run has started (a DHCP change) is covered from the next start.

If the server cannot enforce this, the sandbox stays off with a plain reason. It never runs in a weaker mode.

## What this release installs

- `/usr/local/sbin/tec-tac-sandbox`: the root helper. Root-owned, installed by `install.sh`.
- One sudo rule for the Tactical service account with exactly three commands: `--start`, `--stop` and `--status`. While the switch is off `--start` and `--stop` read nothing and refuse with `sandbox_disabled`. The rule is unchanged in 1.17.118.
- `--register-module`, `--unregister-module`, `--selftest` (with `--canary`), and `--sweep` are root only. The module install helpers call the first two. Since 1.18.14 there is no `--finish` mode and no unit property runs a command (a `+` command on systemd 255 sees only the sandbox root, not the host); the helper builds the end frame's memory evidence from its own live cgroup poll.
- 1.17.118 adds the in-unit launcher and the canary programs under `/usr/local/lib/tec-tac/sandbox/` (root-owned, 0755) and the run folders under `/run/tec-tac/sandbox/` (slots, secrets, handoff, runs; root, 0700).
- `tec-tac-sandbox.slice`, a systemd group with a server-wide memory and task cap for all runs together.
- `tec-tac-sandbox-sweep.timer`: at boot and daily it checks the runtime folders again and removes stray test folders.
- A selftest at every install. If the server cannot host the sandbox, the install still succeeds and prints `Sandbox is off: <reason>. ai ChatGPT stays off.`

The selftest checks: the systemd version (249 or newer), that cgroup v2 is in use, a harmless transient unit, a dynamic user, the allow-list file system (the sandbox root folder must match this server, then the real file view is probed) (1.18.12: `ProtectHome=yes` makes systemd add an empty `/root` mount point inside the sandbox root, so the skeleton lists `root` as an empty root-owned folder, and the skeleton is checked again after the probe units so a pass is never logged on a skeleton a probe changed), `LoadCredential`, one probe with the real unit shape (the real file view plus `LoadCredential`, check `real_unit_shape`; 1.18.13), `ProtectProc`, the address filter (the helper opens its own loopback listener and the probe must not reach it; private ranges must be refused; the same probe without the filter must connect, so a probe that cannot connect anyway is never read as a pass), and that a DNS reply arrives from inside the filtered unit. Any reply counts, including "no such name". The result is `/var/lib/tec-tac/sandbox/status.json`, root-owned and small. 1.18.13: a real run makes systemd add `run/systemd/incoming` inside the sandbox root, so the skeleton lists `run/systemd` and `run/systemd/incoming` as empty root-owned folders and nothing else in `run`. After every run ends the helper checks the skeleton again. A new entry is named (relative path only) in a `skeleton.changed` audit row and in the status reason, the sandbox is not ready, and only a new selftest (the install runs one) makes it ready again.

## The launch path (Core 1.17.118)

With the switch on, a run goes like this.

1. The owning module calls `tec_tac.sandbox.start(runner_id, input=..., parameters=..., credentials=..., requested_by=..., user=...)`. Core finds the caller from the call stack (AD-26). Only the module that owns the runner may start it.
2. Core checks the server is ready, the runner and its runtime, the input size, the parameters and the credential names, and writes one strict audit row `sandbox.run.started` **before** the launch. A run that cannot be audited does not start.
3. Core starts the root helper through sudo (`--start`). The header, the input and the credentials go to its stdin, never to argv or the environment. The helper checks every rule again against the root-owned registry row, re-checks the runtime folder and the program's SHA-256, and takes a slot.
4. The helper builds the unit itself, from the registry row and its own constants. The caller cannot add or change a property. The unit carries a dynamic user, an allow-list file system (since 1.18.8: its root is a Core-made folder of empty mount points, `/usr/local/lib/tec-tac/sandbox/root`, and only what the run needs is bound into it, read only), a private scratch folder `/work`, the section 15 address filter, the system-call filter and the limits.
5. A small Core-owned launcher runs inside the unit and starts the program. The program's output streams back as frames.
6. Credentials sit only on tmpfs (`/run/tec-tac/sandbox/secrets/<run id>/`, folder 0700, files 0600), reach the unit through `LoadCredential`, and are deleted by the helper itself as soon as the unit holds its own complete copy (1.18.14; before that a `+` `ExecStartPost` that could not see the host), again when the run ends for any reason, and again by the sweep. Since 1.18.8 the unit only ever sees the fixed names `cred0` and `cred1`; the launcher links each declared name to its slot under `/work/credentials`, so a runner still reads `$CREDENTIALS_DIRECTORY/<declared name>`.

**Slots.** At most `min(6, floor((MemAvailable - 1.5 GiB) / memory_max))` runs at once, never fewer than 1; at most 2 per person. A start waits in the queue for up to the runner's `queue_seconds`, then raises `busy` or `person_busy` with `retry_after`. The person is the signed-in `user` you pass; without it Core uses `requested_by`, which it cannot verify, so that is used for the limit and the audit row only, never for access.

**`RunHandle`.** `start()` returns it: `run_id`, `events(timeout=None)` (started, then out and err as the program prints, then one end), `wait()`, `cancel()` and `close()`. Closing the handle closes the helper's pipes, and that stops the unit (a dead-man switch). If the caller or the helper dies, the launcher inside the unit sees its output pipe close and stops the program as well. `run()` is the blocking form and returns `{run_id, exit_code, stdout, stderr, reason, duration_ms, peak_mb, credentials_out, stdout_truncated, stderr_truncated}`. `reason` is `exited`, `timeout`, `output_limit`, `oom`, `cancelled` or `start_failed`. The partial output is kept for every reason; `wait(raise_on_failure=True)` raises `SandboxError` with that code instead.

**Credential return.** When a runner declares `credential_return`, the program may write a refreshed credential to `$SANDBOX_OUT/credential` (a regular file, at most 16 KiB). The launcher sends it as one final line framed with a random nonce that only the launcher knows. The helper takes only that line and strips it from the output, so a program cannot forge it. It arrives as `credentials_out`.

**Audit rows.** Module `core`, object type `sandbox_run`, never the credential, the input or the output: `sandbox.run.started` (strict), `sandbox.run.ended` (exit code, reason, duration, bytes, peak memory), `sandbox.run.refused` and `sandbox.run.cancelled`.

**Permissions and routes.** The permission group `Sandbox` holds `core.sandbox.view` and `core.sandbox.manage` (an effective superuser passes, AD-10). `GET /api/tfd/system/sandbox/status/` (view) gives the same answer as `status(live=True)`. `POST /api/tfd/system/sandbox/runs/<run_id>/cancel/` (manage) stops any run by id and writes an audit row. The plan named `/api/tfd/core/sandbox/...`; Core has no `core/` route prefix, so both routes sit under `system/`.

**The canary.** `sudo /usr/local/sbin/tec-tac-sandbox --selftest --canary` (root only, not in the sudo rule) runs an in-memory runner `core.canary` through the same launch code and tries to break out: planted files, sockets, loopback and every listening port, LAN and cloud metadata, DNS, privilege calls, writes, host processes, memory, fork, loop, scratch and output limits, abstract sockets, credentials (including `ps`, `/proc/*/cmdline`, `systemctl show` and journald), cancel and kill, slots and latency. It prints a table and writes `/var/lib/tec-tac/sandbox/canary.json` (counts and failing rows, no secret). `CANARY PASSED` appears only when no row says `ATTACK SUCCEEDED` or `NOT RUN` and no security row is `SKIPPED` (1.17.123: only `public tcp 443`, for a server with no public route, may be skipped). A skipped row is shown and never counted as a pass. From 1.17.123 the table also has rows for the server's own addresses and gateway, `127.0.0.53` on the listening ports and six more, the memory limit (judged on the MiB allocated and how the run ended, not on systemd's label), the credential frame (it looks for the real nonce frame, the launcher header and the tokens, not for the word `CRED`), and every abstract unix socket the host listens on (root lists them, the unit tries each one). From 1.17.124 runners no longer keep `AF_UNIX` (`RestrictAddressFamilies=AF_INET`). The abstract unix namespace belongs to the network namespace, which `IPAddressDeny` does not change, so with `AF_UNIX` the host's abstract listeners (multipathd, iscsid) were reachable (Medium finding R1). Without it `socket(AF_UNIX)` fails with `EAFNOSUPPORT` before any connect, for pathname and abstract sockets alike. systemd documents that this filter covers `socket()` only: `socketpair()`, pipes and inherited file descriptors are not affected, so the stdio pipes of a Node-based CLI (libuv) and a child process with piped stdio keep working. The `ExecStopPost=+` command (`--finish`, which calls `systemctl`) is a fully privileged `+` command and is not filtered; dev02 confirms it by the memory row's `oom_kills` value. The canary has rows that prove both sides: `unix socket creation refused` (stream, dgram, seqpacket) and `unix pathname socket refused` must be OK, and the controls `socketpair round trip`, `pipe round trip` and `child process with stdio pipes` must work (a failed control is NOT RUN, never an attack, and fails the canary). The Claude and Codex CLIs are not yet proven on `socketpair` alone. If one later proves to need `AF_UNIX`, that is a new request to Johan (option b: `PrivateNetwork=yes` plus a Core socket bridge for DNS and 443), never re-added silently. From 1.17.124 the memory row is judged on kernel evidence (the cgroup's `oom_kill` counter or a refused allocation) and the peak, not on a label, the loopback probes run in parallel so all six `127.0.0.53` rows report, and the abstract list sent to the unit is capped (names left out are counted and covered by the `unix socket creation refused` rows). `tests/sandbox-canary-1.17.124.sh` runs it on a dev server.

**1.18.24 (Patch B).** The network paragraphs above describe earlier builds. The `dns` and `public` groups are retired (the network group covers them), `AF_UNIX` is allowed again for the egress door only (the four `unix socket creation refused` rows are retired; the 13 `unix <host path>` rows and the abstract group stay and must read OK; a new row `unix door path without a door` must read OK), and `tests/sandbox-canary-1.18.24.sh` runs the Patch B exit list (step 5t): every network row OK, the seven proxy rows included.

## Declaring a runner in a manifest

Add the optional top-level key `sandbox_runners` to `tec_tac.json`. It is a list of at most 4 entries. A manifest without the key is unchanged.

```json
{
  "publisher_permissions": ["sandbox.register"],
  "requires": {"framework": ">=1.17.116"},
  "sandbox_runners": [
    {
      "id": "ai.claude",
      "description": "Runs the Claude command line program",
      "executable": "sandbox/runners/claude.sh",
      "argv": ["--model", {"param": "model"}],
      "parameters": {"model": {"type": "enum", "choices": ["a", "b"]}},
      "environment": {"LANG": "C.UTF-8"},
      "runtime_roots": [{"path": "/opt/tec-tac/runtimes/ai/claude", "tree_sha256_file": "sandbox/claude.sha256"}],
      "credential_files": ["auth"],
      "credential_return": true,
      "limits": {"memory_mb": 1536, "run_seconds": 300},
      "revision": "1"
    }
  ]
}
```

| Key | Rule |
|---|---|
| `id` | `<module-id>.<name>`. Letters, digits, `.`, `_`, `-`. Unique in the manifest. |
| `description` | 1 to 200 plain characters. |
| `executable` | A file below `sandbox/runners/` in the module folder. Relative, no `..`, no symlink, must exist. Core copies it root-owned (0755) to `/usr/local/lib/tec-tac/sandbox/runners/<module>/` and records its SHA-256. It never runs from the module folder. |
| `argv` | Literal strings or `{"param": name}`. At most 64. No shell text. |
| `parameters` | Typed values the caller may pass: `string`, `integer`, `boolean` or `enum`. |
| `environment` | A fixed map of non-secret text. `HOME`, `TMPDIR`, `SSL_CERT_FILE`, `SANDBOX_WORK` and `SANDBOX_OUT` are Core's. Names that start `LD_` or look like a secret (`TOKEN`, `SECRET`, `PASSWORD`, `CREDENTIAL`, `API_KEY`, `PRIVATE`) are refused. |
| `runtime_roots` | A list of `{path, tree_sha256_file}`. `path` is absolute and normalised (no `..`, no empty part, no backslash, no control character, 512 characters at most) and sits strictly below `/opt/tec-tac/runtimes/<module id>/`, at least one folder deeper (since 1.17.117). `/opt/tec-tac/runtimes/ai/claude` is valid for module `ai`; `/opt/tec-tac/runtimes/ai` alone, another module's folder and any path outside `/opt/tec-tac/runtimes/` are refused when the package is installed and again by the root helper. `tree_sha256_file` is a file inside the signed module with one `<sha256>  <relative path>` line per file of the runtime. |
| `credential_files` | At most 2 names (`[a-z0-9][a-z0-9._-]{0,63}`), 16 KiB per file. |
| `credential_return` | `true` lets the run hand one refreshed credential back. Needs a declared name. |
| `limits` | Whole numbers, at most the Core ceiling. See the table below. |
| `revision` | Short text. |

`allowed_hosts` is optional (Core 1.18.24, AD-65 Patch B; before that it was refused). It is a list of at most 16 exact, lower-case DNS names with at least two labels (letters, digits and `-`, at most 253 characters), for example `["api.anthropic.com"]`. No wildcard, no port (the port is always 443), no IP literal in any spelling (the last label of a name is never all digits or a `0x` number), nothing ending `.local`, `.internal`, `.localhost` or `.lan`, no repeats. A runner without it has no network at all.

`HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`, `ALL_PROXY`, `NO_PROXY` and `no_proxy` are Core's too (1.18.24): a manifest that sets one of them is refused. Core sets `HTTPS_PROXY` and `https_proxy` to `http://127.0.0.1:3128` only for a runner that declares `allowed_hosts`.

## The network of a run (Core 1.18.24, AD-65 Patch B)

Before 1.18.24 a run kept the host's network and a filter (`IPAddressDeny`) denied private ranges. That filter could not show every way back to the server, so it is gone. A run now has **its own, empty network space** (`PrivateNetwork=yes`):

* it sees only `lo` (its own loopback); there is no interface, no default route, no DNS and no `/etc/resolv.conf`; a name lookup fails at once;
* it reaches the network only through one door. For a runner that declares `allowed_hosts`, Core starts a small proxy on the host for that run alone (`tec-tac-sandbox-egress@<run id>.socket`, activated on the first connection, its own unprivileged user). Inside the run, the Core launcher listens on `127.0.0.1:3128` and relays each connection, byte for byte, to the proxy's Unix socket (the per-run folder is bound read only at `/run/egress`; only that path connects). Programs use `HTTPS_PROXY`, which Core sets;
* the proxy accepts HTTP `CONNECT` only, to `<allowed host>:443` only. It refuses (403) any other method, any port but 443, an IP literal, a single-label or `.local` style name and any host that is not an exact match in `allowed_hosts`. It resolves the name itself (the run never does), requires every address to be global (no private, loopback, link-local, multicast, carrier-grade NAT or reserved range), refuses this server's own addresses, gateways and name, and then connects to the checked numeric address, never to the name again. Limits: 16 tunnels at once, 100 per run, 256 MiB per run, 10 s to connect, 60 s idle;
* `AF_UNIX` is allowed in a run (`RestrictAddressFamilies=AF_INET AF_UNIX`) for the door only. Host pathname sockets are not in the run's file view and abstract sockets belong to the run's own network space, so the 13 host-path rows and the abstract group of the canary must still read OK. A runner that needed `AF_UNIX` for a host service is still refused by the file view;
* the proxy writes one audit line per `CONNECT` (host, port, allowed or refused, a reason code, bytes up and down; never a payload, a header or a credential). After the run the root helper writes one audit row `run.egress` (counts and the capped rows) before `run.ended`; `run.ended` gains `egress_allowed`, `egress_refused` and `egress_bytes`;
* a runner with no `allowed_hosts` still gets the empty network space but no proxy, no forwarder and no proxy variable.

A server whose own name server is a private or loopback address other than the systemd-resolved stub `127.0.0.53` makes the proxy fail closed: the selftest says so in plain words and the sandbox stays off. The proxy's own unit carries a second wall (`IPAddressDeny` for the numeric private ranges, with `IPAddressAllow=127.0.0.53/32` for the stub only).

| Limit | Default | Core ceiling |
|---|---|---|
| `memory_mb` | 1024 | 2048 |
| `cpu_percent` | 100 | 200 |
| `tasks` | 256 | 512 |
| `run_seconds` | 240 | 600 |
| `stdout_kib` | 512 | 1024 |
| `stderr_kib` | 64 | 64 |
| `scratch_mb` | 64 | 256 |
| `input_kib` | 64 | 256 |
| `queue_seconds` | 10 | 30 |

The module must declare `sandbox.register` in `publisher_permissions`, and the publisher that signs the package must hold it. `install.sh` grants it to nobody, not even the development publisher: the local trust policy decides. An unsigned package that declares it is refused.

Core checks every rule twice: `registry.py` when the package is installed, and the root helper again, from the root-owned installed manifest, when it registers the runners. The helper never trusts job metadata.

A runner whose runtime folder is missing or does not match its signed listing is still registered, marked `runtime_unverified`. `runtime_reason` is a fixed code and a fixed sentence per runtime root, for example `root 1: hash_mismatch (a file in the runtime folder differs from the signed listing)`. It never holds a path or a file name, because the registry file is world-readable. The codes are `runtime_missing` (the normal first state: the module builds its runtime after install), `unreadable`, `unsafe_path`, `unsafe_entry` (a link, a special file, or an entry that is not root-owned or is writable by others, anywhere in the path or tree), `extra_file`, `missing_file`, `hash_mismatch`, `too_many_files`, `listing_empty`, `listing_unreadable`, `listing_changed` and `listing_not_recorded`. To find the file, run your own tree-listing tool again.

Registration records the SHA-256 of each tree listing file in the registry row (a hash only, no names). The boot and daily sweep reads the listing again and compares it with that hash first. A listing that changed after registration gives `listing_changed` and the runtime folder is not walked; the module registers again (an install or upgrade does this) to record the new hash. A row from Core 1.17.116 has no recorded hash and shows `listing_not_recorded` until its module registers again. A path outside `/opt/tec-tac/runtimes/<module id>/` in a row is never walked (`unsafe_path`).

On an upgrade the helper drops the runners and programs that the new manifest no longer declares. A module that declares none loses all. A module removal removes them too.

## The calls

Check `has_capability('core.sandbox')` first and require framework >=1.17.116 (>=1.17.118 for the launch path).

| Call | What it does |
|---|---|
| `status(live=False)` | `{enabled, ready, reason, systemd_version, address_filter_ok, dns_ok, network_private_ok, egress_ok, selftest_at, slots_total, slots_used, canary_ok, canary_at, runners}`. Since 1.18.24 `address_filter_ok` means the network wall is proven and `dns_ok` means the egress proxy resolves names and opens a tunnel; `network_private_ok` and `egress_ok` are the same answers under their own names (additive). `enabled` is `False` until the switch is on. `ready` is `True` only when the selftest passed. `slots_used` is `None` unless `live` is `True` (one `sudo --status` call, 3 seconds at most). `canary_ok` is `True` only when the last full canary passed. No secret. The last four keys and `live` are new in 1.17.118 and additive. |
| `describe(runner_id)` | The declared limits, SHA-256, version and runtime state of one runner. The owning module only. |
| `start(...)` | Returns a `RunHandle` (see the launch path). Raises `SandboxError` `sandbox_disabled` before it reads anything while the switch is off. |
| `run(...)` | The blocking form of `start`. |
| `cancel(run_id)` | Stops a run this process started. Another module's run, or one this process does not know, is `not_owner`. |

`status()` reasons for an unready answer: the plain reason from the selftest, `selftest_not_run` when `status.json` is missing, and `status_unreadable` when it is a link, not root-owned, writable by others, too big or not JSON. New keys are added later; read the keys you know and ignore the rest.

`describe` finds the caller from the call stack (AD-26). Core, a library, a generated frame, a disabled or legacy module and any module that does not own the runner get `not_owner`. An id that does not begin with the caller's own module id is `not_owner` too, so a module cannot tell another module's runner from a missing one.

### Errors

`SandboxError` carries `code`, a plain `message` and `retry_after` (seconds; only for `busy` and `person_busy`). The codes: `sandbox_disabled`, `sandbox_unavailable`, `runner_unknown`, `runner_disabled`, `runtime_unverified`, `not_owner`, `invalid_input`, `input_too_large`, `credential_invalid`, `busy`, `person_busy`, `start_failed`, `timeout`, `output_limit`, `oom` and `cancelled`.

## What is not in this release

- The switch. `SANDBOX_ENABLED` is `False` in `tec_tac/sandbox.py` and in the helper. It is turned on by a separate patch after the dev02 canary passes in full.
- A setting to lower the slot count, and a status panel in the UI.
- IPv6 for a run (`RestrictAddressFamilies` is `AF_INET` only since 1.17.124; there is no `AF_UNIX` either), an egress proxy, a host list, a warm pool.
- Audit log rotation: the helper's own file `/var/lib/tec-tac/sandbox/audit.jsonl` grows by about 300 bytes a row and is not rotated yet.
- Copying the helper's registered and removed rows into Core's audit log. The helper's log file is not readable by the Tactical account and Core has nowhere to keep a read position yet; a later patch adds both.
- No module uses `core.sandbox` yet.

## The file system a run sees (1.18.8)

A run does not get the server's file system with some folders hidden. It gets a small root of its own, built by `install.sh` and checked at every start and in the selftest. The root holds only empty mount points: `usr`, `work`, `tmp`, `var/tmp`, `proc`, `sys`, `dev`, `run`, `opt/tec-tac/runtimes`, `etc/ssl/certs`, `etc/ca-certificates`, a few empty files under `etc`, and the merged-`/usr` names (`bin`, `sbin`, `lib`, `lib64`, `lib32`, `libx32`) in the form this server has. What the run needs is bound into those points, read only: `/usr`, the system's certificates and account files, its own runner, its own runtime folder `/opt/tec-tac/runtimes/<module id>` (one bind for the whole folder) and the launcher. The server's own `/usr/local` is replaced by an empty folder. If the root does not match the server, the selftest says so in plain words and no run starts: run the Core install again. There is no weaker mode.

**The helper's own audit rows.** Besides Core's `sandbox.run.*` rows, the root helper writes `run.started` (before the unit is started; no row, no run) and `run.ended` to `/var/lib/tec-tac/sandbox/audit.jsonl`. They hold the runner id, the run id, a key made from the person (never the person's text), whether it was a canary run, the end reason, the exit code, the duration, the output sizes, the memory peak and the kernel's kill count. They never hold the input, an output, a parameter, a credential or a path. A direct `sudo tec-tac-sandbox --start` call leaves a record even if Django is bypassed.

**Canary proof rows (1.18.15).** `/run` is writable inside a run, because systemd gives each unit its own `/run` (it holds the credential copies). The canary row `write /run` is OK only when that is proven private: the probe leaves a marker file in `/run`, and the row is OK only if the marker is not in the skeleton's `run/` folder and the next run's own listing of `/run` does not show it (the row then says "private per-run /run"). Nothing in the unit's properties changed. Memory pages of that tmpfs count against the run's memory limit by kernel rule, but the canary does not measure that. A run record the sweep removes (a run whose helper was killed) gets a `run.ended` row with reason `swept`. If the credential clean-up gives up after 15 seconds, the helper writes `run.credentials_lingered` with the run id, the runner id and the seconds, and nothing else. The canary prints one `ROW <id> <verdict>` line per table row, so its checker never depends on a cut label.

**Canary memory proof (1.18.16).** The memory row is judged on the kernel's own counters. The helper reads `max`, `high`, `oom` and `oom_kill` from the unit's `memory.events` at every poll and keeps the highest of each; the end frame carries them as an additive `memory_events` key that Core drops, so modules and the `run.ended` audit row do not change. The row is OK on an `oom_kill` of 1 or more, on `max` of 1 or more with a known peak at or below `MemoryMax` and a probe that did not finish, or on a probe `MemoryError`, and its text ends with `proof: ...` naming which. No counters and no kill stays NOT RUN. The `/run` privacy check no longer lists `/run`: the next run is told the marker name and answers `CANARYRUNSEEN 1` or `0`. The sweep writes no `swept` row for a run that already has its own `run.ended`.

**Run unit result (1.18.17).** The run unit is started without `--collect`, so systemd keeps its record after `systemd-run --wait` returns. The helper reads that record once with `systemctl show` (`LoadState`, `ActiveState`, `Result`, `ExecMainCode`, `ExecMainStatus`), checks every value against a whitelist, and trusts it only when the unit is still loaded. The end of the run comes from that record and never from text on the run's streams: the sandboxed program writes to the same stderr as systemd-run and could forge a line such as `Finished with result`. `Result=oom-kill` gives the end reason `oom` when the helper itself did not stop the run; a timeout, a cancel or an output limit still wins. The end frame reports the program's real exit code (or the signal, with `exit` empty) in additive internal keys that Core drops. After each run, and in the boot and daily sweep, a failed run unit is reset with `reset-failed`, so none stays in systemd.

## For administrators

To read the state on the server: `sudo /usr/local/sbin/tec-tac-sandbox --status`. To run the test again as root: `/usr/local/sbin/tec-tac-sandbox --selftest`. The helper's log is `/var/lib/tec-tac/sandbox/audit.jsonl`. The last canary result is `/var/lib/tec-tac/sandbox/canary.json`. `uninstall.sh` removes the helper, the sudo rule, the slice and the sweep timer, and keeps that log.

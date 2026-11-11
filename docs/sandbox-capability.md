# Core sandbox

Core 1.17.116 (AD-63). Capability `core.sandbox` 1.0.0. Python only: `tec_tac.sandbox`.

Some modules need to run a program they did not write: a command line tool from an AI provider, for example. Core can run that program in a sandbox. A sandbox is a small, locked room. The program can do its work, and it cannot see the server's files or reach the server itself.

**Nothing runs in Core 1.17.116.** This release adds the foundation: the manifest key, the publisher permission, the root helper that registers programs and tests the server, and the contract. The switch that lets a program run is off, and a later Core release turns it on after a full test on a real server. Until then `start`, `run` and `cancel` refuse.

## What a run will be

- It runs as a throw-away user that exists only for that run. Two runs never share an account.
- It sees only what Core gives it: its own program, a read-only runtime folder you declare, and a private scratch folder. It cannot see Tactical's or Tec-Tac's files, the database, or any other module's files.
- It has no extra privileges and a limited set of system calls.
- It has fixed limits for memory, CPU time, tasks, run time, output and scratch space.
- Its login data, if any, is handed in for that one run, readable only by that run, and deleted when it ends.

## The smaller sandbox (what the network rule is)

The network rule is deliberately small. Core uses systemd's address filter (a built-in kernel feature that drops traffic to chosen addresses). A run cannot reach:

- the server itself (`localhost`),
- link-local addresses, which include the cloud metadata address 169.254.169.254,
- multicast,
- private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 and fc00::/7.

Public HTTPS stays open. There is no host list and no proxy. We accept that a run can reach any public site, because it has no files to read and no tools to act with.

Name lookup still works. Core finds the server's name server in `/etc/resolv.conf` (for example `127.0.0.53` with systemd-resolved, or a name server on your LAN) and allows exactly that address.

If the server cannot enforce this, the sandbox stays off with a plain reason. It never runs in a weaker mode.

## What this release installs

- `/usr/local/sbin/tec-tac-sandbox`: the root helper. Root-owned, installed by `install.sh`.
- One sudo rule for the Tactical service account with exactly three commands: `--start`, `--stop` and `--status`. `--start` and `--stop` read nothing and refuse with `sandbox_disabled`.
- `--register-module`, `--unregister-module`, `--selftest` and `--sweep` are root only. The module install helpers call the first two.
- `tec-tac-sandbox.slice`, a systemd group with a server-wide memory and task cap for all runs together.
- `tec-tac-sandbox-sweep.timer`: at boot and daily it checks the runtime folders again and removes stray test folders.
- A selftest at every install. If the server cannot host the sandbox, the install still succeeds and prints `Sandbox is off: <reason>. ai ChatGPT stays off.`

The selftest checks: the systemd version (249 or newer), that cgroup v2 is in use, a harmless transient unit, a dynamic user, a hidden file system with a read-only bind, `LoadCredential`, `ProtectProc`, the address filter (the helper opens its own loopback listener and the probe must not reach it; private ranges must be refused; the same probe without the filter must connect, so a probe that cannot connect anyway is never read as a pass), and that a DNS reply arrives from inside the filtered unit. Any reply counts, including "no such name". The result is `/var/lib/tec-tac/sandbox/status.json`, root-owned and small.

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

`allowed_hosts` is refused. The smaller sandbox has no host list, so a manifest that declares it is refused with a plain message.

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

Check `has_capability('core.sandbox')` first and require framework >=1.17.116.

| Call | What it does in 1.17.116 |
|---|---|
| `status()` | `{enabled, ready, reason, systemd_version, address_filter_ok, dns_ok, selftest_at, runners}`. `enabled` is `False`. `ready` is `True` only when the selftest passed. No secret. |
| `describe(runner_id)` | The declared limits, SHA-256, version and runtime state of one runner. The owning module only. |
| `start(...)`, `run(...)`, `cancel(...)` | Exist so you can code against the final shape. They raise `SandboxError` `sandbox_disabled` before they read anything. |

`status()` reasons for an unready answer: the plain reason from the selftest, `selftest_not_run` when `status.json` is missing, and `status_unreadable` when it is a link, not root-owned, writable by others, too big or not JSON. New keys are added later; read the keys you know and ignore the rest.

`describe` finds the caller from the call stack (AD-26). Core, a library, a generated frame, a disabled or legacy module and any module that does not own the runner get `not_owner`. An id that does not begin with the caller's own module id is `not_owner` too, so a module cannot tell another module's runner from a missing one.

### Errors

`SandboxError` carries `code`, a plain `message` and `retry_after` (seconds; only for `busy` and `person_busy`). The codes: `sandbox_disabled`, `sandbox_unavailable`, `runner_unknown`, `runner_disabled`, `runtime_unverified`, `not_owner`, `invalid_input`, `input_too_large`, `credential_invalid`, `busy`, `person_busy`, `start_failed`, `timeout`, `output_limit`, `oom` and `cancelled`.

## What is not in this release

- The launch path (`--start`, `--stop`, `--finish`, the unit builder, slots, output streaming, cancel). It follows in the next patch, with the full canary test on a real server.
- Permissions `core.sandbox.view` and `core.sandbox.manage`, a status route and a status panel in the UI.
- Django audit rows. The helper keeps its own append-only log of registrations, removals, selftests and sweeps. It never holds a credential.

## For administrators

To read the state on the server: `sudo /usr/local/sbin/tec-tac-sandbox --status`. To run the test again as root: `/usr/local/sbin/tec-tac-sandbox --selftest`. The helper's log is `/var/lib/tec-tac/sandbox/audit.jsonl`. `uninstall.sh` removes the helper, the sudo rule, the slice and the sweep timer, and keeps that log.

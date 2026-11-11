# Tec-Tac Framework 1.17.119

Date: 11 November 2026. `core.sandbox` hardening: the two held findings of the 1.17.118 review are fixed before the kill-switch patch. **Nothing can run in the sandbox yet.** `SANDBOX_ENABLED` stays `False`; the sudo rule, the status keys and the public contract `core.sandbox` 1.0.0 are unchanged.

Request: the `core.sandbox` request in `reviews/requests/core.md` stays open (it ends when the kill-switch patch and the dev02 canary are signed). Closes the 1.17.118 held Medium "a runtime root path with whitespace or ':' injects extra BindReadOnlyPaths entries" and the held Low "validated parameter values reach ExecStart unescaped" (the release manager marks both fixed in `reviews/core/BACKLOG-new-findings.md`).

## What changed and why

1. **A runtime root path can only be one bind** (Medium).
   * Each part of a runtime root path must now match `[A-Za-z0-9._-]+`. Space, tab, newline, `:`, `%`, `$`, quotes, backslash and non-ASCII are refused. The older rules stay (absolute, normalised, no `..` or `.`, below `/opt/tec-tac/runtimes/<module id>/` and one part deeper, 512 characters at most). `registry.py` (`_sandbox_runtime_path`) and `scripts/sandbox-helper.py` (`_check_runtime_path`) give the same answer.
   * Defence in depth: `build_properties` checks every runtime root path from the registry row with `_bind_path_safe` (no whitespace, `:`, `%`, `$`, control character or backslash) and raises `Refusal('runtime_unverified')` before it writes a `BindReadOnlyPaths=` line. The fixed binds (system files, runner folder, launcher) are not checked: they are constants, and the Windows test harness uses a path with a space and a drive colon.
   * `check_runner_ready` and the sweep already call `_check_runtime_path`, so an old registered row with a bad path now shows `runtime_unverified` with no further code.
2. **Command words reach the program as validated** (Low). systemd expands `$VAR` and `%specifier` in the command of a transient unit. `build_argv` now escapes `$` as `$$` and `%` as `%%` in every word after the first `--` (Python, launcher, `--return-credential`, inner `--`, executable, literal argv strings and parameter values). `--unit=`, `--property=` and `--setenv=` items are not escaped. `render_command` is unchanged, so logs and audit rows show the plain value.

## Tests

* New `tests/sandbox-path-chars-1.17.119.py` and `tests/sandbox-exec-escape-1.17.119.py`.
* `tests/sandbox-harness-1.17.118.py`: the fake `systemd-run` now undoes `$$` and `%%` like systemd, so the launch tests prove a round trip.
* Not run here: real systemd (whether `$$` and `%%` are the right escapes for a transient unit, and whether each property is accepted) and Django.
* **Canary row not built.** The in-memory `core.canary` runner takes one enum parameter (`group`). A string parameter would need a larger change, and the plan said not to widen the canary. On dev02, after `sudo bash tests/sandbox-canary-1.17.118.sh`, run one manual check: `sudo systemd-run --pipe --wait --collect --quiet -- /usr/bin/printf '%s\n' 'a$$HOME b%%h$$$$'` must print `a$HOME b%h$$`. If `%` arrives doubled, the next patch drops the `%` escape and refuses `%` in values.

## Module-facing changes

None. A search of `modules/` finds no `sandbox_runners`, `runtime_roots` or `core.sandbox` user. A module whose runtime folder name uses a character outside letters, digits, `.`, `_` and `-` must rename it before it can register a runner.

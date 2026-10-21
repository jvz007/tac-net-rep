# Tec-Tac Framework 1.17.72

Date: 21 October 2026. No migration. No new route. No new capability. `core.module_dependants` stays at 1.0.0.

Two small hardening changes. Both close findings that were waiting.

- **A token in a repository URL no longer reaches `module-state.json`.** That file is readable by everyone on the server. We now store the scheme, host, port and path of a repository URL and nothing else.
- **One bad dependency entry no longer hides the good ones.** A broken entry in one module's manifest used to drop every dependency of that key. Now only the broken entry is skipped, and Core says the answer is incomplete.

What changes for a person today: nothing you can see. Downloads from a repository still use the full URL, so a repository that needs a token in its address keeps working.

No module-facing change. No module calls `core.module_dependants` yet, and no module reads `source.repository_url` from `module-state.json` (checked with a search of `modules/`).

## What changed and why

### 1. No query string or fragment in `source.repository_url` (external audit closure report, H2, LOW-MEDIUM)

A repository URL can carry a secret, for example `https://repo.example.com/index.json?token=abc#frag`. Core copied that URL into the staged package record and then into `module-state.json`, which is mode 0o644. Any local account could read the token.

1. A new function, `strip_repository_url(value)`, keeps `scheme://host[:port]/path` and drops the query, the fragment, `;params` and user info. The scheme and host are written in lower case. An IPv6 host keeps its brackets. Anything that is not text, not http or https, or has no host gives an empty string, so nothing risky is stored.
2. The function is used at every place that writes `source.repository_url`:
   - `module_repository.py`: the `source` record built for a staged package. The repository record and every fetch URL are not changed, so downloads still work.
   - `module_state.py` (`_save_state_unlocked`): Core's own state write.
   - `scripts/module-v2-job-helper.py`: `remember_version` cleans the incoming source, and `save_module_state_unlocked` cleans every module record on each write.
   - `scripts/module-job-helper.py`: the three state writers (remove, enable or disable, set category) clean the state before they write it.
3. The two root helpers never import the Tactical-writable tree, so each carries its own copy of the function, the same pattern as the AD-20 replacement rules. `tests/module-state-source-url-1.17.72.py` runs all four copies over one matrix and fails if they differ.
4. State already on disk is cleaned the next time anything writes it: an install, enable, disable, a visibility change or a category change. Only the key `repository_url` inside a module's `source` is touched. Other keys and other modules stay as they were.
5. File mode (0o644), owner, locks and the `atomic_json` arguments are exactly as before. No scanner rule is suppressed.

Not done here, on purpose: making `module-state.json` 0o640 `root:tactical`. You said never to change the file mode in this batch. It is held as a question in `reviews/questions/core.md`.

### 2. A malformed dependency entry drops only itself (held LOW from the 1.17.71 review)

`_dependency_pairs` returned an empty result as soon as it met a blank or non-text module id. So one bad entry hid every good pair of that key.

1. The bad entry is now skipped with `continue`. Every good pair is kept and sorted as before. A non-text constraint beside a good id still reads as `*`. `{" ": "*"}` alone still gives an empty result. `_dependency_pairs` keeps its name and signature.
2. `PluginSpec` gets one more defaulted field, `dependencies_incomplete` (False by default). Like the 1.17.71 fields it is left out of equality, hashing and repr, so every older `PluginSpec(...)` call stays valid. A small private helper, `_dependency_pairs_checked`, returns the pairs and whether the key was incomplete: present but not an object, or an entry skipped.
3. `core.module_dependants.dependants()` answers `complete: False` when any other installed extension is flagged. Core cannot know whether that module depends on the caller. It writes one warning that names module ids only. The output keys are the documented ones (`module`, `dependants`, `complete`) and the row keys are unchanged. A clean registry answers exactly as in 1.17.71. The caller check (AD-26) and the fail-closed `DependantsUnavailable` path are not touched.
4. A flagged module that is the caller, a legacy module or a reportset does not make the answer incomplete, because the function never reads those as dependants.
5. The registry still never raises (rule 1.13).

## Tests

- New: `tests/module-state-source-url-1.17.72.py` (strip matrix on all four copies, staged source, install write, every state writer, odd shapes, source check that each state write is preceded by the scrub).
- New: `tests/module-dependants-malformed-1.17.72.py`.
- Unchanged and still passing: `tests/module-dependants-1.17.71.py`, `tests/module-dependants-runtime-1.17.71.py`.

What could not run on the build PC: Django is not installed, and the root helpers cannot run as root here. The helper tests use the same stubs as the 1.17.12 and 1.17.13 tests. The install from a real repository and the real file owner are for the dev-server check.

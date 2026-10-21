# Tec-Tac Framework 1.17.73

Date: 21 October 2026. No migration. No new route. No new capability. No new setting. No contract change.

Two small changes. The first tightens how Core talks to GitHub. The second corrects a claim we made in 1.17.72.

- **GitHub redirects are now checked.** Core follows a GitHub redirect over https only, at most 5 times, and sends the GitHub token only to the three approved GitHub hosts.
- **We corrected the 1.17.72 note about repository tokens.** The note said too much. See "Correction to 1.17.72" below.

What changes for a person today: nothing you can see. System updates from GitHub work as before.

## What changed and why

### 1. A redirect handler for the three GitHub calls (external audit closure report, H1, LOW)

`system_update.py` makes three GitHub calls: the JSON read, the file read and the repository archive download. Each one used `urllib.request.urlopen`, which follows any redirect and keeps the `Authorization` header on the way. A redirect to another host would have carried the token with it.

1. A new redirect handler, `_GithubRedirectHandler`, replaces that behaviour. The three calls now go through `_github_open`.
2. **https only.** A redirect to http, file or ftp is refused with "GitHub redirected to a non-HTTPS address; the download was refused." The message holds no address and no token. A first address that is not https is refused too.
3. **At most 5 redirects.** The sixth is refused with "GitHub redirected too many times; the request was refused." This is the same limit as the module repository fetch.
4. **The token goes to three hosts only:** `api.github.com`, `github.com` and `codeload.github.com`, over https, on port 443 or no port. A redirect anywhere else is followed without `Authorization`. That covers lookalikes such as `codeload.github.com.evil.example`, `evilgithub.com`, `https://api.github.com@evil.example/` and `https://codeload.github.com:8443/`. The other headers (Accept, User-Agent, X-GitHub-Api-Version) stay.
5. **codeload.github.com does receive the token.** A zipball request starts at `api.github.com` and GitHub redirects it to `codeload.github.com`. You asked for codeload to be one of the approved hosts, so the token is kept on that hop. See Q-CORE-H1A in `reviews/questions/core.md`.

Not changed: how the token file is read, proxy handling (the default environment proxy behaves as before), `module_repository.py` (a separate release), and every route, setting and migration.

### 2. Correction to 1.17.72

The 1.17.72 notes said: "A token in a repository URL no longer reaches `module-state.json`." That is true only in part.

- **Removed from `module-state.json` `source.repository_url`:** the query string, the fragment, `;params` and user info.
- **Not removed:** anything in the path. A token placed in the path, for example `/t/<token>/index.json`, still reaches the file. The file stays 0o644 and world-readable.

No code changed. We corrected these words:

- `docs/releases/RELEASE_NOTES_1.17.72.md` (moved from the root) has a dated "Corrected in 1.17.73" paragraph and fixed lines.
- The docstring of `strip_repository_url` in `module_state.py`, `scripts/module-job-helper.py` and `scripts/module-v2-job-helper.py` now says the path is kept and no secret belongs in it. Comment-only change.
- `docs/module-repositories.md` has a new section, "What module-state.json keeps of a repository address". Carry a repository token in the query or user info (never stored), or hold it by repository id. Never in the path.
- `tests/module-state-source-url-path-1.17.73.py` documents the limit across all four copies.

The file mode is not changed. Q-CORE-H2A is still open, and Q-CORE-H2B asks whether to store less in the file later.

## Module-facing change

No module-facing change. A search of `modules/` for `system_update`, `_github_json`, `_github_headers`, `_download_to_stage` and `module-state.json` finds no importer. `modules/tacticalupdater` has its own urllib code. `softwarerepository.repository_url` is that module's own model field.

## Tests

- `tests/system-update-redirect-1.17.73.py`: no network; a fake https handler answers. Covers the approved and unapproved hosts, refused schemes, the 5-hop limit, a loop, a non-https first address, and the three call sites end to end.
- `tests/module-state-source-url-path-1.17.73.py`: the path is kept and the rest is dropped in all four copies, the mode is still 0o644, and the docstrings no longer overclaim.

## Not in this release

- The https-to-http downgrade on redirect in `module_repository.py`: a separate small release after this one.
- A fresh contract export into `docs/contracts`: no contract changed, so the newest file stays valid.
- A 0o640 `root:tactical` mode for `module-state.json`: Q-CORE-H2A is open.
- Storing a repository id instead of a path in `module-state.json`: a design change, Q-CORE-H2B.

No request in `reviews/requests/core.md` is closed by this release. The source is the external audit closure report.

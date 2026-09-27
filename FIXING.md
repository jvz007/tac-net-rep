# FIXING.md — Core 1.15.141

## Review scope

This release is intentionally limited to **U2, L06 and L07** from the current Core/UI tracker.

### U2 — publish the `console_required` trust-policy response
The live Core public-contract catalog now includes the exact response object returned when the authenticated trust-policy PUT cannot lower the root-owned trust floor. The documented fields are `status`, `requested_level`, `environment`, `command`, `help_article`, and `help_url`.

### L06 — preserve legacy 200-row history behavior
The existing compatibility paths are now covered by executable view-level tests. Requests without pagination/filter parameters still call the legacy Module v2 job-history and session-audit list functions with a default limit of 200; paged calls retain the newer page-size behavior.

### L07 — trusted Bash portability is part of the normal suite
All privileged helpers continue to resolve Bash from the fixed `/bin/bash`, `/usr/bin/bash` candidate list and require a root-owned, non-writable regular file. The existing boundary tests are now wired into the ordinary contract foundation runner so this cannot regress silently.

No other tracker findings are intentionally changed. U1 remains a UI/server-installer repository finding and is not claimed by this Core release.

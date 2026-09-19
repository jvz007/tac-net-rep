# Tec-Tac Framework 1.13.6

Module Manager multi-file package classification fix.

- Module artifact type is now determined by archive structure rather than filename.
- A normal module package whose filename contains `bundle` is still treated as a normal package.
- Genuine bundle ZIPs are only considered after normal package inspection fails.
- Multi-file upload continues to accept independent module packages and resolve their dependency-safe install sequence.
- Genuine bundle archives remain a separate single-file bundle workflow.
- Added regression coverage preventing filename-based bundle classification from returning.

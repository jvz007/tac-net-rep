# Tec-Tac Core 1.15.106

## M8 — legacy housekeeping policy compatibility

- Repairs legacy saved housekeeping retention values of exactly zero to the category's current safe built-in default when configuration is read.
- Applies the same zero-only compatibility repair inside the privileged helper for already-queued requests from an older Core.
- Keeps destructive-zero behavior disabled and keeps new policy saves strict at 1–3650.
- Leaves negative, malformed, and unsupported policy values invalid rather than silently rewriting them.
- Adds behavioral regression coverage for both the Core read/save path and the privileged helper request path.

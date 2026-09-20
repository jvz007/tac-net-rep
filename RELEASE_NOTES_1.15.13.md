# Tec-Tac Framework 1.15.13

- Bumps `core.server_backup` to 1.5.2.
- Removes the redundant Tec-Tac recovery include for `/opt/tec-tac/etc`; `/opt/tec-tac` already covers it recursively.
- Hardens `make_payload_tar()` to canonicalize requested roots, de-duplicate exact paths and discard any requested descendant already covered by an included directory ancestor.
- Keeps duplicate normalized TAR-member validation enabled as the final packaging integrity boundary.
- Adds regression coverage proving parent + child + duplicate inputs produce one copy of each archive member.

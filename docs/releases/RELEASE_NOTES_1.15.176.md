# Tec-Tac Core 1.15.176

## Resource Directory F5/F6 closure

This release closes the remaining database-behaviour acceptance coverage for Resource Directory site and client deletion.

### F5 - delete site and relocate agents

- Adds a PostgreSQL integration regression using Tactical's real Client, Site, Agent, Role and User models.
- Proves an out-of-scope destination is refused without moving agents, deleting the source site, or recording a Resource Directory audit event.
- Proves that granting the destination site allows the operation, moves every source agent, removes the source site and emits exactly one delete audit event.

### F6 - delete client and relocate agents

- Adds PostgreSQL coverage for a destination inside the client being deleted, which must be refused without changing data or auditing a delete.
- Adds PostgreSQL coverage for an out-of-scope external destination, which must also be refused without changes or audit.
- Proves agents spread across multiple sites under the source client are all moved to an explicitly granted destination site, the source client is deleted, and exactly one delete audit event is emitted.

## Validation

The PostgreSQL regression is intentionally server-side and requires a Tactical installation with its normal PostgreSQL database/settings. It wraps the test transaction and rolls all created rows back at completion.

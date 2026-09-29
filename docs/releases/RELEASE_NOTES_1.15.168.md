# Tec-Tac Core 1.15.168

## Clients & Sites lifecycle and custom fields (F5-F7)

- Adds audited client deletion with atomic relocation of remaining agents to a writable destination site outside the deleted client.
- Adds audited site deletion with atomic relocation of remaining agents to another site under the same client; the last site in a client cannot be deleted.
- Adds Core-managed client/site custom-field value APIs over Tactical's native custom-field models, including type/options/required validation and hidden-field exclusion.
- Advances the additive `core.resources` public contract to `1.3.0` and publishes the new delete/custom-field operations.
- Custom-field audit records intentionally redact values and persist only changed field IDs.
- Keeps destructive resource mutations behind Tactical manage permission, Tec-Tac Resource Directory RBAC, Tactical native write scope, and strict Core audit persistence.

Regression coverage is part of the existing Resource Directory behavioral foundation, extended for F5-F7.

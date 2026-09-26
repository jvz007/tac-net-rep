# Tec-Tac Core 1.15.81

## Resource Directory boundary completion

- Removed the Scheduler's remaining direct imports of Tactical `Client`, `Site`, and `Agent` ORM models.
- Added scoped target-resolution helpers to the Core Resource Directory adapter so Tactical model compatibility remains centralized in one boundary.
- Preserved whole-client targeting semantics: seeing a child site does not grant authority to target the entire parent client; explicit `can_view_clients` membership remains required.
- Site and endpoint scheduler targets continue to use Tactical native role scoping, now through the Resource Directory adapter.
- Added regression coverage that rejects reintroduction of direct Tactical client/agent model imports into Scheduler scope authorization.

## Compatibility

- No public contract or database schema change. Existing Scheduler target payloads and Core Resource Directory APIs remain compatible.

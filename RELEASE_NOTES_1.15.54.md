# Tec-Tac Framework 1.15.54

## Scheduler target-scope authorization

- Enforces Tactical client, site and endpoint scope when operators create, edit, inspect, run or remove schedules.
- Uses canonical Tactical-native target objects so Core authorizes the same identifiers delivered to scheduled handlers.
- Preserves administrator access to legacy/module schedules whose saved target objects predate the canonical target contract, allowing them to be inspected, repaired, run or removed without a server error.
- Returns a controlled authorization denial for non-manager access to malformed legacy Tactical-native target objects instead of exposing an internal scheduler exception.
- Normalizes module-owned targets through the same canonical target contract in `reconcile_schedule()`.
- Migrates safely convertible legacy schedule/run targets to canonical form. Schedules whose native target shape cannot be converted without guessing are disabled and marked for administrator review.
- Adds runtime dispatch protection so malformed Tactical-native targets cannot continue executing if they are inserted outside supported APIs.

## Backwards-compatible dynamic targets

- Keeps the documented dynamic input shape compatible, including `scope.client_id`, `scope.client_ids`, `scope.site_id`, `scope.site_ids`, `scope.agent_id`, `scope.agent_ids`, and equivalent endpoint aliases.
- Converts accepted legacy scope aliases to canonical `scope: {type, ids}` before authorization, persistence and handler dispatch.
- Accepts known legacy dynamic root scope aliases and consumes them into the same canonical scope instead of forwarding alternate target keys to handlers.
- Rejects conflicting or ambiguous scope aliases.
- Reserves Tactical target aliases only at the top level of dynamic `filter`; nested module-owned filter objects may use ordinary `id`, `ids`, or scope-like field names.
- Keeps static Tactical-native targets strict as `type` plus `ids`, preventing alternate static keys from bypassing Core scope checks.

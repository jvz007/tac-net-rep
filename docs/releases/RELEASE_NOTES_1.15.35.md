# Tec-Tac Framework 1.15.35

## Core Tactical Report Manager registration contract

- adds `tec_tac.reporting` as the supported Core-owned integration boundary for report-facing module models;
- exposes `register_reporting_model`, `unregister_reporting_model`, `list_reporting_models`, and `reporting_model_status`;
- synchronizes enabled Tec-Tac reporting models into Tactical's in-memory reporting allow-lists without modules importing `ee.reporting.*`;
- dynamically augments Tactical's existing Report Manager query-schema response while preserving the native static schema file unchanged;
- enforces provider enable/disable availability and blocks disabled providers from report-query model resolution immediately;
- rebuilds reporting registrations naturally across normal module install/update/enable/disable/remove runtime reloads;
- rejects duplicate public reporting IDs, duplicate Django model registrations, global model-name collisions, and collisions with Tactical native reporting models;
- publishes reporting-model provider, state, Django identity, queryable fields and description through Public Contracts;
- documents the provider contract and the ScoutDNS migration path away from direct Tactical reporting internals;
- adds static foundation coverage plus a Tactical-runtime regression test for registration, schema visibility, query resolution, lifecycle state, duplicate handling, Public Contracts and native-model preservation.

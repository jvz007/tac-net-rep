# Core 1.15.182

## Tactical web UI availability contract

- Publishes `tactical_web_ui.installed` and `tactical_web_ui.url` in the authenticated runtime context.
- `installed` is true only when both the standard Tactical UI index and nginx frontend configuration are present.
- Allows the Tec-Tac UI to hide Tactical launch controls on servers where Tactical's web UI is not installed.

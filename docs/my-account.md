# My Account

Tec-Tac exposes self-service account controls under `/api/tfd/account/`. These endpoints always operate on the authenticated Tactical user and never accept another user id.

## Password change

`PUT /api/tfd/account/password/` requires the user's current local password and a new password that passes Django/Tactical password validation. SSO-managed accounts are rejected. After the password changes, Core revokes every other Tactical Knox credential and Tec-Tac trust session while preserving the current session. The mutation is strictly audited.

## Two-factor reset and re-enrollment

`POST /api/tfd/account/totp/reset/` requires both the current password and current TOTP code. Core then clears the Tactical user's TOTP secret, invalidates all Tec-Tac MFA backup codes, audits the reset and revokes every active session including the current one. The user signs in again through the normal Tec-Tac/Tactical flow; because Tactical now reports no TOTP secret, the existing one-time enrollment path is used to issue a new authenticator seed.

SSO-managed accounts cannot use local password or TOTP self-service.

## Other sessions

My Account uses the existing `POST /api/tfd/session/revoke-others/` contract. It preserves the current Tec-Tac/Knox credential and revokes every other credential for the same username, including Knox tokens Tec-Tac has not previously observed.

## Tactical UI preferences

`GET/PUT /api/tfd/account/tactical-ui/` reads and writes Tactical's own user columns, the same ones Tactical's UI writes, so both UIs show one choice. Tec-Tac does not duplicate these values in its preference JSON. Valid double-click values are derived from Tactical model metadata at runtime, so Core follows the installed Tactical version. URL Actions are only listed or assignable when the effective Tactical role can run URL Actions.

Since 1.17.35 the PUT also saves every other UI preference Tactical saves (Tactical 1.5.2 `UserUISerializer`):

| Field | Value |
| --- | --- |
| `dark_mode`, `show_community_scripts`, `clear_search_when_switching` | `true` or `false`. A string such as `"false"` is refused. |
| `default_agent_tbl_tab` | `server`, `workstation` or `mixed` (Tactical's choices, from the model). |
| `client_tree_sort` | `alphafail` or `alpha` (Tactical's choices, from the model). |
| `client_tree_splitter` | a whole number from 1 to 99. |
| `loading_bar_color`, `dash_info_color`, `dash_positive_color`, `dash_negative_color`, `dash_warning_color` | a Quasar colour name such as `red` or `deep-purple-3` (lower case letters, digits and hyphens), or a `#` colour of 3, 4, 6 or 8 hex digits. At most 40 characters. |
| `date_format` | empty or `null` for the server default, otherwise at most 30 letters, digits, spaces and `: / - . , [ ]`. Empty stores `null`. |

Rules for the PUT:

- It is a partial update: only the fields sent change. The `agent_dblclick_action` and `url_action_id` rules are unchanged.
- It is all or nothing. One invalid value (a wrong type, an unknown choice, a value out of range, a colour or date format outside the rules above) gives `400` and saves none of the fields in that request.
- `block_dashboard_login` is not a UI preference. It is a login block, so it is refused as an unknown field. Any other unknown key is refused the same way.
- The answer is the GET object: every value above plus the choices (`agent_dblclick_choices`, `default_agent_tbl_choices`, `client_tree_sort_choices`, and `url_actions` when the person may run URL Actions). The UI builds its form from these lists.
- The audit row `self_tactical_ui_preferences_changed` records the changed field names only, never the values.

The hot-path context (`GET /api/tfd/ui/context/`, `tactical_ui`) carries the three keys it always had and the same scalars (no choice lists), so modules can read them. Core does not change `dateTimeFormat`: it stays the server default. The person's own `date_format` is published as `tactical_ui.date_format` only.

Tec-Tac's own preferences (theme, font scale, navigation, dashboard) are a different store, described in `user-preferences.md`. Saving a Tec-Tac theme does not change `dark_mode`, and `dark_mode` does not change the theme.

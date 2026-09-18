# Tec-Tac backend/framework 1.1.0

## Access and RBAC API

1.1.0 adds a framework-owned, upgrade-safe API surface without editing Tactical tracked source.

### New routes
- `GET /api/tfd/ui/context/` — authenticated Tec-Tac user context: Tactical user ID, username, display name, role, role ID, effective superuser state, effective Tec-Tac extension permissions, and extension permission catalog.
- `GET /api/tfd/access/extensions/` — first-class extension permission catalog for roles visible to the current Tactical operator.
- `GET /api/tfd/access/roles/<role_id>/permissions/` — extension grants for a Tactical role.
- `PUT /api/tfd/access/roles/<role_id>/permissions/` — updates extension grants for that Tactical role.

### Authorization
- Tactical authentication remains authoritative.
- Context requires an authenticated Tactical session.
- Access catalog and role-grant reads use Tactical `can_list_roles` authorization.
- Role-grant changes use Tactical `can_manage_roles` authorization.
- Tactical user superadmins and Tactical superuser roles receive effective access to all currently registered Tec-Tac extension permissions.

### Upgrade safety

The framework registers `tec_tac.apps.TecTacFrameworkConfig` through the existing ignored `local_settings.py` bootstrap and adds `/api/tfd/` routes in memory. No Tactical tracked source files are changed.

### Compatibility

The existing `ExtensionRolePermission` compatibility table remains the persistence store for Tec-Tac extension grants. No new database migration is required in 1.1.0.

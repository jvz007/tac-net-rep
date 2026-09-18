# Tec-Tac backend/framework 1.2.1

## Public extension UI contract

Extends the 1.2.0 module lifecycle contract with optional unauthenticated UI surfaces.

An extension UI manifest may now declare authenticated UI, public UI, or both:

```json
{
  "id": "example",
  "version": "1.0.0",
  "entry": "ui/index.js",
  "public": {
    "entry": "ui/public.js",
    "base_path": "/public/example"
  },
  "permissions": ["example.manage"]
}
```

Rules enforced by package inspection and installed-module discovery:

- `public` is optional.
- `public.entry` is required when `public` is declared.
- At least one of `entry` or `public.entry` must exist.
- Public entry paths must remain inside the extension root.
- Public routes are namespaced exactly below `/public/<extension-id>`.
- When both authenticated and public entries are present they must share one UI bundle directory so the deployed runtime bundle remains atomic.
- Public UI does not imply public backend access. Extension APIs must explicitly use an anonymous permission policy such as DRF `AllowAny` where appropriate.

The module catalog now reports authenticated UI and public UI capabilities separately.

## Reference package

`docs/tutorial-packages/uitest/uitest-0.1.1.zip` exercises both authenticated and public UI registration. Its public route is `/tec-tac/#/public/uitest` after installation and UI synchronization.

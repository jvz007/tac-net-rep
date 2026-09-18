# UI Test package

Use this reference package only on a Tec-Tac development system.

It is intended to prove the browser-driven module lifecycle end to end:

1. upload and inspect the package in **Modules**
2. install it
3. wait for the lifecycle job and Tactical restart to complete
4. reload Tec-Tac
5. confirm `uitest` appears as UI-enabled
6. confirm **UI Test** appears in navigation for a role with `uitest.read` (effective superusers are allowed automatically)
7. remove the module from the Modules page
8. reload and confirm the runtime page/navigation disappears

The package has no database models, so removal is safe for development testing.

Public UI test route after installation and UI synchronization:

```text
/tec-tac/#/public/uitest
```

The public route must render without a Tactical session.

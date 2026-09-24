# Tec-Tac Framework 1.15.42

## Signed UI execution-tree hygiene

- Fixed signed UI updates failing on stale `node_modules/.bin/*` symlinks left by a previous UI build.
- Online UI source updates now use an exact Git worktree cleanup (`git clean -fdx`) after resetting to the resolved release commit and before execution-tree signature verification.
- Generated/ignored UI source artifacts such as `node_modules`, `dist`, `.vite`, and `.env` cannot survive into the signed execution checkout.
- Framework source cleanup keeps its existing less-destructive behavior; the stronger cleanup is scoped to the UI source checkout only.
- Signed-tree verification remains fail-closed and unchanged: symlinks and special files are still rejected rather than ignored.
- Added a regression test that reproduces an ignored `node_modules/.bin/rollup` symlink and proves it is removed before execution verification.

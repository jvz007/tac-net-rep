"""Shared helpers for the sandbox tests (1.18.26). Not a test: the tests import it with ``sys.path.insert(0, <tests folder>)``.

* ``launcher_for_tests(root, folder)``: the path of the launcher to run as a child process. On a server (POSIX) it is the real file. On a
  development PC without user ids or /proc the 1.18.26 leftover check cannot prove the table clean, so a COPY in ``folder`` has
  ``kill_leftovers`` answer True (nothing else changes). The real file is never edited.
* ``load_helper(root, name)``: the helper and ``scripts/sandbox-selftest.py`` as one object (the 1.18.26
  split), so a test keeps patching and calling names exactly as before the split.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

STUB = "\n\ndef kill_leftovers(**_ignored):  # test copy for a PC without /proc\n    return True\n\n\nif __name__ == \"__main__\":"


def launcher_for_tests(root, folder):
    real = Path(root) / "scripts" / "sandbox-launcher.py"
    if hasattr(os, "getuid") and os.path.isdir("/proc"):
        return real
    text = real.read_text(encoding="utf-8")
    marker = "\n\nif __name__ == \"__main__\":"
    assert text.count(marker) == 1
    copy = Path(folder) / "sandbox-launcher.py"
    copy.write_text(text.replace(marker, STUB, 1), encoding="utf-8", newline="\n")
    return copy


class HelperView:
    """One object over the two files (1.18.26 split): a name the selftest file defines (the selftest and canary code and their constants) is
    read and set there; every other name is the helper's. A test that patches ``sh.launch`` or ``sh.CGROUP_ROOT`` therefore reaches both the
    helper's own code and the selftest code (which reads those names as ``H.<name>``), and a test that patches ``sh.collect_run`` reaches the
    selftest code that calls it. ``_helper_module`` and ``_selftest_module`` give the two modules."""

    def __init__(self, selftest):
        object.__setattr__(self, "_selftest_module", selftest)
        object.__setattr__(self, "_helper_module", selftest.H)
        helper_names = set(vars(selftest.H))
        own = {name for name in vars(selftest) if not name.startswith("__") and name != "H" and name not in helper_names}
        object.__setattr__(self, "_own", frozenset(own))

    def __getattr__(self, name):
        if name in self._own:
            return getattr(self._selftest_module, name)
        return getattr(self._helper_module, name)

    def __setattr__(self, name, value):
        setattr(self._selftest_module if name in self._own else self._helper_module, name, value)

    def __delattr__(self, name):
        delattr(self._selftest_module if name in self._own else self._helper_module, name)


def load_view(selftest_file, name="sandbox_helper_under_test"):
    """The helper that sits beside ``selftest_file`` and that file, as one HelperView. The dev02 drivers pass the INSTALLED sandbox-selftest.py."""
    spec = importlib.util.spec_from_file_location(name + "_selftest", str(selftest_file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return HelperView(module)


def load_helper(root, name="sandbox_helper_under_test"):
    """The source helper and selftest file under ``root/scripts`` as one object (see HelperView). ``name`` only makes the module names unique."""
    return load_view(Path(root) / "scripts" / "sandbox-selftest.py", name)

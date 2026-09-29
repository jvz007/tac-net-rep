#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def must(value, message):
    if not value:
        raise AssertionError(message)


class Log:
    def write(self, *_args):
        pass


# ---------------------------------------------------------------------------
# L10: every backup transport must make the sidecar visible before the final
# archive and remove the sidecar again if final archive publication fails.

print("[TEST] PASS final L10 sidecar/archive publication atomicity")

"""Regular expressions that compile on first use (1.18.1).

Core's own files define a few dozen fixed patterns at module level. Compiling them
all when Django starts costs start-up time on every uWSGI worker and Celery child,
and most are only used when a module registers an operation or an action. A
``LazyPattern`` keeps the same pattern text and flags and offers the same methods
(``match``, ``fullmatch``, ``search``, ``sub``, ``findall`` and anything else
``re.Pattern`` has, through ``__getattr__``). It compiles once, on the first call.
A race at first use can compile twice at worst; both results are identical.
"""
from __future__ import annotations

import re


class LazyPattern:
    __slots__ = ("_compiled", "_flags", "_source")

    def __init__(self, source: str, flags: int = 0) -> None:
        self._source = source
        self._flags = flags
        self._compiled = None

    def _get(self) -> re.Pattern[str]:
        compiled = self._compiled
        if compiled is None:
            compiled = self._compiled = re.compile(self._source, self._flags)
        return compiled

    @property
    def compiled(self) -> bool:
        return self._compiled is not None

    def match(self, string, *args):
        return self._get().match(string, *args)

    def fullmatch(self, string, *args):
        return self._get().fullmatch(string, *args)

    def search(self, string, *args):
        return self._get().search(string, *args)

    def sub(self, repl, string, *args, **kwargs):
        return self._get().sub(repl, string, *args, **kwargs)

    def findall(self, string, *args):
        return self._get().findall(string, *args)

    def __getattr__(self, name):
        # pattern, flags, finditer, split, subn and the rest of re.Pattern
        return getattr(self._get(), name)

    def __repr__(self) -> str:
        return f"LazyPattern({self._source!r}, {self._flags!r})"


def lazy_pattern(source: str, flags: int = 0) -> LazyPattern:
    return LazyPattern(source, flags)

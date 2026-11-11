"""Analyzer plugin interface.

Subclasses set `name` and `applies_to`, then implement `run`. Everything else is
handled by the pipeline, so adding a check is a single small module.
"""

from __future__ import annotations

from maltriage.models import FileKind, Finding, SampleContext


class Analyzer:
    name: str = ""
    applies_to: set[FileKind] | None = None  # None means every file kind

    def applies(self, kind: FileKind) -> bool:
        return self.applies_to is None or kind in self.applies_to

    def run(self, ctx: SampleContext) -> list[Finding]:
        raise NotImplementedError


from maltriage.registry import register_analyzer  # noqa: E402,F401

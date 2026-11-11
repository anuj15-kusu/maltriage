"""Parser interface. A parser turns bytes into structured artifacts only - no verdicts."""

from __future__ import annotations

from typing import Protocol

from maltriage.models import FileKind, SampleContext


class Parser(Protocol):
    name: str
    kinds: set[FileKind]

    def parse(self, ctx: SampleContext) -> None:
        """Populate ctx.parsed with format artefacts."""


from maltriage.registry import register_parser  # noqa: E402,F401

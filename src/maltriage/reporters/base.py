"""Renderer interface and template location helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from maltriage.models import Report


class Renderer(Protocol):
    name: str
    suffix: str

    def render(self, report: Report, *, defang: bool = True) -> str:
        """Serialise a report to text."""


def template_dir() -> Path:
    """Find templates/ both from a source checkout and an installed package."""
    here = Path(__file__).resolve()
    for candidate in (here.parents[3] / "templates", Path.cwd() / "templates"):
        if (candidate / "report.html.j2").exists():
            return candidate
    return here.parents[3] / "templates"


SEVERITY_COLORS = {
    "critical": "#8e0e00",
    "high": "#c0392b",
    "medium": "#d68910",
    "low": "#2471a3",
    "info": "#566573",
}

BAND_COLORS = {
    "malicious": "#8e0e00",
    "likely_malicious": "#c0392b",
    "suspicious": "#d68910",
    "clean": "#1e8449",
}

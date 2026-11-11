"""Renderer registry."""

from __future__ import annotations

from maltriage.reporters.base import Renderer
from maltriage.reporters.html_report import HTMLRenderer
from maltriage.reporters.json_report import JSONRenderer
from maltriage.reporters.markdown_report import MarkdownRenderer
from maltriage.reporters.stix import STIXRenderer

_RENDERERS: dict[str, Renderer] = {
    "json": JSONRenderer(),
    "html": HTMLRenderer(),
    "markdown": MarkdownRenderer(),
    "stix": STIXRenderer(),
}

ALIASES = {"md": "markdown", "stix2": "stix"}


def get_renderer(name: str) -> Renderer:
    key = ALIASES.get(name.lower(), name.lower())
    if key not in _RENDERERS:
        raise KeyError(f"unknown report format {name!r}; choose from {', '.join(_RENDERERS)}")
    return _RENDERERS[key]


def available() -> list[str]:
    return list(_RENDERERS)

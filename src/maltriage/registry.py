"""Plugin registries. Adding a parser or analyzer means adding one module."""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any

_PARSERS: dict[str, Any] = {}
_ANALYZERS: dict[str, Any] = {}
_LOADED = False


def _import_package(package_name: str, skip: set[str]) -> None:
    package = importlib.import_module(package_name)
    for module in pkgutil.iter_modules(package.__path__):
        if module.name.startswith("_") or module.name in skip:
            continue
        importlib.import_module(f"{package_name}.{module.name}")


def load_plugins() -> None:
    """Import every parser/analyzer module so their decorators run."""
    global _LOADED
    if _LOADED:
        return
    _import_package("maltriage.parsers", {"base"})
    _import_package("maltriage.analyzers", {"base"})
    _LOADED = True


def register_parser(cls: Any) -> Any:
    instance = cls()
    for kind in instance.kinds:
        _PARSERS.setdefault(kind, instance)
    return cls


def register_analyzer(cls: Any) -> Any:
    instance = cls()
    _ANALYZERS.setdefault(instance.name, instance)
    return cls


def parsers() -> dict[str, Any]:
    load_plugins()
    return dict(_PARSERS)


def analyzers() -> list[Any]:
    load_plugins()
    return list(_ANALYZERS.values())


def reset() -> None:
    """Test helper."""
    global _LOADED
    _PARSERS.clear()
    _ANALYZERS.clear()
    _LOADED = False

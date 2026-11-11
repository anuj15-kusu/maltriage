"""Runtime configuration, loaded from environment / .env.

`.env` is resolved relative to the **project root**, not the current working
directory, so scans behave the same no matter where the command is invoked from.

Resolution order for the env files (lowest priority first):

1. ``<current directory>/.env``
2. ``<project root>/.env``  -- wins over the working directory

The project root is found from ``MALTRIAGE_PROJECT_ROOT`` if set, otherwise by
walking up from this package (editable installs) and then from the current
directory, looking for a ``pyproject.toml`` that names this project.
``MALTRIAGE_ENV_FILE`` bypasses the search and loads exactly one file.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_settings.sources import DotEnvSettingsSource

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"
TEMPLATE_DIR = PACKAGE_DIR.parent.parent / "templates"

ENV_FILENAME = ".env"
PROJECT_MARKER = 'name = "maltriage"'
ENV_FILE_OVERRIDE = "MALTRIAGE_ENV_FILE"
PROJECT_ROOT_OVERRIDE = "MALTRIAGE_PROJECT_ROOT"


def _looks_like_project_root(directory: Path) -> bool:
    pyproject = directory / "pyproject.toml"
    try:
        if not pyproject.is_file():
            return False
        return PROJECT_MARKER in pyproject.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False


def find_project_root() -> Path | None:
    """Locate this project's root directory, or None when it cannot be found."""
    override = os.environ.get(PROJECT_ROOT_OVERRIDE)
    if override:
        candidate = Path(override).expanduser().resolve()
        return candidate if candidate.is_dir() else None

    seen: set[Path] = set()
    for start in (PACKAGE_DIR, Path.cwd().resolve()):
        for candidate in (start, *start.parents):
            if candidate in seen:
                continue
            seen.add(candidate)
            if _looks_like_project_root(candidate):
                return candidate
    return None


def env_files() -> tuple[Path, ...]:
    """Env files to load, lowest priority first."""
    override = os.environ.get(ENV_FILE_OVERRIDE)
    if override:
        return (Path(override).expanduser(),)

    files = [Path.cwd() / ENV_FILENAME]
    root = find_project_root()
    if root is not None:
        root_env = root / ENV_FILENAME
        if root_env.resolve() not in {path.resolve() for path in files}:
            files.append(root_env)
    return tuple(files)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        env_prefix="MALTRIAGE_",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    # --- safety limits -------------------------------------------------
    offline: bool = False
    max_file_mb: int = 256
    max_archive_depth: int = 2
    max_archive_files: int = 200
    max_archive_mb: int = 200
    max_archive_ratio: int = 100
    analyzer_timeout: int = 60

    # --- paths ---------------------------------------------------------
    report_dir: Path = Path("out")
    cache_path: Path = Path(".cache/maltriage.db")
    rules_dir: Path = Path("rules")

    # --- credentials ---------------------------------------------------
    vt_api_key: str | None = Field(default=None, validation_alias=AliasChoices("VT_API_KEY"))
    mb_auth_key: str | None = Field(default=None, validation_alias=AliasChoices("MB_AUTH_KEY"))

    # --- enrichment behaviour ------------------------------------------
    vt_min_interval: float = 15.0  # public tier allows 4 requests/minute
    vt_cache_days: int = 7
    submit: bool = False  # upload samples to VirusTotal only when explicitly asked

    # --- reporting -----------------------------------------------------
    defang: bool = True

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: Any,
        env_settings: Any,
        dotenv_settings: Any,
        file_secret_settings: Any,
    ) -> tuple[Any, ...]:
        """Replace the default dotenv source with one that knows the project root."""
        return (
            init_settings,
            env_settings,
            DotEnvSettingsSource(
                settings_cls,
                env_file=env_files(),
                env_file_encoding="utf-8",
                env_prefix="MALTRIAGE_",
                case_sensitive=False,
            ),
            file_secret_settings,
        )

    def in_scope(self, path: Path) -> bool:
        """True when the file is small enough to be loaded into memory."""
        return path.stat().st_size <= self.max_file_mb * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

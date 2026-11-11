"""Runtime configuration, loaded from environment / .env."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"
TEMPLATE_DIR = PACKAGE_DIR.parent.parent / "templates"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
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

    def in_scope(self, path: Path) -> bool:
        """True when the file is small enough to be loaded into memory."""
        return path.stat().st_size <= self.max_file_mb * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

from __future__ import annotations

from pathlib import Path

import pytest

from maltriage.config import Settings, get_settings

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _ignore_real_dotenv(tmp_path: Path, monkeypatch):
    """Never read the developer's own .env, which may hold a live API key."""
    monkeypatch.setenv("MALTRIAGE_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.delenv("MALTRIAGE_PROJECT_ROOT", raising=False)
    yield


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        cache_path=tmp_path / "cache.db",
        rules_dir=REPO_ROOT / "rules",
        report_dir=tmp_path / "out",
        offline=True,
        vt_api_key=None,
        mb_auth_key=None,
        analyzer_timeout=30,
    )


@pytest.fixture
def pipeline(settings: Settings):
    from maltriage.pipeline import Pipeline

    instance = Pipeline(settings=settings)
    yield instance
    instance.close()

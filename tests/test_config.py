from __future__ import annotations

from pathlib import Path

import pytest

from maltriage.config import Settings, env_files, find_project_root, get_settings

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def clean_env(monkeypatch):
    """Undo the global isolation so the real resolution logic runs."""
    monkeypatch.delenv("MALTRIAGE_ENV_FILE", raising=False)
    monkeypatch.delenv("MALTRIAGE_PROJECT_ROOT", raising=False)
    for name in ("VT_API_KEY", "MB_AUTH_KEY"):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _fake_project(tmp_path: Path, env_body: str) -> Path:
    root = tmp_path / "fake-project"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname = "maltriage"\n', encoding="utf-8")
    (root / ".env").write_text(env_body, encoding="utf-8")
    nested = root / "some" / "deep" / "dir"
    nested.mkdir(parents=True)
    return nested


def test_project_root_is_detected(clean_env):
    assert find_project_root() == REPO_ROOT


def test_env_files_point_at_the_project_root(clean_env):
    files = env_files()
    assert files, "expected at least one candidate env file"
    assert all(path.is_absolute() for path in files)
    assert any(path.resolve() == (REPO_ROOT / ".env").resolve() for path in files)


def test_settings_read_root_env_from_a_nested_folder(tmp_path: Path, monkeypatch, clean_env):
    """The whole point: running from a sub-directory still finds the project .env."""
    nested = _fake_project(tmp_path, "VT_API_KEY=from_project_root\nMALTRIAGE_OFFLINE=true\n")
    monkeypatch.chdir(nested)
    monkeypatch.setenv("MALTRIAGE_PROJECT_ROOT", str(nested.parents[2]))

    settings = Settings()
    assert settings.vt_api_key == "from_project_root"
    assert settings.offline is True


def test_env_is_not_read_from_the_working_directory_only(tmp_path: Path, monkeypatch, clean_env):
    nested = _fake_project(tmp_path, "VT_API_KEY=from_project_root\n")
    (nested / "unrelated.txt").write_text("x", encoding="utf-8")
    monkeypatch.chdir(nested)
    monkeypatch.setenv("MALTRIAGE_PROJECT_ROOT", str(nested.parents[2]))

    # A .env next to the sample is ignored; the project root's file is authoritative.
    (nested / ".env").write_text("VT_API_KEY=from_cwd\n", encoding="utf-8")
    assert Settings().vt_api_key == "from_project_root"


def test_explicit_env_file_override(tmp_path: Path, monkeypatch, clean_env):
    custom = tmp_path / "custom.env"
    custom.write_text("VT_API_KEY=from_override\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MALTRIAGE_ENV_FILE", str(custom))

    assert env_files() == (custom,)
    assert Settings().vt_api_key == "from_override"


def test_os_environment_wins_over_dotenv(tmp_path: Path, monkeypatch, clean_env):
    custom = tmp_path / "custom.env"
    custom.write_text("VT_API_KEY=from_file\n", encoding="utf-8")
    monkeypatch.setenv("MALTRIAGE_ENV_FILE", str(custom))
    monkeypatch.setenv("VT_API_KEY", "from_shell")

    assert Settings().vt_api_key == "from_shell"


def test_missing_env_file_is_not_an_error(tmp_path: Path, monkeypatch, clean_env):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MALTRIAGE_ENV_FILE", str(tmp_path / "nope.env"))

    settings = Settings()
    assert settings.vt_api_key is None
    assert settings.offline is False

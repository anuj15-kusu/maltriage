"""The secret guard, and the tree it protects.

`tools/secret_guard.py` is the scanner the pre-commit hook runs. These tests keep
it honest: they prove it catches the shapes a key actually leaks in, and prove it
does not trip over the fixtures and hashes this repository legitimately holds.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = REPO_ROOT / "tools" / "secret_guard.py"

# Carries a placeholder marker, so the guard ignores this file while the patterns
# still have a value they can extract and compare.
SAMPLE_VALUE = "example1234567890abcdef12345678"


def _load_guard() -> ModuleType:
    spec = importlib.util.spec_from_file_location("secret_guard", GUARD_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = _load_guard()


def _clean_tree(root: Path) -> None:
    (root / ".gitignore").write_text(".env\n", encoding="utf-8")
    (root / ".dockerignore").write_text(".env\n", encoding="utf-8")
    (root / ".env.example").write_text("VT_API_KEY=\n", encoding="utf-8")


def test_the_repository_has_no_leaked_secret() -> None:
    assert guard.scan() == []


def test_the_env_template_ships_without_secrets() -> None:
    template = REPO_ROOT / ".env.example"
    assert template.exists(), ".env.example must exist so users have a template to copy"

    filled = [name for _, name, value in guard.secret_assignments(template) if value]
    assert filled == [], f".env.example must ship empty, found: {filled}"


def test_no_dotenv_file_is_tracked() -> None:
    tracked = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in guard.tracked_files(REPO_ROOT)
        if path.name in guard.ENV_NAMES
    ]
    assert tracked == []


def test_dotenv_is_ignored_by_git_and_docker() -> None:
    for name in guard.IGNORE_FILES:
        entries = {line.strip() for line in guard.read_lines(REPO_ROOT / name)}
        assert ".env" in entries, f"{name} must ignore .env"


def test_a_filled_template_is_reported_end_to_end(tmp_path: Path) -> None:
    _clean_tree(tmp_path)
    assert guard.scan(tmp_path) == []

    fake = hashlib.sha256(b"end to end").hexdigest()
    (tmp_path / ".env.example").write_text(f"VT_API_KEY={fake}\n", encoding="utf-8")

    problems = guard.scan(tmp_path)
    assert len(problems) == 1, problems
    assert ".env.example:1 VT_API_KEY" in problems[0]
    assert fake not in problems[0], "the report must never echo the value"


def test_the_guard_flags_a_leaked_key(tmp_path: Path) -> None:
    """Self-test: the detector must catch the shape of the value that leaked."""
    fake = hashlib.sha256(b"maltriage secret guard self-test").hexdigest()
    sample = tmp_path / "leaked.env"
    sample.write_text(
        f"VT_API_KEY={fake}\nMB_AUTH_KEY={fake}\n# leaked: VT_API_KEY={fake}\n",
        encoding="utf-8",
    )

    found = list(guard.secret_assignments(sample))
    assert [name for _, name, _ in found] == ["VT_API_KEY", "MB_AUTH_KEY", "VT_API_KEY"]
    assert all(guard.looks_like_a_key(value) for _, _, value in found)


def test_the_guard_ignores_placeholders_and_fixtures() -> None:
    for value in (
        "",
        "...",
        "your-key-here",
        "CHANGEME",
        "CANARY_key_hygiene_test_value",
        "from_project_root",
        "test-key",
        "null",
        "None",
    ):
        assert not guard.looks_like_a_key(value), value


def test_assignments_are_matched_in_the_formats_people_actually_paste() -> None:
    for line in (
        f"VT_API_KEY={SAMPLE_VALUE}",
        f"export VT_API_KEY={SAMPLE_VALUE}",
        f"  VT_API_KEY: {SAMPLE_VALUE}",
        f'  "vt_api_key": "{SAMPLE_VALUE}"',
        f"- VT_API_KEY: {SAMPLE_VALUE}",
        f"# VT_API_KEY={SAMPLE_VALUE}",
        f"  # MB_AUTH_KEY: {SAMPLE_VALUE}",
    ):
        match = guard.SECRET_ASSIGNMENT.match(line)
        if match is None:
            assert line.lstrip().startswith(("#", "-")), line
            match = guard.COMMENT_SECRET.search(line)
        assert match is not None, line
        assert match.group("value") == SAMPLE_VALUE, line

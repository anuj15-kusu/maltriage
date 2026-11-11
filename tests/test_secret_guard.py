"""A credential must never reach a tracked file.

`.env.example` ships with the repository, so it has to stay empty. The real
secrets belong in `.env`, which is never tracked, and no tracked file may hold a
value that looks like a live key.

The scan is name-based on purpose. This repository legitimately contains hashes
(EICAR's SHA-256, rule metadata) and test fixtures such as
`CANARY_key_hygiene_test_value`, which a generic high-entropy scan would flag.
"""

from __future__ import annotations

import hashlib
import math
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

TEMPLATE_SUFFIXES = (".example", ".sample", ".template")
IGNORED_ENV_NAMES = (".env", ".env.local", ".env.production", ".env.development")

SECRET_ASSIGNMENT = re.compile(
    r"""
    ^\s*
    (?:\#\s*)?                                 # commented-out assignment
    (?:-\s*)?                                  # yaml list item
    ["']?
    (?:export\s+)?
    (?P<name>[A-Za-z0-9_]*
        (?:API_?KEY|AUTH_?KEY|ACCESS_?KEY|TOKEN|SECRET|PASSWORD|PASSWD)
        [A-Za-z0-9_]*)
    ["']?\s*[:=]\s*
    (?P<quote>["']?)
    (?P<value>[^\s"'#]*)
    """,
    re.IGNORECASE | re.VERBOSE,
)

SECRET_NAME = (
    r"[A-Za-z0-9_]*"
    r"(?:API_?KEY|AUTH_?KEY|ACCESS_?KEY|TOKEN|SECRET|PASSWORD|PASSWD)"
    r"[A-Za-z0-9_]*"
)

COMMENT_PREFIXES = ("#", "//", ";")

# Inside a comment the name need not start the line: "# leaked: VT_API_KEY=..."
# still leaks the credential.
COMMENT_SECRET = re.compile(
    rf"(?P<name>{SECRET_NAME})\s*[:=]\s*[\"']?(?P<value>[^\s\"'#]*)",
    re.IGNORECASE,
)

# Values that read as a placeholder rather than a credential.
PLACEHOLDER_MARKERS = (
    "...",
    "<",
    ">",
    "$",
    "{",
    "%",
    "your",
    "example",
    "placeholder",
    "dummy",
    "fake",
    "canary",
    "change",
    "redacted",
    "not-a-real",
    "xxxx",
)

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".cache",
    "out",
    "demo-reports",
    "node_modules",
}
SKIP_SUFFIXES = {".pyc", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".woff", ".woff2"}
MAX_BYTES = 1_000_000


def _tracked_files() -> list[Path]:
    """Every file git would publish, or every source file outside a checkout."""
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
            timeout=60,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return _walked_files()

    names = [name for name in completed.stdout.decode("utf-8", "replace").split("\0") if name]
    if not names:
        return _walked_files()
    return [REPO_ROOT / name for name in names]


def _walked_files() -> list[Path]:
    found: list[Path] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        relative = path.relative_to(REPO_ROOT)
        if set(relative.parts) & SKIP_DIRS or relative.parts[0].startswith(".venv"):
            continue
        if path.is_file() and path.suffix not in SKIP_SUFFIXES:
            found.append(path)
    return found


def _lines(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if len(data) > MAX_BYTES or b"\0" in data[:8192]:
        return []
    return data.decode("utf-8", "replace").splitlines()


def _secret_assignments(path: Path) -> Iterator[tuple[int, str, str]]:
    """Yield (line number, variable name, value) for secret-looking assignments."""
    for lineno, line in enumerate(_lines(path), start=1):
        match = SECRET_ASSIGNMENT.match(line)
        if match is not None:
            yield lineno, match.group("name"), match.group("value").strip()
            continue
        if line.lstrip().startswith(COMMENT_PREFIXES):
            commented = COMMENT_SECRET.search(line)
            if commented is not None:
                yield lineno, commented.group("name"), commented.group("value").strip()


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    total = len(value)
    return -sum(count / total * math.log2(count / total) for count in counts.values())


def _looks_like_a_key(value: str) -> bool:
    """A value shaped like a real credential rather than a placeholder."""
    value = value.strip().strip("\"'")
    if len(value) < 16:
        return False
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return False
    if re.fullmatch(r"[A-Za-z0-9_\-+/=.:]+", value) is None:
        return False
    if not any(character.isalpha() for character in value):
        return False
    mixed = any(not character.isalpha() for character in value)
    if not mixed and len(value) < 40:
        return False
    return _entropy(value) >= 3.2


def test_no_tracked_file_holds_a_real_looking_secret() -> None:
    offenders = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno} {name}"
        for path in _tracked_files()
        for lineno, name, value in _secret_assignments(path)
        if _looks_like_a_key(value)
    ]
    assert offenders == [], (
        "a credential looks committed; move it to .env, rotate the key and remove it "
        "from history: " + ", ".join(offenders)
    )


def test_the_env_template_ships_without_secrets() -> None:
    template = REPO_ROOT / ".env.example"
    assert template.exists(), ".env.example must exist so users have a template to copy"

    templates = {template}
    templates.update(
        path
        for path in _tracked_files()
        if path.name.endswith(TEMPLATE_SUFFIXES) and path.is_file()
    )

    filled = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno} {name}"
        for path in sorted(templates)
        for lineno, name, value in _secret_assignments(path)
        if value
    ]
    assert filled == [], "template files must ship with empty values: " + ", ".join(filled)


def test_no_dotenv_file_is_tracked() -> None:
    tracked = {
        path.relative_to(REPO_ROOT).as_posix()
        for path in _tracked_files()
        if path.name in IGNORED_ENV_NAMES
    }
    assert tracked == set(), f"these files must never be tracked: {sorted(tracked)}"


def test_dotenv_is_ignored_by_git_and_docker() -> None:
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in [line.strip() for line in gitignore]
    assert ".env" in [line.strip() for line in dockerignore]


def test_the_guard_flags_a_leaked_key(tmp_path: Path) -> None:
    """Self-test: the detector must catch the shape of the value that leaked."""
    fake = hashlib.sha256(b"maltriage secret guard self-test").hexdigest()
    sample = tmp_path / "leaked.env"
    sample.write_text(
        f"VT_API_KEY={fake}\nMB_AUTH_KEY={fake}\n# leaked: VT_API_KEY={fake}\n",
        encoding="utf-8",
    )

    found = list(_secret_assignments(sample))
    assert [name for _, name, _ in found] == ["VT_API_KEY", "MB_AUTH_KEY", "VT_API_KEY"]
    assert all(_looks_like_a_key(value) for _, _, value in found)


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
        assert not _looks_like_a_key(value), value


# Carries a placeholder marker, so the guard ignores this file while the pattern
# still has a value it can extract and compare.
SAMPLE_VALUE = "example1234567890abcdef12345678"


def test_templates_are_matched_in_the_formats_people_actually_paste() -> None:
    for line in (
        f"VT_API_KEY={SAMPLE_VALUE}",
        f"export VT_API_KEY={SAMPLE_VALUE}",
        f"  VT_API_KEY: {SAMPLE_VALUE}",
        f'"vt_api_key": "{SAMPLE_VALUE}"',
        f"- VT_API_KEY: {SAMPLE_VALUE}",
        f"# VT_API_KEY={SAMPLE_VALUE}",
        f"  # MB_AUTH_KEY: {SAMPLE_VALUE}",
    ):
        match = SECRET_ASSIGNMENT.match(line)
        assert match is not None, line
        assert match.group("value") == SAMPLE_VALUE, line

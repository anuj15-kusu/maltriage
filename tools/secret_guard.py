"""Fail when a credential reaches a tracked file.

`.env.example` ships with the repository, so it must stay empty; the real secrets
belong in `.env`, which is never tracked, and no tracked file may hold a value
that looks like a live key.

Standard library only, so the pre-commit hook runs without installed packages:

    python tools/secret_guard.py

Exit code 0 means clean, 1 means something is staged for publication that should
not be. Every message names the file, line and variable and never the value
itself, so the output is safe to paste into a CI log.

The scan is name-based on purpose. The repository legitimately contains hashes
(EICAR's SHA-256, rule metadata) and canary fixtures such as
`CANARY_key_hygiene_test_value`, which a generic high-entropy scan would flag.
"""

from __future__ import annotations

import math
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

TEMPLATE_SUFFIXES = (".example", ".sample", ".template")
ENV_NAMES = (".env", ".env.local", ".env.production", ".env.development")
IGNORE_FILES = (".gitignore", ".dockerignore")

SECRET_NAME = (
    r"[A-Za-z0-9_]*"
    r"(?:API_?KEY|AUTH_?KEY|ACCESS_?KEY|TOKEN|SECRET|PASSWORD|PASSWD)"
    r"[A-Za-z0-9_]*"
)

# A whole line that assigns a secret: .env, YAML, JSON, TOML, source, or the same
# assignment commented out.
SECRET_ASSIGNMENT = re.compile(
    rf"""
    ^\s*
    (?:\#\s*)?                                 # commented-out assignment
    (?:-\s*)?                                  # yaml list item
    ["']?
    (?:export\s+)?
    (?P<name>{SECRET_NAME})
    ["']?\s*[:=]\s*
    (?P<quote>["']?)
    (?P<value>[^\s"'#]*)
    """,
    re.IGNORECASE | re.VERBOSE,
)

COMMENT_PREFIXES = ("#", "//", ";")

# Inside a comment the variable need not start the line: "# leaked: VT_API_KEY=..."
# still commits the credential.
COMMENT_SECRET = re.compile(
    rf"""(?P<name>{SECRET_NAME})\s*[:=]\s*["']?(?P<value>[^\s"'#]*)""",
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


def git_toplevel(root: Path) -> Path | None:
    """The repository that contains `root`, or None when there is no checkout."""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root,
            capture_output=True,
            check=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    toplevel = completed.stdout.strip()
    return Path(toplevel).resolve() if toplevel else None


def tracked_files(root: Path) -> list[Path]:
    """Every file git would publish, or every source file outside a checkout."""
    if git_toplevel(root) != root.resolve():
        return walked_files(root)

    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            capture_output=True,
            check=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return walked_files(root)

    names = [name for name in completed.stdout.decode("utf-8", "replace").split("\0") if name]
    return [root / name for name in names] or walked_files(root)


def walked_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if set(relative.parts) & SKIP_DIRS or relative.parts[0].startswith(".venv"):
            continue
        if path.is_file() and path.suffix not in SKIP_SUFFIXES:
            found.append(path)
    return found


def read_lines(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if len(data) > MAX_BYTES or b"\0" in data[:8192]:
        return []
    return data.decode("utf-8", "replace").splitlines()


def secret_assignments(path: Path) -> Iterator[tuple[int, str, str]]:
    """Yield (line number, variable name, value) for secret-looking assignments."""
    for lineno, line in enumerate(read_lines(path), start=1):
        match = SECRET_ASSIGNMENT.match(line)
        if match is not None:
            yield lineno, match.group("name"), match.group("value").strip()
            continue
        if line.lstrip().startswith(COMMENT_PREFIXES):
            commented = COMMENT_SECRET.search(line)
            if commented is not None:
                yield lineno, commented.group("name"), commented.group("value").strip()


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    total = len(value)
    return -sum(count / total * math.log2(count / total) for count in counts.values())


def looks_like_a_key(value: str) -> bool:
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
    return entropy(value) >= 3.2


def scan(root: Path = REPO_ROOT) -> list[str]:
    """One message per problem; the list is empty when the tree is clean."""
    problems: list[str] = []

    for path in tracked_files(root):
        relative = path.relative_to(root).as_posix()
        if path.name in ENV_NAMES:
            problems.append(f"{relative}: a .env file must never be tracked")
            continue
        template = path.name.endswith(TEMPLATE_SUFFIXES)
        for lineno, name, value in secret_assignments(path):
            if template and value:
                problems.append(f"{relative}:{lineno} {name}: templates must ship empty")
            elif looks_like_a_key(value):
                problems.append(f"{relative}:{lineno} {name}: looks like a live credential")

    for name in IGNORE_FILES:
        ignore = root / name
        if not ignore.is_file():
            problems.append(f"{name}: missing, so .env has no protection")
            continue
        if ".env" not in {line.strip() for line in read_lines(ignore)}:
            problems.append(f"{name}: must ignore .env")

    return problems


def main() -> int:
    problems = scan()
    if not problems:
        print(f"secret guard: clean ({len(tracked_files(REPO_ROOT))} tracked files)")
        return 0

    print("secret guard: refusing, a credential may reach git", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    print(
        "Move the value to .env (untracked), rotate the key, and remove it from history.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

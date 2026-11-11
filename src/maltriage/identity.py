"""Hashes and fuzzy hashes used for identification and dedupe."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

try:  # pure-python ssdeep; never touches the network
    import ppdeep
except Exception:  # pragma: no cover - defensive
    ppdeep = None  # type: ignore[assignment]

CHUNK = 1024 * 1024
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def resolve_hash(target: str) -> str:
    """Turn either a SHA-256 hex digest or a file path into a SHA-256 digest."""
    if SHA256_RE.match(target):
        return target.lower()
    path = Path(target)
    if not path.is_file():
        raise ValueError(f"expected a SHA-256 hash or a file path, got: {target!r}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fuzzy_hash(data: bytes) -> str | None:
    """ssdeep-compatible fuzzy hash, or None when unavailable."""
    if ppdeep is None:
        return None
    try:
        return ppdeep.hash(data)
    except Exception:
        return None


def fuzzy_compare(a: str, b: str) -> int:
    """Similarity 0-100 between two fuzzy hashes."""
    if ppdeep is None or not a or not b:
        return 0
    try:
        return int(ppdeep.compare(a, b))
    except Exception:
        return 0

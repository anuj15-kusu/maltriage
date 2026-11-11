"""String extraction, entropy and simple obfuscation helpers."""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
BASE64_RE = re.compile(rb"[A-Za-z0-9+/]{32,}={0,2}")
MAX_STRINGS = 20000


def extract(data: bytes, limit: int = MAX_STRINGS) -> list[str]:
    """Extract printable ASCII and UTF-16LE strings, de-duplicated in order."""
    seen: dict[str, None] = {}
    for match in ASCII_RE.finditer(data):
        seen.setdefault(match.group().decode("ascii", "ignore"), None)
        if len(seen) >= limit:
            return list(seen)
    for match in UTF16_RE.finditer(data):
        seen.setdefault(match.group().decode("utf-16-le", "ignore"), None)
        if len(seen) >= limit:
            break
    return list(seen)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def base64_blobs(data: bytes, min_len: int = 32, limit: int = 10) -> list[str]:
    """Long base64-looking runs that actually decode to readable bytes."""
    found: list[str] = []
    for match in BASE64_RE.finditer(data):
        if len(found) >= limit:
            break
        raw = match.group()
        if len(raw) % 4:
            raw = raw[: len(raw) - (len(raw) % 4)]
        try:
            decoded = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) < min_len // 2:
            continue
        printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
        if decoded and printable / len(decoded) > 0.75:
            found.append(decoded.decode("ascii", "ignore")[:400])
    return found


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)

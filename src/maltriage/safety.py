"""Input validation and archive-bomb protection.

Nothing in this module executes or otherwise touches the sample; it only decides
whether a file is safe to hand to the parsers.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath

MB = 1024 * 1024


class SafetyError(RuntimeError):
    """The input cannot be triaged safely."""


@dataclass
class ArchiveInspection:
    members: list[dict] = field(default_factory=list)
    total_uncompressed: int = 0
    total_compressed: int = 0
    truncated: bool = False
    problems: list[str] = field(default_factory=list)

    @property
    def ratio(self) -> float:
        if self.total_compressed <= 0:
            return 0.0
        return self.total_uncompressed / self.total_compressed


def check_file(path, max_mb: int) -> int:
    """Validate a path and return its size in bytes."""
    if not path.exists():
        raise SafetyError(f"file not found: {path}")
    if not path.is_file():
        raise SafetyError(f"not a regular file: {path}")
    size = path.stat().st_size
    if size == 0:
        raise SafetyError(f"empty file: {path}")
    if size > max_mb * MB:
        raise SafetyError(f"file is {size / MB:.1f} MiB, limit is {max_mb} MiB")
    return size


def safe_member_name(name: str) -> bool:
    """Reject archive entries that would escape the extraction root."""
    normalized = name.replace("\\", "/")
    if not normalized:
        return False
    if re.match(r"^[A-Za-z]:", normalized):
        return False
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        return False
    return True


def inspect_zip(data: bytes, *, max_files: int, max_mb: int, max_ratio: int) -> ArchiveInspection:
    """Read the central directory only - never extract."""
    result = ArchiveInspection()
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(data)) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        result.problems.append(f"unreadable zip: {exc}")
        return result

    for info in infos:
        if len(result.members) >= max_files:
            result.truncated = True
            result.problems.append(f"archive has more than {max_files} entries; rest skipped")
            break
        if not safe_member_name(info.filename):
            result.problems.append(f"unsafe member path rejected: {info.filename!r}")
            continue
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            result.problems.append(f"symlink member rejected: {info.filename!r}")
            continue
        result.members.append(
            {
                "name": info.filename,
                "size": info.file_size,
                "compressed": info.compress_size,
                "is_dir": info.is_dir(),
            }
        )
        result.total_uncompressed += info.file_size
        result.total_compressed += info.compress_size

    if result.total_uncompressed > max_mb * MB:
        result.problems.append(
            f"declared uncompressed size {result.total_uncompressed / MB:.1f} MiB "
            f"exceeds limit {max_mb} MiB"
        )
    if result.total_uncompressed > 10 * MB and result.ratio > max_ratio:
        result.problems.append(
            f"compression ratio {result.ratio:.0f}:1 looks like a bomb (limit {max_ratio}:1)"
        )
    return result


def read_member(data: bytes, name: str, cap: int) -> bytes:
    """Read one archive member, capped, without extracting to disk."""
    with zipfile.ZipFile(__import__("io").BytesIO(data)) as zf:
        with zf.open(name) as fh:
            return fh.read(cap)

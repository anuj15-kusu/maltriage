"""Magic-byte file type identification (pure Python, no libmagic dependency)."""

from __future__ import annotations

import re
from pathlib import Path

from maltriage.models import FileKind

SCRIPT_EXTENSIONS = {
    ".ps1",
    ".psm1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".sh",
    ".bash",
    ".bat",
    ".cmd",
    ".py",
    ".hta",
    ".wsf",
    ".jar",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso"}

_SIGNATURES = [
    (b"MZ", FileKind.PE),
    (b"\x7fELF", FileKind.ELF),
    (b"%PDF", FileKind.PDF),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", FileKind.OLE),
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", FileKind.ARCHIVE),
    (b"7z\xbc\xaf\x27\x1c", FileKind.ARCHIVE),
    (b"\x1f\x8b", FileKind.ARCHIVE),
    (b"BZh", FileKind.ARCHIVE),
    (b"\xfd7zXZ", FileKind.ARCHIVE),
    (b"MSCF", FileKind.ARCHIVE),
]

_SHEBANG = re.compile(rb"^#!.*\b(?:sh|bash|python|perl|ruby)\b")
_PS1_HINT = re.compile(rb"(?i)(?:Write-Host|Invoke-Expression|\bparam\s*\(|\$env:|Add-Type)")
_TEXT_RATIO = 0.90


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:8192]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample)


def detect(data: bytes, name: str | Path | None = None) -> FileKind:
    """Classify the sample from its leading bytes."""
    head = data[:4096]
    suffix = Path(name).suffix.lower() if name else ""

    for magic, kind in _SIGNATURES:
        if head.startswith(magic):
            if kind == "zip":
                return _classify_zip(data, suffix)
            return kind  # type: ignore[return-value]

    if len(head) > 262 and head[257:262] == b"ustar":
        return FileKind.ARCHIVE
    if _SHEBANG.match(head):
        return FileKind.SCRIPT
    if suffix in SCRIPT_EXTENSIONS and _printable_ratio(head) > 0.85:
        return FileKind.SCRIPT
    if _PS1_HINT.search(head) and _printable_ratio(head) > 0.85:
        return FileKind.SCRIPT
    if suffix in ARCHIVE_EXTENSIONS:
        return FileKind.ARCHIVE
    if _printable_ratio(head) >= _TEXT_RATIO:
        return FileKind.TEXT
    return FileKind.UNKNOWN


def _classify_zip(data: bytes, suffix: str) -> FileKind:
    import io
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
    except Exception:
        return FileKind.ARCHIVE

    if "AndroidManifest.xml" in names and "classes.dex" in names:
        return FileKind.APK
    if "[Content_Types].xml" in names:
        if any(n.startswith(("word/", "xl/", "ppt/")) for n in names):
            return FileKind.OOXML
    if suffix in {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}:
        return FileKind.OOXML
    return FileKind.ARCHIVE


def describe(data: bytes) -> str | None:
    """Human readable MIME guess, best effort."""
    try:
        import filetype

        kind = filetype.guess(data[:8192])
        return kind.mime if kind else None
    except Exception:
        return None


MAGIC_NOTES = {
    b"\xd0\xcf\x11\xe0": "legacy OLE / compound file (Office 97-2003, MSI, .lnk)",
    b"\x7fELF": "ELF executable",
    b"MZ": "DOS/PE image",
    b"%PDF": "PDF document",
}

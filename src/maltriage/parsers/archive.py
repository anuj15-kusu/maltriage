"""Archive parser: central-directory inspection only, no extraction."""

from __future__ import annotations

import io
import tarfile
import zipfile

from maltriage.models import FileKind, SampleContext
from maltriage.parsers.base import register_parser
from maltriage.safety import inspect_zip, safe_member_name

EXECUTABLE_SUFFIXES = {
    ".exe",
    ".dll",
    ".scr",
    ".sys",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".lnk",
    ".hta",
    ".msi",
    ".com",
    ".pif",
}


@register_parser
class ArchiveParser:
    name = "archive"
    kinds = {FileKind.ARCHIVE, FileKind.APK}

    def parse(self, ctx: SampleContext) -> None:
        data = ctx.read()
        result: dict = {
            "format": "unknown",
            "members": [],
            "member_count": 0,
            "executables": [],
            "truncated": False,
            "problems": [],
            "ratio": 0.0,
            "total_uncompressed": 0,
        }
        cfg = ctx.config

        if data.startswith(b"PK\x03\x04"):
            result["format"] = "zip"
            inspection = inspect_zip(
                data,
                max_files=cfg.max_archive_files,
                max_mb=cfg.max_archive_mb,
                max_ratio=cfg.max_archive_ratio,
            )
            result["members"] = inspection.members[:200]
            result["member_count"] = len(inspection.members)
            result["truncated"] = inspection.truncated
            result["problems"] = inspection.problems
            result["ratio"] = round(inspection.ratio, 1)
            result["total_uncompressed"] = inspection.total_uncompressed
            result["executables"] = [
                m["name"] for m in inspection.members if _suffix(m["name"]) in EXECUTABLE_SUFFIXES
            ][:50]
        elif len(data) > 262 and data[257:262] == b"ustar":
            result["format"] = "tar"
            try:
                with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                    members = tf.getmembers()[: cfg.max_archive_files]
                    result["member_count"] = len(members)
                    result["members"] = [
                        {"name": m.name, "size": m.size, "is_dir": m.isdir()}
                        for m in members
                        if safe_member_name(m.name)
                    ][:200]
                    result["executables"] = [
                        m.name for m in members if _suffix(m.name) in EXECUTABLE_SUFFIXES
                    ][:50]
            except Exception as exc:
                ctx.add_error(f"tar parse failed: {exc}")
        else:
            result["format"] = "opaque"
            result["problems"].append("container format not inspected (only zip/tar are parsed)")

        ctx.parsed["archive"] = result


def _suffix(name: str) -> str:
    lowered = name.lower()
    dot = lowered.rfind(".")
    return lowered[dot:] if dot > 0 else ""


def _unused_import_guard() -> None:  # pragma: no cover
    _ = zipfile

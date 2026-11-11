"""Extension/content mismatch - the oldest trick in the phishing book."""

from __future__ import annotations

from pathlib import Path

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.models import FileKind, Finding, SampleContext, Severity

EXPECTED = {
    FileKind.PE: {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".pif", ".msi", ".efi"},
    FileKind.PDF: {".pdf"},
    FileKind.OLE: {".doc", ".xls", ".ppt", ".msi", ".msg", ".lnk"},
    FileKind.OOXML: {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"},
    FileKind.ELF: {".so", ".elf", ".bin", ".ko"},
    FileKind.SCRIPT: {
        ".ps1",
        ".psm1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".bat",
        ".cmd",
        ".sh",
        ".py",
        ".hta",
        ".wsf",
    },
}


@register_analyzer
class TypeMismatchAnalyzer(Analyzer):
    name = "type_mismatch"
    applies_to = None

    def run(self, ctx: SampleContext) -> list[Finding]:
        expected = EXPECTED.get(ctx.kind)
        if not expected:
            return []
        suffix = Path(ctx.path).suffix.lower()
        if not suffix or suffix in expected:
            return []
        return [
            Finding(
                analyzer=self.name,
                title=f"Extension {suffix!r} does not match content ({ctx.kind.value})",
                severity=Severity.MEDIUM,
                confidence=0.8,
                description="A disguised extension makes the file look harmless.",
                signal="type_mismatch",
                evidence={"extension": suffix, "detected": ctx.kind.value},
                tags=["delivery"],
            )
        ]

"""Detection of executables hidden inside another file (carved MZ/PE headers)."""

from __future__ import annotations

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.models import FileKind, Finding, SampleContext, Severity

MAX_CARVE = 5


def find_embedded_pes(data: bytes, limit: int = MAX_CARVE) -> list[int]:
    offsets: list[int] = []
    start = 1  # skip the outer header
    while len(offsets) < limit:
        index = data.find(b"MZ", start)
        if index < 0:
            break
        if index + 0x40 <= len(data):
            e_lfanew = int.from_bytes(data[index + 0x3C : index + 0x40], "little")
            pe_offset = index + e_lfanew
            if 0 < e_lfanew < 0x10000 and pe_offset + 4 <= len(data):
                if data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                    offsets.append(index)
        start = index + 2
    return offsets


@register_analyzer
class EmbeddedAnalyzer(Analyzer):
    name = "embedded"
    applies_to = None

    def run(self, ctx: SampleContext) -> list[Finding]:
        data = ctx.read()
        findings: list[Finding] = []
        offsets = find_embedded_pes(data)

        if offsets and not (ctx.kind is FileKind.PE and offsets == [0]):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(offsets)} embedded PE image(s)",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    description="A full executable is hidden inside this file.",
                    signal="embedded_executable",
                    evidence={"offsets": [hex(o) for o in offsets]},
                    tags=["dropper"],
                )
            )

        archive = ctx.parsed.get("archive") or {}
        executables = archive.get("executables") or []
        if executables:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(executables)} executable member(s) in the archive",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description="Archives carrying executables are the usual delivery container.",
                    signal="embedded_executable",
                    evidence={"members": executables[:15]},
                    tags=["archive", "dropper"],
                )
            )

        if archive.get("problems"):
            bomb = [p for p in archive["problems"] if "bomb" in p or "exceeds" in p]
            if bomb:
                findings.append(
                    Finding(
                        analyzer=self.name,
                        title="Archive bomb characteristics",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        description="Declared size or ratio suggests a decompression bomb.",
                        signal="archive_bomb",
                        evidence={"problems": archive["problems"], "ratio": archive.get("ratio")},
                        tags=["archive", "dos"],
                    )
                )
        return findings

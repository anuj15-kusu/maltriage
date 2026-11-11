"""Macro and document active-content analysis."""

from __future__ import annotations

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.models import FileKind, Finding, SampleContext, Severity


@register_analyzer
class MacroAnalyzer(Analyzer):
    name = "macro"
    applies_to = {FileKind.OLE, FileKind.OOXML}

    def run(self, ctx: SampleContext) -> list[Finding]:
        office = ctx.parsed.get("office") or {}
        findings: list[Finding] = []

        if office.get("has_vba"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="VBA macro present",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    description="The document contains a VBA project.",
                    signal="macro_present",
                    evidence={
                        "modules": [m.get("module") for m in office.get("macros", [])][:10],
                        "container": office.get("container"),
                    },
                    tags=["macro"],
                )
            )

        autoexec = office.get("autoexec") or []
        if autoexec:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(autoexec)} macro auto-exec trigger(s)",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    description="The macro runs as soon as the document is opened.",
                    signal="macro_autoexec",
                    evidence={"triggers": autoexec[:10]},
                    tags=["macro", "execution"],
                )
            )

        suspicious = office.get("suspicious") or []
        if suspicious:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(suspicious)} suspicious macro keyword(s)",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    description="Macro code uses downloader, shell or obfuscation primitives.",
                    evidence={"keywords": suspicious[:15]},
                    tags=["macro", "obfuscation"],
                )
            )

        if office.get("remote_template"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Remote template injection",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    description=(
                        "The document references a remote template or attached template URL, "
                        "so the payload is fetched after opening."
                    ),
                    signal="ooxml_remote_template",
                    evidence={"external_rels": office.get("external_rels", [])[:10]},
                    tags=["macro", "downloader"],
                )
            )

        if office.get("dde"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="DDE field detected",
                    severity=Severity.HIGH,
                    confidence=0.6,
                    description="Dynamic Data Exchange can execute commands without macros.",
                    tags=["dde", "execution"],
                )
            )

        if office.get("embedded_objects"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(office['embedded_objects'])} embedded object(s)",
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    description="Embedded binaries or OLE objects can carry a second stage.",
                    signal="embedded_executable",
                    evidence={"objects": office["embedded_objects"][:15]},
                    tags=["embedded"],
                )
            )
        return findings

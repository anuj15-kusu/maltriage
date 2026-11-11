"""PDF active-content analysis."""

from __future__ import annotations

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.models import FileKind, Finding, SampleContext, Severity

DANGEROUS = {"javascript", "launch_action", "embedded_file", "embedded_navigation", "rich_media"}
HIGH_VALUE = {"open_action", "additional_action"}


@register_analyzer
class PDFAnalyzer(Analyzer):
    name = "pdf_active"
    applies_to = {FileKind.PDF}

    def run(self, ctx: SampleContext) -> list[Finding]:
        pdf = ctx.parsed.get("pdf")
        if not pdf:
            return []
        findings: list[Finding] = []
        active = pdf.get("active", {})
        dangerous = {k: v for k, v in active.items() if k in DANGEROUS}
        triggers = {k: v for k, v in active.items() if k in HIGH_VALUE}

        if dangerous:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"PDF active content: {', '.join(sorted(dangerous))}",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    description="JavaScript, launch actions or embedded files can execute code.",
                    signal="pdf_active_content",
                    evidence={"tokens": dangerous, "pages": pdf.get("pages")},
                    tags=["pdf", "execution"],
                )
            )
        if triggers:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"PDF auto-trigger: {', '.join(sorted(triggers))}",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description="The action fires when the document is opened.",
                    evidence={"tokens": triggers},
                    tags=["pdf"],
                )
            )
        if pdf.get("encrypted"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="PDF is encrypted",
                    severity=Severity.INFO,
                    confidence=0.9,
                    description="Encryption blocks some static checks and is used for evasion.",
                    tags=["pdf"],
                )
            )
        if pdf.get("urls"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(pdf['urls'])} URL(s) embedded in the PDF",
                    severity=Severity.LOW,
                    confidence=0.5,
                    description="Embedded links are the usual delivery path for PDF phishing.",
                    evidence={"urls": pdf["urls"][:10]},
                    tags=["pdf", "ioc"],
                )
            )
        return findings

"""Code-signing state. Full chain validation is out of scope; presence is what we report."""

from __future__ import annotations

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.models import FileKind, Finding, SampleContext, Severity


@register_analyzer
class SignatureAnalyzer(Analyzer):
    name = "signature"
    applies_to = {FileKind.PE}

    def run(self, ctx: SampleContext) -> list[Finding]:
        pe = ctx.parsed.get("pe")
        if not pe:
            return []
        if pe.get("signed"):
            return [
                Finding(
                    analyzer=self.name,
                    title="Authenticode signature table present",
                    severity=Severity.INFO,
                    confidence=0.9,
                    description=(
                        "A certificate table exists. Presence is not trust: "
                        "validate the chain and timestamp before relying on it."
                    ),
                    evidence={"cert_size": pe.get("cert_size")},
                    tags=["signature"],
                )
            ]
        return [
            Finding(
                analyzer=self.name,
                title="Binary is not digitally signed",
                severity=Severity.LOW,
                confidence=0.85,
                description=(
                    "No Authenticode table found. Most malware is unsigned, "
                    "but so is a lot of legitimate custom software."
                ),
                evidence={"machine": pe.get("machine"), "compiler": pe.get("timestamp")},
                tags=["signature"],
            )
        ]

"""File-level entropy, printable ratio and decoded blob analysis."""

from __future__ import annotations

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.models import Finding, SampleContext, Severity
from maltriage.strings import base64_blobs, printable_ratio, shannon_entropy

HIGH_ENTROPY = 7.2
MIN_SIZE_FOR_ENTROPY = 64 * 1024


@register_analyzer
class EntropyAnalyzer(Analyzer):
    name = "entropy"
    applies_to = None

    def run(self, ctx: SampleContext) -> list[Finding]:
        data = ctx.read()
        findings: list[Finding] = []
        entropy = round(shannon_entropy(data), 2)
        ratio = round(printable_ratio(data), 3)

        if len(data) >= MIN_SIZE_FOR_ENTROPY and entropy >= HIGH_ENTROPY:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"High whole-file entropy ({entropy})",
                    severity=Severity.MEDIUM,
                    confidence=0.55,
                    description=(
                        "Entropy close to 8.0 usually means the file is compressed, "
                        "encrypted or packed."
                    ),
                    signal="packed_high_entropy",
                    evidence={"entropy": entropy, "size": len(data), "printable_ratio": ratio},
                    tags=["entropy", "packing"],
                )
            )

        blobs = base64_blobs(data, min_len=64, limit=5)
        if blobs:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(blobs)} decodable base64 blob(s)",
                    severity=Severity.LOW,
                    confidence=0.5,
                    description="Long base64 runs decoding to readable text often hide payloads.",
                    evidence={"previews": [b[:160] for b in blobs]},
                    tags=["obfuscation"],
                )
            )
        return findings

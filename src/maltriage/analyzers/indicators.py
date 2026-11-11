"""Indicator analysis over the strings extracted by the pipeline."""

from __future__ import annotations

import re

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.models import Finding, IOCType, SampleContext, Severity

LOLBIN_RE = re.compile(
    r"(?i)(?:powershell(?:\.exe)?\s+(?:-\w+\s+)*-e(?:nc|ncodedcommand)?\b|"
    r"certutil(?:\.exe)?\s+-urlcache|bitsadmin\s+/transfer|mshta\s+https?://|"
    r"rundll32(?:\.exe)?\s+javascript:|regsvr32\s+/s\s+/u\s+/i:https?://|"
    r"wmic\s+process\s+call\s+create|curl\s+-s\s+http|wget\s+http)"
)


@register_analyzer
class IndicatorsAnalyzer(Analyzer):
    name = "indicators"
    applies_to = None

    def run(self, ctx: SampleContext) -> list[Finding]:
        findings: list[Finding] = []
        strings = ctx.strings or []
        iocs = ctx.parsed.get("iocs", [])

        remote = [i for i in iocs if i.type in (IOCType.URL, IOCType.IPV4)]
        if remote:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(remote)} hardcoded network indicator(s)",
                    severity=Severity.MEDIUM,
                    confidence=0.55,
                    description="The file references remote endpoints directly.",
                    signal="ioc_public_endpoint",
                    evidence={"samples": [i.value for i in remote[:10]]},
                    tags=["ioc", "network"],
                )
            )

        lolbins = []
        for text in strings:
            match = LOLBIN_RE.search(text)
            if match:
                lolbins.append(match.group()[:200])
                if len(lolbins) >= 5:
                    break
        if lolbins:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Living-off-the-land command line",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    description="Built-in Windows tools are used to download or execute code.",
                    signal="lolbin_download",
                    evidence={"commands": lolbins},
                    tags=["execution", "lolbin"],
                )
            )
        return findings

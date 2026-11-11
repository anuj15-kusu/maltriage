"""Behavioural analysis of scripts."""

from __future__ import annotations

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.models import FileKind, Finding, SampleContext, Severity


@register_analyzer
class ScriptBehaviorAnalyzer(Analyzer):
    name = "script_behavior"
    applies_to = {FileKind.SCRIPT}

    def run(self, ctx: SampleContext) -> list[Finding]:
        script = ctx.parsed.get("script")
        if not script:
            return []
        findings: list[Finding] = []
        keywords = script.get("keywords", {})

        if "download" in keywords:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Script downloads remote content",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    description="Download primitives are present in the script body.",
                    signal="lolbin_download",
                    evidence={
                        "keywords": keywords["download"][:10],
                        "language": script.get("language"),
                    },
                    tags=["downloader"],
                )
            )

        if "evasion" in keywords:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Evasion or obfuscation keywords",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description="AMSI bypass, hidden window flags or encoded commands are used.",
                    evidence={"keywords": keywords["evasion"][:10]},
                    tags=["evasion"],
                )
            )

        if script.get("base64_blobs"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(script['base64_blobs'])} base64 payload(s) in the script",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description="Encoded blobs are decoded at runtime, hiding the real logic.",
                    evidence={"previews": [b[:120] for b in script["base64_blobs"]]},
                    tags=["obfuscation"],
                )
            )

        if script.get("long_lines", 0) > 5 or script.get("max_line_length", 0) > 2000:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Heavily obfuscated script layout",
                    severity=Severity.MEDIUM,
                    confidence=0.55,
                    description="Long lines and dense symbols are typical of obfuscators.",
                    evidence={
                        "long_lines": script.get("long_lines"),
                        "max_line_length": script.get("max_line_length"),
                        "obfuscation_ratio": script.get("obfuscation_ratio"),
                    },
                    tags=["obfuscation"],
                )
            )

        if "persistence" in keywords:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Persistence mechanism referenced",
                    severity=Severity.HIGH,
                    confidence=0.6,
                    description="The script registers autorun or scheduled tasks.",
                    evidence={"keywords": keywords["persistence"][:10]},
                    tags=["persistence"],
                )
            )

        if "credential" in keywords:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Credential access keywords",
                    severity=Severity.HIGH,
                    confidence=0.5,
                    description="The script references credential theft tooling or LSASS.",
                    evidence={"keywords": keywords["credential"][:10]},
                    tags=["credential"],
                )
            )
        return findings

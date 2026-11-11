"""Packer and protector detection from section names, entropy and import count."""

from __future__ import annotations

from functools import lru_cache

import yaml

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.config import DATA_DIR
from maltriage.models import FileKind, Finding, SampleContext, Severity


@lru_cache(maxsize=1)
def _packer_db() -> tuple[list[dict], float, int]:
    raw = yaml.safe_load((DATA_DIR / "packers.yaml").read_text(encoding="utf-8"))
    return (
        raw.get("signatures", []),
        float(raw.get("high_entropy_threshold", 7.2)),
        int(raw.get("min_packed_section_size", 4096)),
    )


@register_analyzer
class PackerAnalyzer(Analyzer):
    name = "packer"
    applies_to = {FileKind.PE, FileKind.ELF}

    def run(self, ctx: SampleContext) -> list[Finding]:
        findings: list[Finding] = []
        signatures, threshold, min_size = _packer_db()
        pe = ctx.parsed.get("pe")
        elf = ctx.parsed.get("elf")
        sections = (pe or elf or {}).get("sections", [])
        if not sections:
            return findings

        names = {s["name"] for s in sections}
        blob = (
            " ".join(sorted(names)).lower()
            + " "
            + " ".join((pe or {}).get("version_strings", [])).lower()
        )

        matched = []
        for entry in signatures:
            for marker in entry["markers"]:
                if marker.lower() in blob:
                    matched.append({"packer": entry["name"], "marker": marker})
                    break
        if matched:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"Known packer/protector: {', '.join(m['packer'] for m in matched)}",
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    description="Section names or metadata match a known packer or protector.",
                    signal="packer_signature",
                    evidence={"matches": matched, "sections": sorted(names)},
                    tags=["packing"],
                )
            )

        packed_sections = [
            s
            for s in sections
            if s["entropy"] >= threshold and s.get("raw_size", s.get("size", 0)) >= min_size
        ]
        if packed_sections:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(packed_sections)} high-entropy section(s)",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description="Sections above the entropy threshold are compressed or encrypted.",
                    signal="packed_high_entropy",
                    evidence={
                        "threshold": threshold,
                        "sections": [
                            {"name": s["name"], "entropy": s["entropy"]} for s in packed_sections
                        ],
                    },
                    tags=["packing"],
                )
            )

        exec_write = [s["name"] for s in sections if s.get("executable") and s.get("writable")]
        if exec_write:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Writable and executable section(s)",
                    severity=Severity.LOW,
                    confidence=0.5,
                    description="RWX sections are common in packed or self-modifying code.",
                    evidence={"sections": exec_write},
                    tags=["hardening"],
                )
            )
        return findings

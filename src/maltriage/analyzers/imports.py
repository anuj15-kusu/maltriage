"""Import table analysis: injection combos, network reach and signature state."""

from __future__ import annotations

from functools import lru_cache

import yaml

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.config import DATA_DIR
from maltriage.models import FileKind, Finding, SampleContext, Severity


@lru_cache(maxsize=1)
def _api_db() -> dict:
    return yaml.safe_load((DATA_DIR / "suspicious_apis.yaml").read_text(encoding="utf-8"))


@register_analyzer
class ImportsAnalyzer(Analyzer):
    name = "imports"
    applies_to = {FileKind.PE}

    def run(self, ctx: SampleContext) -> list[Finding]:
        pe = ctx.parsed.get("pe")
        if not pe:
            return []
        findings: list[Finding] = []
        db = _api_db()

        imported = {name for funcs in pe.get("imports", {}).values() for name in funcs}
        lowered = {name.lower() for name in imported}

        for combo_name, spec in db.get("combos", {}).items():
            required = spec["require"]
            if all(r.lower() in lowered for r in required):
                findings.append(
                    Finding(
                        analyzer=self.name,
                        title=spec["label"],
                        severity=Severity.HIGH,
                        confidence=0.8,
                        description="All APIs required for this technique are imported.",
                        signal="injection_api_combo",
                        evidence={"combo": combo_name, "apis": required},
                        tags=["injection"],
                    )
                )

        network = [api for api in db.get("network", []) if api.lower() in lowered]
        if network and not pe.get("signed"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Unsigned binary imports network APIs",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description=(
                        "The PE has no Authenticode table but can open network connections."
                    ),
                    signal="unsigned_pe_network",
                    evidence={"network_apis": network[:15], "signed": False},
                    tags=["network", "signature"],
                )
            )

        downloaders = [
            api
            for api in (
                "URLDownloadToFileA",
                "URLDownloadToFileW",
                "InternetOpenUrlA",
                "InternetOpenUrlW",
                "WinHttpSendRequest",
            )
            if api.lower() in lowered
        ]
        if downloaders and not pe.get("signed"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Downloader APIs present",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    description="The binary can fetch a remote file at runtime.",
                    evidence={"apis": downloaders},
                    tags=["downloader"],
                )
            )

        if pe.get("import_count", 0) <= 5 and pe.get("sections"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"Very small import table ({pe.get('import_count', 0)} functions)",
                    severity=Severity.LOW,
                    confidence=0.5,
                    description="Packed samples often resolve most APIs dynamically.",
                    evidence={"imports": pe.get("imports", {})},
                    tags=["packing"],
                )
            )

        if pe.get("pdb_path"):
            findings.append(
                Finding(
                    analyzer=self.name,
                    title="Debug information left in the binary",
                    severity=Severity.INFO,
                    confidence=0.9,
                    description="A PDB path can reveal the build environment.",
                    evidence={"pdb_path": pe["pdb_path"]},
                    tags=["metadata"],
                )
            )

        if pe.get("overlay_size", 0) > 0:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"Overlay data after the last section ({pe['overlay_size']} bytes)",
                    severity=Severity.LOW,
                    confidence=0.45,
                    description="Installers and droppers append payloads after the PE image.",
                    evidence={"overlay_size": pe["overlay_size"]},
                    tags=["overlay"],
                )
            )
        return findings

"""Scan orchestrator: intake -> identity -> parsing -> analysis -> enrichment -> score."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from maltriage import __version__, registry
from maltriage.cache import Cache
from maltriage.config import Settings, get_settings
from maltriage.enrichment.malwarebazaar import MalwareBazaar
from maltriage.enrichment.virustotal import VirusTotal
from maltriage.filetype import describe as describe_mime
from maltriage.filetype import detect
from maltriage.iocs import extract as extract_iocs
from maltriage.models import (
    EnrichmentResult,
    FileInfo,
    FileKind,
    Finding,
    Report,
    SampleContext,
    Severity,
    utcnow,
)
from maltriage.safety import SafetyError, check_file
from maltriage.scoring import default_weights, score
from maltriage.strings import extract as extract_strings

MAX_WORKERS = 4


@dataclass
class ScanOptions:
    enrich: bool = True
    submit: bool = False
    refresh: bool = False


class Pipeline:
    def __init__(self, settings: Settings | None = None, cache: Cache | None = None) -> None:
        self.settings = settings or get_settings()
        self.cache = cache if cache is not None else Cache(self.settings.cache_path)
        self.enrichers = [VirusTotal(), MalwareBazaar()]

    def close(self) -> None:
        self.cache.close()

    # --- main entry point ---------------------------------------------
    def scan(self, path: Path | str, options: ScanOptions | None = None) -> Report:
        options = options or ScanOptions()
        path = Path(path)
        started = perf_counter()
        timings: dict[str, float] = {}

        size = check_file(path, self.settings.max_file_mb)
        data = path.read_bytes()
        markup = perf_counter()
        timings["intake"] = round(markup - started, 3)

        from maltriage.identity import fuzzy_hash, hashes

        digest = hashes(data)
        kind = detect(data, path)
        ctx = SampleContext(path=path, size=size, kind=kind, config=self.settings, hashes=digest)
        ctx._data = data
        self.cache.remember_sample(
            digest["sha256"], digest["md5"], digest["sha1"], fuzzy_hash(data), size, kind.value
        )
        timings["identity"] = round(perf_counter() - markup, 3)

        # 1. format parsing
        mark = perf_counter()
        parser = registry.parsers().get(kind)
        if parser is not None:
            try:
                parser.parse(ctx)
            except Exception as exc:
                ctx.add_error(f"{parser.name} parser crashed: {exc}")
        timings["parse"] = round(perf_counter() - mark, 3)

        # 2. strings + indicators (shared by several analyzers)
        mark = perf_counter()
        ctx.strings = extract_strings(data)
        ctx.parsed["iocs"] = extract_iocs(ctx.strings)
        timings["strings"] = round(perf_counter() - mark, 3)

        # 3. analyzers
        mark = perf_counter()
        findings = self._run_analyzers(ctx)
        timings["analyzers"] = round(perf_counter() - mark, 3)

        # 4. enrichment
        enrichment: list[EnrichmentResult] = []
        if options.enrich and not self.settings.offline:
            mark = perf_counter()
            results, extra = self._enrich(ctx, options)
            enrichment.extend(results)
            findings.extend(extra)
            timings["enrichment"] = round(perf_counter() - mark, 3)

        previous = self.cache.previous_scan(ctx.sha256)
        if previous:
            findings.append(
                Finding(
                    analyzer="cache",
                    title="Sample was scanned before",
                    severity=Severity.INFO,
                    confidence=0.9,
                    description=(
                        f"Previous verdict {previous.get('verdict')} "
                        f"({previous.get('score')}/100) at {previous.get('finished_at')}"
                    ),
                    evidence=dict(previous),
                    tags=["history"],
                )
            )

        verdict = score(findings, default_weights())

        report = Report(
            tool_version=__version__,
            generated_at=utcnow(),
            file=FileInfo(
                name=path.name,
                path=str(path.resolve()),
                size=size,
                kind=kind,
                md5=digest["md5"],
                sha1=digest["sha1"],
                sha256=digest["sha256"],
                ssdeep=fuzzy_hash(data),
                mime=describe_mime(data),
                magic_note=_magic_note(data),
            ),
            verdict=verdict,
            findings=sorted(
                findings,
                key=lambda f: ["info", "low", "medium", "high", "critical"].index(f.severity.value),
                reverse=True,
            ),
            iocs=ctx.parsed.get("iocs", []),
            enrichment=enrichment,
            ruleset=ctx.parsed.get("ruleset", {}),
            timings=timings,
            errors=ctx.errors,
        )
        report.timings["total"] = round(perf_counter() - started, 3)
        self.cache.save_report(report)
        return report

    # --- stages --------------------------------------------------------
    def _run_analyzers(self, ctx: SampleContext) -> list[Finding]:
        selected = [a for a in registry.analyzers() if a.applies(ctx.kind)]
        if not selected:
            return []
        findings: list[Finding] = []
        workers = min(MAX_WORKERS, len(selected))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(a.run, ctx): a for a in selected}
            done, not_done = wait(futures, timeout=self.settings.analyzer_timeout * 2)
            for future in done:
                analyzer = futures[future]
                try:
                    findings.extend(future.result())
                except Exception as exc:
                    ctx.add_error(f"{analyzer.name} analyzer failed: {exc}")
            for future in not_done:
                analyzer = futures[future]
                future.cancel()
                ctx.add_error(f"{analyzer.name} analyzer timed out")
        return findings

    def _enrich(
        self, ctx: SampleContext, options: ScanOptions
    ) -> tuple[list[EnrichmentResult], list[Finding]]:
        results: list[EnrichmentResult] = []
        findings: list[Finding] = []
        if options.refresh:
            self.cache.drop_vt(ctx.sha256)
        for enricher in self.enrichers:
            try:
                result, extra = enricher.enrich(ctx, self.cache, self.settings)
            except Exception as exc:
                results.append(
                    EnrichmentResult(
                        provider=enricher.name,
                        status="error",
                        summary=f"{type(exc).__name__}: {exc}",
                    )
                )
                continue
            if result is not None:
                results.append(result)
            findings.extend(extra)
        return results, findings


def _magic_note(data: bytes) -> str | None:
    from maltriage.filetype import MAGIC_NOTES

    for magic, note in MAGIC_NOTES.items():
        if data.startswith(magic):
            return note
    return None


__all__ = ["Pipeline", "ScanOptions", "SafetyError", "FileKind"]

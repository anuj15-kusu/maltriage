"""VirusTotal API v3 hash lookup.

Hash lookups are cheap and cached; uploading a sample happens only with --submit.
Free tier limits: 4 requests/minute, 500/day. Everything is cached in SQLite so a
repeat scan costs no quota at all.
"""

from __future__ import annotations

import time

import requests

from maltriage.cache import Cache
from maltriage.config import Settings
from maltriage.enrichment.ratelimit import MinInterval
from maltriage.models import EnrichmentResult, Finding, SampleContext, Severity

BASE_URL = "https://www.virustotal.com/api/v3"
GUI_URL = "https://www.virustotal.com/gui/file"

_pacer = MinInterval(15.0)


class VirusTotal:
    name = "virustotal"

    def enabled(self, settings: Settings) -> bool:
        return bool(settings.vt_api_key) and not settings.offline

    def enrich(
        self, ctx: SampleContext, cache: Cache, settings: Settings
    ) -> tuple[EnrichmentResult | None, list[Finding]]:
        if not self.enabled(settings):
            reason = "offline mode" if settings.offline else "no VT_API_KEY configured"
            return (
                EnrichmentResult(provider=self.name, status="disabled", summary=reason),
                [],
            )

        cached = cache.get_vt(ctx.sha256, settings.vt_cache_days)
        if cached:
            payload = cached["payload"]
            return (
                self._build_result(
                    cached["malicious"],
                    cached["suspicious"],
                    cached["total"],
                    ctx.sha256,
                    source="cache",
                ),
                self._findings(cached["malicious"], cached["suspicious"], cached["total"], ctx),
            )

        headers = {"x-apikey": settings.vt_api_key or "", "accept": "application/json"}
        _pacer.wait()
        try:
            response = self._get(f"{BASE_URL}/files/{ctx.sha256}", headers)
        except Exception as exc:
            cache.log_enrichment(self.name, "files", f"error:{type(exc).__name__}")
            return (
                EnrichmentResult(
                    provider=self.name, status="error", summary=f"request failed: {exc}"
                ),
                [],
            )

        if response.status_code == 404:
            cache.log_enrichment(self.name, "files", "not_found")
            return (
                EnrichmentResult(
                    provider=self.name,
                    status="not_found",
                    summary="hash is not known to VirusTotal",
                ),
                [],
            )
        if response.status_code == 429:
            cache.log_enrichment(self.name, "files", "quota")
            return (
                EnrichmentResult(
                    provider=self.name,
                    status="quota",
                    summary="rate or daily quota exhausted; cached results will be used next time",
                ),
                [],
            )
        if response.status_code >= 400:
            cache.log_enrichment(self.name, "files", f"http_{response.status_code}")
            return (
                EnrichmentResult(
                    provider=self.name,
                    status="error",
                    summary=f"HTTP {response.status_code}",
                ),
                [],
            )

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 0

        cache.put_vt(ctx.sha256, malicious, suspicious, total, payload)
        cache.log_enrichment(self.name, "files", "ok")
        return (
            self._build_result(malicious, suspicious, total, ctx.sha256, source="live"),
            self._findings(malicious, suspicious, total, ctx),
        )

    # --- helpers -------------------------------------------------------
    def _get(self, url: str, headers: dict, attempts: int = 3) -> requests.Response:
        last: requests.Response | None = None
        for attempt in range(attempts):
            response = requests.get(url, headers=headers, timeout=20)
            last = response
            if response.status_code not in (429, 500, 502, 503, 504):
                return response
            retry_after = response.headers.get("Retry-After")
            sleep_for = float(retry_after) if retry_after and retry_after.isdigit() else 20.0
            if attempt < attempts - 1:
                time.sleep(min(sleep_for, 60.0))
        assert last is not None
        return last

    def _build_result(
        self, malicious: int, suspicious: int, total: int, sha256: str, source: str
    ) -> EnrichmentResult:
        return EnrichmentResult(
            provider=self.name,
            status="ok",
            detections=malicious,
            total_engines=total,
            link=f"{GUI_URL}/{sha256}",
            summary=f"{malicious}/{total} engines flag this file (source: {source})",
            raw={"suspicious": suspicious, "source": source},
        )

    def _findings(
        self, malicious: int, suspicious: int, total: int, ctx: SampleContext
    ) -> list[Finding]:
        findings: list[Finding] = []
        if malicious >= 10:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{malicious} engines detect the file as malicious",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    description="Multiple independent engines agree the sample is malicious.",
                    signal="vt_malicious_high",
                    evidence={"detections": malicious, "total": total},
                    tags=["enrichment", "virustotal"],
                )
            )
        elif malicious >= 1:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{malicious} engine(s) detect the file",
                    severity=Severity.HIGH,
                    confidence=0.6,
                    description="Few detections: could be a false positive or a fresh sample.",
                    signal="vt_malicious_low",
                    evidence={"detections": malicious, "suspicious": suspicious, "total": total},
                    tags=["enrichment", "virustotal"],
                )
            )
        elif total:
            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"No engine detects the file ({total} engines)",
                    severity=Severity.INFO,
                    confidence=0.5,
                    description="Not conclusive: fresh or targeted samples are often undetected.",
                    signal="vt_known_good",
                    evidence={"total": total},
                    tags=["enrichment", "virustotal"],
                )
            )
        return findings

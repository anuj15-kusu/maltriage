"""External enrichment provider interface. Providers are optional by design."""

from __future__ import annotations

from typing import Protocol

from maltriage.cache import Cache
from maltriage.config import Settings
from maltriage.models import EnrichmentResult, Finding, SampleContext


class Enricher(Protocol):
    name: str

    def enabled(self, settings: Settings) -> bool: ...

    def enrich(
        self, ctx: SampleContext, cache: Cache, settings: Settings
    ) -> tuple[EnrichmentResult | None, list[Finding]]: ...

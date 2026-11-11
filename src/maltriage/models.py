"""Data models shared by parsers, analyzers, scoring and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from maltriage.config import Settings


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FileKind(StrEnum):
    PE = "pe"
    ELF = "elf"
    OLE = "ole"
    OOXML = "ooxml"
    PDF = "pdf"
    APK = "apk"
    ARCHIVE = "archive"
    SCRIPT = "script"
    TEXT = "text"
    UNKNOWN = "unknown"


class IOCType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    EMAIL = "email"
    REGISTRY = "registry"
    MUTEX = "mutex"
    FILENAME = "filename"
    BTC = "btc"


class IOC(BaseModel):
    type: IOCType
    value: str
    context: str = ""


class Finding(BaseModel):
    """One observation from one analyzer."""

    analyzer: str
    title: str
    severity: Severity = Severity.INFO
    confidence: float = 0.5
    description: str = ""
    signal: str | None = None  # key in data/weights.yaml
    evidence: dict[str, Any] = Field(default_factory=dict)
    iocs: list[IOC] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ScoreContribution(BaseModel):
    signal: str
    label: str
    category: str
    points: int
    applied_points: int


class Verdict(BaseModel):
    score: int = 0
    band: str = "clean"
    confidence: float = 0.0
    breakdown: list[ScoreContribution] = Field(default_factory=list)


class FileInfo(BaseModel):
    name: str
    path: str
    size: int
    kind: FileKind
    md5: str
    sha1: str
    sha256: str
    ssdeep: str | None = None
    mime: str | None = None
    magic_note: str | None = None


class EnrichmentResult(BaseModel):
    provider: str
    status: str  # ok | not_found | quota | error | disabled
    detections: int = 0
    total_engines: int = 0
    family: str | None = None
    link: str | None = None
    summary: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class Report(BaseModel):
    schema_version: str = "1"
    tool_version: str
    generated_at: datetime
    file: FileInfo
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    enrichment: list[EnrichmentResult] = Field(default_factory=list)
    ruleset: dict[str, Any] = Field(default_factory=dict)
    timings: dict[str, float] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)

    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_RANK[s])


@dataclass
class SampleContext:
    """Everything an analyzer or parser is allowed to see. The sample is never executed."""

    path: Path
    size: int
    kind: FileKind
    config: Settings
    hashes: dict[str, str] = field(default_factory=dict)
    parsed: dict[str, Any] = field(default_factory=dict)
    strings: list[str] | None = None
    errors: list[str] = field(default_factory=list)
    _data: bytes | None = None

    def read(self) -> bytes:
        """File contents, read once, read-only."""
        if self._data is None:
            with self.path.open("rb") as fh:
                self._data = fh.read()
        return self._data

    @property
    def sha256(self) -> str:
        return self.hashes.get("sha256", "")

    def add_error(self, message: str) -> None:
        self.errors.append(message)


def utcnow() -> datetime:
    return datetime.now(UTC)

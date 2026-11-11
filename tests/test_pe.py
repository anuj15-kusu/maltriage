from __future__ import annotations

from pathlib import Path

from maltriage.models import FileKind, SampleContext
from maltriage.parsers.pe import PEParser

from .pe_builder import LONG_UNIQUE_PAYLOAD, build_pe


def _context(tmp_path: Path, data: bytes) -> SampleContext:
    target = tmp_path / "sample.exe"
    target.write_bytes(data)
    ctx = SampleContext(path=target, size=len(data), kind=FileKind.PE, config=None)  # type: ignore[arg-type]
    ctx._data = data
    return ctx


def test_parses_machine_and_sections(tmp_path: Path):
    data = build_pe(payload=LONG_UNIQUE_PAYLOAD)
    ctx = _context(tmp_path, data)
    PEParser().parse(ctx)

    pe = ctx.parsed["pe"]
    assert pe["machine"] == "i386"
    assert pe["subsystem"] == "console"
    assert len(pe["sections"]) == 1
    assert pe["sections"][0]["name"] == ".text"
    assert pe["sections"][0]["executable"] is True
    assert pe["entrypoint"] == "0x1000"


def test_unsigned_sample_has_no_certificate(tmp_path: Path):
    ctx = _context(tmp_path, build_pe())
    PEParser().parse(ctx)
    assert ctx.parsed["pe"]["signed"] is False


def test_malformed_sample_is_reported_not_raised(tmp_path: Path):
    ctx = _context(tmp_path, b"MZ" + b"\x00" * 40)
    PEParser().parse(ctx)
    assert "pe" not in ctx.parsed
    assert ctx.errors


def test_amd64_machine(tmp_path: Path):
    ctx = _context(tmp_path, build_pe(machine=0x8664))
    PEParser().parse(ctx)
    assert ctx.parsed["pe"]["machine"] == "amd64"

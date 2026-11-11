from __future__ import annotations

from pathlib import Path

from maltriage.cache import Cache
from maltriage.config import Settings
from maltriage.enrichment import virustotal as vt_module
from maltriage.enrichment.ratelimit import MinInterval
from maltriage.models import FileKind, SampleContext

PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 42,
                "suspicious": 2,
                "undetected": 15,
                "harmless": 0,
            }
        }
    }
}


class FakeResponse:
    def __init__(
        self, status_code: int, payload: dict | None = None, headers: dict | None = None
    ) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self) -> dict:
        return self._payload


def _context(tmp_path: Path) -> SampleContext:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")
    ctx = SampleContext(
        path=target,
        size=11,
        kind=FileKind.TEXT,
        config=None,  # type: ignore[arg-type]
        hashes={"sha256": "a" * 64},
    )
    ctx._data = b"hello world"
    return ctx


def _settings(tmp_path: Path, **overrides) -> Settings:
    base = dict(
        cache_path=tmp_path / "cache.db",
        offline=False,
        vt_api_key="test-key",
        mb_auth_key=None,
        rules_dir=tmp_path / "rules",
    )
    base.update(overrides)
    return Settings(**base)


def test_disabled_without_key(settings: Settings, tmp_path: Path):
    result, findings = vt_module.VirusTotal().enrich(
        _context(tmp_path), Cache(settings.cache_path), settings
    )
    assert result is not None and result.status == "disabled"
    assert findings == []


def test_disabled_when_offline(tmp_path: Path):
    cfg = _settings(tmp_path, offline=True)
    result, findings = vt_module.VirusTotal().enrich(_context(tmp_path), Cache(cfg.cache_path), cfg)
    assert result is not None and result.status == "disabled"


def test_high_detections(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(vt_module, "_pacer", MinInterval(0))
    monkeypatch.setattr(vt_module.requests, "get", lambda *a, **k: FakeResponse(200, PAYLOAD))
    cfg = _settings(tmp_path)

    result, findings = vt_module.VirusTotal().enrich(_context(tmp_path), Cache(cfg.cache_path), cfg)
    assert result is not None
    assert result.detections == 42
    assert result.total_engines == 59
    assert findings[0].signal == "vt_malicious_high"


def test_not_found(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(vt_module, "_pacer", MinInterval(0))
    monkeypatch.setattr(vt_module.requests, "get", lambda *a, **k: FakeResponse(404))
    cfg = _settings(tmp_path)

    result, findings = vt_module.VirusTotal().enrich(_context(tmp_path), Cache(cfg.cache_path), cfg)
    assert result is not None and result.status == "not_found"
    assert findings == []


def test_quota_exhausted(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(vt_module, "_pacer", MinInterval(0))
    monkeypatch.setattr(vt_module.requests, "get", lambda *a, **k: FakeResponse(429))
    monkeypatch.setattr(vt_module.time, "sleep", lambda seconds: None)
    cfg = _settings(tmp_path)

    result, findings = vt_module.VirusTotal().enrich(_context(tmp_path), Cache(cfg.cache_path), cfg)
    assert result is not None and result.status == "quota"
    assert findings == []


def test_second_call_uses_cache_without_network(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(vt_module, "_pacer", MinInterval(0))
    monkeypatch.setattr(vt_module.requests, "get", lambda *a, **k: FakeResponse(200, PAYLOAD))
    cfg = _settings(tmp_path)
    cache = Cache(cfg.cache_path)
    ctx = _context(tmp_path)

    first, _ = vt_module.VirusTotal().enrich(ctx, cache, cfg)
    assert first is not None

    def explode(*args, **kwargs):
        raise AssertionError("cache hit must not hit the network")

    monkeypatch.setattr(vt_module.requests, "get", explode)
    second, findings = vt_module.VirusTotal().enrich(ctx, cache, cfg)
    assert second is not None and second.status == "ok"
    assert second.raw["source"] == "cache"
    assert findings[0].signal == "vt_malicious_high"


def test_refresh_drops_cache(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(vt_module, "_pacer", MinInterval(0))
    monkeypatch.setattr(vt_module.requests, "get", lambda *a, **k: FakeResponse(200, PAYLOAD))
    cfg = _settings(tmp_path)
    cache = Cache(cfg.cache_path)
    ctx = _context(tmp_path)
    vt_module.VirusTotal().enrich(ctx, cache, cfg)

    assert cache.get_vt(ctx.sha256, 7) is not None
    cache.drop_vt(ctx.sha256)
    assert cache.get_vt(ctx.sha256, 7) is None

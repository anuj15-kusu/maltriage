"""The API key must be used for the request and stored nowhere.

A canary value stands in for a real key: if it ever shows up in a report or in the
SQLite cache, this test fails.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from maltriage.config import Settings
from maltriage.enrichment import virustotal as vt_module
from maltriage.enrichment.ratelimit import MinInterval
from maltriage.pipeline import Pipeline
from maltriage.reporters import available, get_renderer

from .sample_files import write_eicar

REPO_ROOT = Path(__file__).resolve().parents[1]
CANARY = "CANARY_key_hygiene_test_value"

PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 11,
                "suspicious": 0,
                "undetected": 40,
                "harmless": 0,
            }
        }
    }
}


class FakeResponse:
    status_code = 200

    def json(self) -> dict:
        return PAYLOAD


@pytest.fixture
def recorder(monkeypatch):
    """Replace the HTTP layer and remember the headers that would be sent."""
    seen: dict[str, str] = {}

    def fake_get(url, headers=None, timeout=None):
        seen.update(headers or {})
        return FakeResponse()

    monkeypatch.setattr(vt_module, "_pacer", MinInterval(0))
    monkeypatch.setattr(vt_module.requests, "get", fake_get)
    return seen


def test_key_is_sent_but_never_persisted(tmp_path: Path, recorder: dict[str, str]):
    settings = Settings(
        cache_path=tmp_path / "cache.db",
        rules_dir=REPO_ROOT / "rules",
        offline=False,
        vt_api_key=CANARY,
        mb_auth_key=None,
    )
    sample = write_eicar(tmp_path / "eicar.txt")

    pipeline = Pipeline(settings=settings)
    report = pipeline.scan(sample)
    pipeline.close()

    # 1. the key really is used for authentication
    assert recorder.get("x-apikey") == CANARY

    # 2. ...and it appears in no output surface
    surfaces = {name: get_renderer(name).render(report, defang=True) for name in available()}
    surfaces["report_json"] = report.model_dump_json()
    leaked = [name for name, body in surfaces.items() if CANARY in body]
    assert leaked == [], f"key leaked into: {leaked}"

    # 3. the cache stores the API response, never the credential
    assert CANARY.encode() not in (tmp_path / "cache.db").read_bytes()


def test_offline_mode_skips_the_key(tmp_path: Path, monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("offline mode must not call the API")

    monkeypatch.setattr(vt_module.requests, "get", explode)
    settings = Settings(
        cache_path=tmp_path / "cache.db",
        rules_dir=REPO_ROOT / "rules",
        offline=True,
        vt_api_key=CANARY,
        mb_auth_key=None,
    )
    sample = write_eicar(tmp_path / "eicar.txt")

    pipeline = Pipeline(settings=settings)
    report = pipeline.scan(sample)
    pipeline.close()

    assert report.enrichment == []

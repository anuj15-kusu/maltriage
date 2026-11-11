from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from maltriage.cli import app
from maltriage.config import Settings, get_settings
from maltriage.doctor import FAIL, OK, WARN, run_checks

REPO_ROOT = Path(__file__).resolve().parents[1]
CANARY = "CANARY_doctor_test_value"


def _settings(tmp_path: Path, **overrides) -> Settings:
    base = dict(
        cache_path=tmp_path / "cache.db",
        rules_dir=REPO_ROOT / "rules",
        report_dir=tmp_path / "out",
        offline=True,
        vt_api_key=None,
        mb_auth_key=None,
    )
    base.update(overrides)
    return Settings(**base)


def test_api_key_value_is_never_rendered(tmp_path: Path):
    settings = _settings(tmp_path, vt_api_key=CANARY, mb_auth_key=CANARY)
    checks = run_checks(settings)
    rendered = " ".join(f"{c.name} {c.status} {c.detail}" for c in checks)

    assert CANARY not in rendered
    vt_check = next(c for c in checks if c.name == "VT_API_KEY")
    assert vt_check.status == OK
    assert "set" in vt_check.detail


def test_missing_key_is_a_warning(tmp_path: Path):
    checks = run_checks(_settings(tmp_path))
    vt_check = next(c for c in checks if c.name == "VT_API_KEY")
    assert vt_check.status == WARN
    assert "not set" in vt_check.detail


def test_rules_cache_and_report_dir_are_checked(tmp_path: Path):
    checks = {c.name: c for c in run_checks(_settings(tmp_path))}

    assert checks["YARA rules"].status == OK
    assert "3 file(s)" in checks["YARA rules"].detail
    assert checks["Cache"].status == OK
    assert checks["Report directory"].status == OK
    assert checks["Python"].status == OK


def test_missing_rules_directory_is_a_warning(tmp_path: Path):
    checks = {c.name: c for c in run_checks(_settings(tmp_path, rules_dir=tmp_path / "nope"))}
    assert checks["YARA rules"].status == WARN


def test_api_check_requires_a_key(tmp_path: Path):
    settings = _settings(tmp_path, offline=False, vt_api_key=None)
    api = next(c for c in run_checks(settings, check_api=True) if c.name == "VirusTotal API")
    assert api.status == FAIL
    assert "VT_API_KEY" in api.detail


def test_api_check_refuses_offline_mode(tmp_path: Path):
    settings = _settings(tmp_path, offline=True, vt_api_key=CANARY)
    api = next(c for c in run_checks(settings, check_api=True) if c.name == "VirusTotal API")
    assert api.status == FAIL
    assert "offline" in api.detail


def test_cli_doctor_exits_zero(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MALTRIAGE_RULES_DIR", str(REPO_ROOT / "rules"))
    monkeypatch.delenv("VT_API_KEY", raising=False)
    get_settings.cache_clear()

    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0, result.stdout
    assert "all checks passed" in result.stdout
    assert "VT_API_KEY" in result.stdout


def test_api_check_bypasses_the_cache(tmp_path: Path, monkeypatch):
    """A cached lookup would never prove the key works, so a request must be made."""
    from maltriage.cache import Cache
    from maltriage.doctor import EICAR_SHA256
    from maltriage.enrichment import virustotal as vt_module
    from maltriage.enrichment.ratelimit import MinInterval

    calls = {"count": 0}

    class FakeResponse:
        status_code = 200

        def json(self) -> dict:
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 1,
                            "suspicious": 0,
                            "undetected": 5,
                            "harmless": 0,
                        }
                    }
                }
            }

    def fake_get(url, headers=None, timeout=None):
        calls["count"] += 1
        return FakeResponse()

    monkeypatch.setattr(vt_module, "_pacer", MinInterval(0))
    monkeypatch.setattr(vt_module.requests, "get", fake_get)

    settings = _settings(tmp_path, offline=False, vt_api_key=CANARY)
    cache = Cache(settings.cache_path)
    cache.put_vt(EICAR_SHA256, 1, 0, 6, {"cached": True})
    cache.close()

    api = next(c for c in run_checks(settings, check_api=True) if c.name == "VirusTotal API")
    assert api.status == OK
    assert calls["count"] == 1, "doctor must not answer from cache"


def test_config_file_check_reports_the_loaded_env(tmp_path: Path, monkeypatch):
    custom = tmp_path / "real.env"
    custom.write_text("VT_API_KEY=dummy\n", encoding="utf-8")
    monkeypatch.setenv("MALTRIAGE_ENV_FILE", str(custom))

    check = next(c for c in run_checks(_settings(tmp_path)) if c.name == "Config file")
    assert check.status == OK
    assert str(custom) in check.detail


def test_config_file_check_warns_when_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("MALTRIAGE_ENV_FILE", str(tmp_path / "absent.env"))

    check = next(c for c in run_checks(_settings(tmp_path)) if c.name == "Config file")
    assert check.status == WARN
    assert "no .env found" in check.detail

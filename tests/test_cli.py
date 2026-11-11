from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from maltriage.cli import app
from maltriage.config import get_settings

REPO_ROOT = Path(__file__).resolve().parents[1]
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _isolate(tmp_path: Path, monkeypatch) -> None:
    """Run the CLI in a temp directory but with the real YARA rules."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MALTRIAGE_RULES_DIR", str(REPO_ROOT / "rules"))
    get_settings.cache_clear()


def test_version_command():
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert "maltriage" in result.stdout


def test_scan_writes_json_report(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    sample = tmp_path / "sample.txt"
    sample.write_bytes(EICAR)

    result = CliRunner().invoke(app, ["scan", str(sample), "--offline", "--format", "json"])
    assert result.exit_code == 0, result.stdout

    reports = list((tmp_path / "out").glob("*.json"))
    assert reports, "expected a JSON report"
    payload = json.loads(reports[0].read_text())
    assert payload["file"]["sha256"]
    assert payload["schema_version"] == "1"


def test_fail_on_malicious_returns_two(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    sample = tmp_path / "sample.txt"
    sample.write_bytes(EICAR)
    # EICAR only reaches the suspicious band without VirusTotal, so gate at suspicious.
    result = CliRunner().invoke(
        app,
        ["scan", str(sample), "--offline", "--format", "json", "--fail-on", "suspicious"],
    )
    assert result.exit_code == 2


def test_rules_lint_passes():
    result = CliRunner().invoke(app, ["rules", "lint", "rules"])
    assert result.exit_code == 0, result.stdout


def test_db_stats(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    result = CliRunner().invoke(app, ["db", "stats"])
    assert result.exit_code == 0, result.stdout


def test_batch_jobs_scans_every_file_in_order(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    for index in range(5):
        (inbox / f"sample{index}.txt").write_bytes(EICAR + f"#{index}".encode())

    result = CliRunner().invoke(
        app, ["batch", str(inbox), "--offline", "--jobs", "3", "--format", "json"]
    )
    assert result.exit_code == 0, result.stdout
    assert "3 worker(s)" in result.stdout

    reports = sorted((tmp_path / "out").glob("*.json"))
    assert len(reports) == 5, result.stdout
    digests = {json.loads(path.read_text())["file"]["sha256"] for path in reports}
    assert len(digests) == 5, "every file must get its own report"

    positions = [result.stdout.find(f"sample{index}.txt") for index in range(5)]
    assert all(position >= 0 for position in positions), result.stdout
    assert positions == sorted(positions), "rows must keep the input order"


def test_batch_parallel_matches_serial_scores(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    for index in range(4):
        (inbox / f"sample{index}.txt").write_bytes(EICAR + f"#{index}".encode())

    def scores(jobs: str, out: str) -> dict[str, int]:
        result = CliRunner().invoke(
            app,
            ["batch", str(inbox), "--offline", "--jobs", jobs, "--format", "json", "-o", out],
        )
        assert result.exit_code == 0, result.stdout
        payloads = [json.loads(path.read_text()) for path in (tmp_path / out).glob("*.json")]
        assert len(payloads) == 4
        return {p["file"]["name"]: p["verdict"]["score"] for p in payloads}

    assert scores("1", "serial") == scores("4", "parallel")


def test_batch_jobs_must_be_positive(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "sample.txt").write_bytes(EICAR)
    result = CliRunner().invoke(app, ["batch", str(inbox), "--jobs", "0"])
    assert result.exit_code == 2


def test_vt_check_requires_key(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    get_settings.cache_clear()
    result = CliRunner().invoke(app, ["vt", "check", "a" * 64])
    assert result.exit_code == 3
    assert "VT_API_KEY" in result.stdout


def test_vt_check_rejects_bad_target(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("VT_API_KEY", "dummy-key")
    get_settings.cache_clear()
    result = CliRunner().invoke(app, ["vt", "check", "not-a-hash-or-file"])
    assert result.exit_code == 4

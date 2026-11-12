"""Report output paths must fail with a message, never with a traceback."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from maltriage.cli import app

runner = CliRunner()


def _sample(tmp_path: Path) -> Path:
    sample = tmp_path / "note.txt"
    sample.write_text("hello world\n", encoding="utf-8")
    return sample


def test_out_pointing_at_a_file_fails_cleanly(tmp_path):
    sample = _sample(tmp_path)
    blocked = tmp_path / "notadir"
    blocked.write_text("", encoding="utf-8")

    result = runner.invoke(
        app, ["scan", str(sample), "--offline", "--out", str(blocked), "--format", "json"]
    )

    assert result.exit_code == 2, result.output
    assert "cannot use report directory" in result.output
    assert "Traceback" not in result.output


def test_out_inside_a_file_fails_cleanly(tmp_path):
    sample = _sample(tmp_path)
    blocked = tmp_path / "notadir"
    blocked.write_text("", encoding="utf-8")

    result = runner.invoke(
        app,
        ["scan", str(sample), "--offline", "--out", str(blocked / "reports"), "--format", "json"],
    )

    assert result.exit_code == 2, result.output
    assert "cannot use report directory" in result.output
    assert "Traceback" not in result.output


def test_nested_out_directory_is_created(tmp_path):
    sample = _sample(tmp_path)
    out = tmp_path / "deep" / "nested" / "out"

    result = runner.invoke(
        app, ["scan", str(sample), "--offline", "--out", str(out), "--format", "json,html"]
    )

    assert result.exit_code == 0, result.output
    assert list(out.glob("*.json"))
    assert list(out.glob("*.html"))

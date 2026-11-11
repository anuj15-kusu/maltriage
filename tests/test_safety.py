from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from maltriage.safety import SafetyError, check_file, inspect_zip, safe_member_name


def test_missing_file(tmp_path: Path):
    with pytest.raises(SafetyError):
        check_file(tmp_path / "nope.bin", 10)


def test_empty_file(tmp_path: Path):
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    with pytest.raises(SafetyError):
        check_file(target, 10)


def test_size_limit(tmp_path: Path):
    target = tmp_path / "big.bin"
    target.write_bytes(b"A" * (2 * 1024 * 1024))
    with pytest.raises(SafetyError):
        check_file(target, 1)


def test_directory_rejected(tmp_path: Path):
    with pytest.raises(SafetyError):
        check_file(tmp_path, 10)


@pytest.mark.parametrize(
    "name",
    ["../escape.txt", "..\\escape.txt", "/etc/passwd", "C:\\Windows\\system32\\x.dll", ""],
)
def test_unsafe_member_names(name: str):
    assert safe_member_name(name) is False


@pytest.mark.parametrize("name", ["folder/file.txt", "a.txt", "deep/nested/path.bin"])
def test_safe_member_names(name: str):
    assert safe_member_name(name) is True


def test_zip_bomb_by_size():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\x00" * (5 * 1024 * 1024))
    inspection = inspect_zip(buffer.getvalue(), max_files=10, max_mb=1, max_ratio=100)
    assert inspection.problems
    assert any("exceeds limit" in problem for problem in inspection.problems)


def test_zip_bomb_by_ratio():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\x00" * (20 * 1024 * 1024))
    inspection = inspect_zip(buffer.getvalue(), max_files=10, max_mb=500, max_ratio=50)
    assert any("bomb" in problem for problem in inspection.problems)


def test_member_limit_truncates():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for index in range(20):
            zf.writestr(f"file{index}.txt", b"x")
    inspection = inspect_zip(buffer.getvalue(), max_files=5, max_mb=100, max_ratio=100)
    assert inspection.truncated
    assert len(inspection.members) == 5

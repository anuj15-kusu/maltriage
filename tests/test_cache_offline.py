"""The cache is an optimisation, never a reason to lose a scan.

A read-only root filesystem (the hardened container), a full disk or a permissions
problem used to surface as an sqlite3.OperationalError traceback before any analysis
ran. These tests pin the degrade-instead-of-crash behaviour.
"""

from __future__ import annotations

from pathlib import Path

from maltriage.cache import Cache


def test_a_writable_path_still_works(tmp_path: Path):
    cache = Cache(tmp_path / "cache.db")
    try:
        assert cache.enabled is True
        assert cache.reason is None
        cache.remember_sample("a" * 64, "b" * 32, "c" * 40, None, 12, "text")
        assert cache.stats()["enabled"] is True
    finally:
        cache.close()


def test_an_unusable_location_degrades_instead_of_raising(tmp_path: Path):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("this path is a file, so .cache/ below it cannot exist", encoding="utf-8")

    cache = Cache(blocker / "cache.db")

    assert cache.enabled is False
    assert cache.reason, "the caller must be able to say why the cache is off"
    assert "cache.db" in cache.reason

    # Every operation is a no-op rather than an error.
    cache.remember_sample("a" * 64, "b" * 32, "c" * 40, None, 12, "text")
    assert cache.stats() == {"enabled": False}
    cache.close()


def test_disabling_on_purpose_stays_quiet(tmp_path: Path):
    cache = Cache(tmp_path / "cache.db", enabled=False)
    try:
        assert cache.enabled is False
        assert cache.reason is None, "--no-cache is a choice, not a failure"
        assert cache.stats() == {"enabled": False}
    finally:
        cache.close()

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maltriage import memory

MIB = 1024 * 1024


def test_peak_rss_is_readable():
    peak = memory.peak_rss_bytes()
    assert peak is not None
    assert peak > 16 * 1024 * 1024, "a Python process with YARA loaded is never this small"


def test_available_memory_is_readable_or_unknown():
    available = memory.available_bytes()
    assert available is None or available > 0


def test_one_batch_splits_the_peak_into_baseline_and_slope():
    # 100 MiB before scanning, 120 MiB after a 10 MiB sample => 2 bytes per byte.
    measurement = memory.build(
        baseline_bytes=100 * MIB,
        peak_bytes=120 * MIB,
        sample_bytes=10 * MIB,
        workers=2,
    )
    assert measurement.fixed_bytes == 100 * MIB
    assert measurement.per_sample_byte == pytest.approx(2.0)

    small = measurement.expected_bytes(10 * MIB)
    large = measurement.expected_bytes(100 * MIB)
    assert small < large
    assert small == int(120 * MIB * memory.HEADROOM)
    assert large == int(300 * MIB * memory.HEADROOM)


def test_two_batches_pin_the_real_line():
    # The first batch alone guesses its baseline before the rules compile.
    first = memory.build(
        baseline_bytes=39 * MIB,
        peak_bytes=50 * MIB,
        sample_bytes=4 * MIB,
        workers=2,
    )
    assert first.per_sample_byte == pytest.approx(2.75)

    # A larger batch turns the two peaks into an exact line: 2.5 bytes per byte,
    # 40 MiB of fixed cost, regardless of the early baseline.
    second = memory.build(
        baseline_bytes=39 * MIB,
        peak_bytes=90 * MIB,
        sample_bytes=20 * MIB,
        workers=2,
        previous=first,
    )
    assert second.per_sample_byte == pytest.approx(2.5)
    assert second.fixed_bytes == pytest.approx(40 * MIB)


def test_a_similar_batch_keeps_the_established_line():
    previous = memory.build(
        baseline_bytes=100 * MIB, peak_bytes=120 * MIB, sample_bytes=10 * MIB, workers=2
    )
    similar = memory.build(
        baseline_bytes=30 * MIB,
        peak_bytes=125 * MIB,
        sample_bytes=11 * MIB,
        workers=2,
        previous=previous,
    )
    assert similar.per_sample_byte == pytest.approx(2.0)
    assert similar.fixed_bytes == previous.fixed_bytes


def test_tiny_samples_keep_the_established_line():
    previous = memory.build(
        baseline_bytes=100 * MIB, peak_bytes=120 * MIB, sample_bytes=10 * MIB, workers=2
    )
    tiny = memory.build(
        baseline_bytes=50 * MIB,
        peak_bytes=60 * MIB,
        sample_bytes=256 * 1024,
        workers=2,
        previous=previous,
    )
    assert tiny.per_sample_byte == pytest.approx(2.0)
    assert tiny.fixed_bytes == previous.fixed_bytes


def test_the_slope_is_clamped():
    # 3 MiB of growth on a 256 KiB sample is a slope of 12, which is noise.
    measurement = memory.build(
        baseline_bytes=50 * MIB, peak_bytes=53 * MIB, sample_bytes=256 * 1024, workers=1
    )
    assert measurement.per_sample_byte == memory.MAX_PER_SAMPLE_BYTE


def test_a_peak_below_the_baseline_has_no_slope():
    measurement = memory.build(baseline_bytes=50, peak_bytes=40, sample_bytes=100, workers=1)
    assert measurement.per_sample_byte == 0.0
    assert measurement.fixed_bytes == 50
    assert measurement.expected_bytes(10_000) == memory.MIN_WORKER_BYTES


def test_tiny_samples_keep_the_floor():
    measurement = memory.build(baseline_bytes=1024, peak_bytes=1024, sample_bytes=1, workers=1)
    assert measurement.expected_bytes(1) == memory.MIN_WORKER_BYTES


def test_save_and_load_round_trip(tmp_path: Path):
    cache_path = tmp_path / ".cache" / "maltriage.db"
    measurement = memory.build(baseline_bytes=1_000, peak_bytes=3_000, sample_bytes=500, workers=3)
    path = memory.save(cache_path, measurement)

    assert path is not None
    assert path.name == memory.MEASUREMENT_NAME
    assert path.parent == tmp_path / ".cache"
    assert memory.load(cache_path) == measurement


def test_a_corrupt_measurement_is_ignored(tmp_path: Path):
    cache_path = tmp_path / ".cache" / "maltriage.db"
    path = memory.path_for(cache_path)
    assert path is not None
    path.parent.mkdir(parents=True)

    path.write_text("{not json", encoding="utf-8")
    assert memory.load(cache_path) is None

    path.write_text(json.dumps({"fixed_bytes": 1}), encoding="utf-8")
    assert memory.load(cache_path) is None


def test_a_missing_measurement_is_none(tmp_path: Path):
    assert memory.load(tmp_path / "nothing.db") is None
    assert memory.load(None) is None

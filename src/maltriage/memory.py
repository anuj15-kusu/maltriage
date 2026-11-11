"""Peak memory measurement, so `--jobs` is sized from evidence instead of a guess.

A worker's footprint is modelled as a fixed cost (interpreter, libraries, YARA
rules) plus a per-byte cost. Both come from a real batch: every worker reports
its own peak resident set size, and the numbers are reused by later runs from
`.cache/worker_memory.json`.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

MEASUREMENT_NAME = "worker_memory.json"
# Headroom for a batch that parses worse than the one that produced the numbers.
HEADROOM = 1.15
MIN_WORKER_BYTES = 64 * 1024 * 1024
# Parser cost is linear in a normal file. Anything steeper is noise or a
# pathological parser, so the slope is clamped instead of trusted blindly.
MAX_PER_SAMPLE_BYTE = 4.0


def peak_rss_bytes() -> int | None:
    """Peak resident set size of this process, or None when it cannot be read."""
    if sys.platform == "win32":
        return _windows_peak_bytes()
    try:
        import resource
    except ImportError:  # pragma: no cover - every POSIX build has it
        return None
    peak = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # Linux reports KiB, macOS reports bytes.
    return peak if sys.platform == "darwin" else peak * 1024


def available_bytes() -> int | None:
    """Free physical memory, or None when the platform has no cheap probe."""
    if sys.platform == "win32":
        return _windows_free_bytes()

    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024

    try:
        pages = os.sysconf("SC_AVPHYS_PAGES")
        size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, OSError, ValueError):
        return None
    if pages <= 0 or size <= 0:
        return None
    return int(pages) * int(size)


def _windows_peak_bytes() -> int | None:
    """PeakWorkingSetSize of this process. Nothing is loaded from a sample."""
    import ctypes
    from ctypes import wintypes

    class _Counters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("page_faults", wintypes.DWORD),
            ("peak_working_set", ctypes.c_size_t),
            ("working_set", ctypes.c_size_t),
            ("peak_paged_pool", ctypes.c_size_t),
            ("paged_pool", ctypes.c_size_t),
            ("peak_nonpaged_pool", ctypes.c_size_t),
            ("nonpaged_pool", ctypes.c_size_t),
            ("pagefile_usage", ctypes.c_size_t),
            ("peak_pagefile_usage", ctypes.c_size_t),
        ]

    # GetCurrentProcess() returns the pseudo-handle (HANDLE)-1. Declaring the
    # restype is what keeps it 64-bit on x64: as a plain int it is truncated to
    # 32 bits on the way back into GetProcessMemoryInfo, which then fails.
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        get_info = getattr(kernel32, "K32GetProcessMemoryInfo", None)
        if get_info is None:
            get_info = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
        get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Counters), wintypes.DWORD]
        get_info.restype = wintypes.BOOL
    except (AttributeError, OSError):
        return None

    counters = _Counters()
    counters.cb = ctypes.sizeof(_Counters)
    try:
        handle = kernel32.GetCurrentProcess()
        ok = get_info(handle, ctypes.byref(counters), counters.cb)
    except (AttributeError, OSError):
        return None
    return int(counters.peak_working_set) if ok else None


def _windows_free_bytes() -> int | None:
    """Free physical memory. Nothing is loaded, imported or executed for a sample."""
    import ctypes

    class _MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_ulong),
            ("memory_load", ctypes.c_ulong),
            ("total_phys", ctypes.c_ulonglong),
            ("avail_phys", ctypes.c_ulonglong),
            ("total_page_file", ctypes.c_ulonglong),
            ("avail_page_file", ctypes.c_ulonglong),
            ("total_virtual", ctypes.c_ulonglong),
            ("avail_virtual", ctypes.c_ulonglong),
            ("avail_extended_virtual", ctypes.c_ulonglong),
        ]

    status = _MemoryStatus()
    status.length = ctypes.sizeof(_MemoryStatus)
    try:
        ok = ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
    except (AttributeError, OSError):
        return None
    return int(status.avail_phys) if ok else None


@dataclass(frozen=True)
class Measurement:
    """What one worker actually cost in the last measured batch."""

    fixed_bytes: int
    per_sample_byte: float
    sample_bytes: int
    peak_bytes: int
    workers: int
    measured_at: str

    def expected_bytes(self, sample_bytes: int) -> int:
        """Footprint for a sample of this size, with headroom and a floor."""
        predicted = self.fixed_bytes + self.per_sample_byte * max(0, sample_bytes)
        return max(MIN_WORKER_BYTES, int(predicted * HEADROOM))


def build(
    *,
    baseline_bytes: int,
    peak_bytes: int,
    sample_bytes: int,
    workers: int,
    previous: Measurement | None = None,
) -> Measurement:
    """Turn one batch's peak numbers into a reusable model."""
    fixed, slope = _fit(baseline_bytes, peak_bytes, sample_bytes, previous)
    return Measurement(
        fixed_bytes=int(max(0.0, fixed)),
        per_sample_byte=slope,
        sample_bytes=max(0, sample_bytes),
        peak_bytes=max(0, peak_bytes),
        workers=max(1, workers),
        measured_at=datetime.now(UTC).isoformat(),
    )


def _fit(
    baseline_bytes: int, peak_bytes: int, sample_bytes: int, previous: Measurement | None
) -> tuple[float, float]:
    """Fixed cost and per-byte slope, preferring two points over a baseline guess.

    A single batch can only split its peak into the pre-scan baseline and a slope,
    and that baseline is taken before YARA compiles its rules, so the slope comes out
    too steep. A second batch of clearly larger samples pins the line exactly; a
    batch of similar or tiny samples keeps the line that is already known.
    """
    if previous is not None and previous.sample_bytes > 0 and sample_bytes > 0:
        if sample_bytes > previous.sample_bytes * 1.5:
            slope = (peak_bytes - previous.peak_bytes) / (sample_bytes - previous.sample_bytes)
            slope = min(MAX_PER_SAMPLE_BYTE, max(0.0, slope))
            return peak_bytes - slope * sample_bytes, slope
        return float(previous.fixed_bytes), previous.per_sample_byte

    if sample_bytes <= 0:
        return float(baseline_bytes), 0.0
    variable = max(0, peak_bytes - baseline_bytes)
    return float(baseline_bytes), min(MAX_PER_SAMPLE_BYTE, variable / sample_bytes)


def path_for(cache_path: Path | None) -> Path | None:
    """Where the measurement lives, next to the scan database."""
    return None if cache_path is None else cache_path.parent / MEASUREMENT_NAME


def load(cache_path: Path | None) -> Measurement | None:
    """The stored measurement, or None when it is missing or unreadable."""
    path = path_for(cache_path)
    if path is None or not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return Measurement(
            fixed_bytes=int(payload["fixed_bytes"]),
            per_sample_byte=float(payload["per_sample_byte"]),
            sample_bytes=int(payload["sample_bytes"]),
            peak_bytes=int(payload["peak_bytes"]),
            workers=int(payload["workers"]),
            measured_at=str(payload["measured_at"]),
        )
    except (OSError, KeyError, TypeError, ValueError):
        return None


def save(cache_path: Path | None, measurement: Measurement) -> Path | None:
    """Persist a measurement for the next run; never raises for an unwritable cache."""
    path = path_for(cache_path)
    if path is None:
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(measurement), indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        return None
    return path

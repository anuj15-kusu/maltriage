"""Sample bytes for the tests, and the one place that copes with a host antivirus.

Writing the EICAR string to disk is exactly what real-time protection exists to stop.
Microsoft Defender quarantines the file the moment it appears: the path still exists
but reads fail with EINVAL / WinError 87, so nothing can scan it. That is the host
protecting itself, so the test is skipped with that reason instead of failing, or
passing by luck on a machine whose protection happens to be off.
"""

from __future__ import annotations

from pathlib import Path

import pytest

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def write_eicar(path: Path, suffix: bytes = b"") -> Path:
    """Write the EICAR test string and prove the bytes can be read back."""
    data = EICAR + suffix
    path.write_bytes(data)
    try:
        readable = path.read_bytes() == data
    except OSError as exc:
        pytest.skip(f"host antivirus blocked the EICAR test file: {exc}")
    if not readable:
        pytest.skip("host antivirus altered the EICAR test file")
    return path

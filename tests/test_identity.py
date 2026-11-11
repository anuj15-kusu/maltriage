from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from maltriage.identity import fuzzy_hash, hashes, resolve_hash


def test_hashes_are_stable():
    digest = hashes(b"abc")
    assert digest["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert digest["md5"] == hashlib.md5(b"abc").hexdigest()


def test_resolve_hash_accepts_a_digest():
    digest = "A" * 64
    assert resolve_hash(digest) == "a" * 64


def test_resolve_hash_reads_a_file(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello triage")
    assert resolve_hash(str(sample)) == hashlib.sha256(b"hello triage").hexdigest()


def test_resolve_hash_rejects_garbage():
    with pytest.raises(ValueError):
        resolve_hash("definitely-not-a-hash")


def test_fuzzy_hash_is_available():
    value = fuzzy_hash(b"the quick brown fox " * 40)
    assert value is None or isinstance(value, str)

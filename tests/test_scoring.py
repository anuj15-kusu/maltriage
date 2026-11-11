from __future__ import annotations

from maltriage.models import Finding
from maltriage.scoring import band_for, default_weights, score


def _finding(signal: str) -> Finding:
    return Finding(analyzer="test", title=signal, signal=signal)


def test_unknown_signal_is_ignored():
    assert score([_finding("not_a_real_signal")]).score == 0


def test_duplicate_signal_counted_once():
    assert score([_finding("yara_malware"), _finding("yara_malware")]).score == 25


def test_category_cap_applies():
    verdict = score([_finding("vt_malicious_high"), _finding("vt_malicious_low")])
    # 35 + 20 = 55, enrichment cap is 40
    assert verdict.score == 40


def test_bands():
    verdict = score(
        [_finding("vt_malicious_high"), _finding("yara_malware"), _finding("macro_autoexec")]
    )
    assert verdict.score == 80
    assert verdict.band == "malicious"


def test_negative_signal_is_clamped_at_zero():
    assert score([_finding("known_good_signer")]).score == 0


def test_negative_signal_reduces_score():
    verdict = score([_finding("vt_malicious_low"), _finding("known_good_signer")])
    assert verdict.score == 0  # 20 - 25 clamps to 0


def test_breakdown_is_explainable():
    verdict = score([_finding("vt_malicious_high"), _finding("packed_high_entropy")])
    signals = {item.signal for item in verdict.breakdown}
    assert signals == {"vt_malicious_high", "packed_high_entropy"}
    assert all(item.label for item in verdict.breakdown)


def test_band_thresholds():
    bands = default_weights().bands
    assert band_for(0, bands) == "clean"
    assert band_for(25, bands) == "suspicious"
    assert band_for(60, bands) == "likely_malicious"
    assert band_for(95, bands) == "malicious"

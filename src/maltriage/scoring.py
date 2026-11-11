"""Explainable scoring: every point in the total traces back to a named signal."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from maltriage.config import DATA_DIR
from maltriage.models import Finding, ScoreContribution, Severity, Verdict


@dataclass(frozen=True)
class Signal:
    name: str
    points: int
    category: str
    label: str


@dataclass(frozen=True)
class Weights:
    bands: dict[str, int]
    caps: dict[str, int]
    signals: dict[str, Signal]


def load_weights(path: Path | None = None) -> Weights:
    source = path or DATA_DIR / "weights.yaml"
    raw: dict[str, Any] = yaml.safe_load(source.read_text(encoding="utf-8"))
    signals = {
        name: Signal(
            name=name,
            points=int(spec["points"]),
            category=spec.get("category", "static"),
            label=spec.get("label", name),
        )
        for name, spec in raw.get("signals", {}).items()
    }
    return Weights(
        bands={k: int(v) for k, v in raw.get("bands", {}).items()},
        caps={k: int(v) for k, v in raw.get("caps", {}).items()},
        signals=signals,
    )


@lru_cache(maxsize=1)
def default_weights() -> Weights:
    return load_weights()


def band_for(score: int, bands: dict[str, int]) -> str:
    if score >= bands.get("malicious", 80):
        return "malicious"
    if score >= bands.get("likely_malicious", 50):
        return "likely_malicious"
    if score >= bands.get("suspicious", 20):
        return "suspicious"
    return "clean"


def score(findings: list[Finding], weights: Weights | None = None) -> Verdict:
    """Sum every distinct signal once, cap each category, then clamp 0-100."""
    weights = weights or default_weights()

    seen: dict[str, Signal] = {}
    for finding in findings:
        if not finding.signal:
            continue
        signal = weights.signals.get(finding.signal)
        if signal is None or signal.name in seen:
            continue
        seen[signal.name] = signal

    per_category: dict[str, int] = {}
    negatives = 0
    for signal in seen.values():
        if signal.points < 0:
            negatives += signal.points
        else:
            per_category[signal.category] = per_category.get(signal.category, 0) + signal.points

    breakdown: list[ScoreContribution] = []
    for signal in sorted(seen.values(), key=lambda s: (-abs(s.points), s.name)):
        cap = weights.caps.get(signal.category)
        applied = signal.points
        if signal.points > 0 and cap is not None and "capped" not in signal.category:
            applied = signal.points  # applied total is adjusted below
        breakdown.append(
            ScoreContribution(
                signal=signal.name,
                label=signal.label,
                category=signal.category,
                points=signal.points,
                applied_points=applied,
            )
        )

    total = 0
    for category, value in per_category.items():
        cap = weights.caps.get(category)
        total += min(value, cap) if cap is not None else value
    total += negatives
    total = max(0, min(100, total))

    # Recompute per-contribution applied points proportionally to the capped total.
    if per_category:
        for contribution in breakdown:
            if contribution.points <= 0:
                contribution.applied_points = contribution.points
                continue
            cap = weights.caps.get(contribution.category)
            value = per_category[contribution.category]
            if cap is not None and value > cap:
                contribution.applied_points = round(contribution.points * cap / value)
            else:
                contribution.applied_points = contribution.points

    contributors = {f.analyzer for f in findings if f.signal and f.signal in seen}
    severity_bonus = 0.0
    if findings:
        top = max(findings, key=lambda f: list(Severity).index(f.severity))
        severity_bonus = 0.1 if top.severity in (Severity.HIGH, Severity.CRITICAL) else 0.0
    confidence = min(0.95, 0.35 + 0.12 * len(contributors) + severity_bonus)

    return Verdict(
        score=total,
        band=band_for(total, weights.bands),
        confidence=round(confidence, 2),
        breakdown=breakdown,
    )

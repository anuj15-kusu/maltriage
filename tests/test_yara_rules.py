"""The shipped YARA rules, exercised without ever writing a sample to disk.

Host antivirus quarantines the EICAR string the moment it lands in a file: the path
still exists, but reads fail, which is why the disk-based pipeline tests skip on such
a machine. Matching the same bytes in memory keeps the rules themselves covered
everywhere, including Windows with real-time protection on.
"""

from __future__ import annotations

from pathlib import Path

from maltriage.analyzers.yara_scan import YaraAnalyzer, load_ruleset
from maltriage.config import Settings
from maltriage.identity import hashes
from maltriage.models import FileKind, SampleContext

from .sample_files import EICAR

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_every_rule_pack_compiles():
    compiled, meta = load_ruleset(REPO_ROOT / "rules")
    assert compiled is not None, meta
    assert "malware" in meta["namespaces"]
    assert sum(meta["namespaces"].values()) >= 3


def test_eicar_rule_matches_in_memory():
    compiled, meta = load_ruleset(REPO_ROOT / "rules")
    assert compiled is not None, meta

    matches = compiled.match(data=EICAR, timeout=10)
    malware = [match for match in matches if match.namespace == "malware"]
    assert malware, f"no malware-namespace match, got {[m.rule for m in matches]}"


def test_yara_analyzer_scores_an_in_memory_sample(tmp_path: Path, settings: Settings):
    compiled, meta = load_ruleset(settings.rules_dir)
    assert compiled is not None, meta

    ctx = SampleContext(
        path=tmp_path / "in-memory.bin",
        size=len(EICAR),
        kind=FileKind.TEXT,
        config=settings,
        hashes=hashes(EICAR),
    )
    ctx._data = EICAR

    findings = YaraAnalyzer().run(ctx)
    assert findings, "the analyzer reported nothing for a rule that should match"
    assert findings[0].signal == "yara_malware"
    assert findings[0].severity.value in {"high", "critical"}

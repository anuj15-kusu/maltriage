"""YARA rule scanning. Rules live in plain files under the rules/ directory."""

from __future__ import annotations

import hashlib
from pathlib import Path

from maltriage.analyzers.base import Analyzer, register_analyzer
from maltriage.models import Finding, SampleContext, Severity

_CACHE: dict[str, tuple[float, object, dict]] = {}

MALWARE_NAMESPACES = {"malware"}
SEVERITY_BY_NAME = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def rule_files(rules_dir: Path) -> list[Path]:
    if not rules_dir.exists():
        return []
    files = [p for p in rules_dir.rglob("*") if p.suffix.lower() in {".yar", ".yara"}]
    return sorted(files)


def load_ruleset(rules_dir: Path) -> tuple[object | None, dict]:
    """Compile every rule file, grouped by sub-directory namespace. Cached by mtime."""
    import yara

    files = rule_files(rules_dir)
    meta: dict = {"files": [str(p.relative_to(rules_dir)) for p in files], "namespaces": {}}
    if not files:
        meta["hash"] = None
        return None, meta

    signature = hashlib.sha256()
    newest = 0.0
    sources: dict[str, list[str]] = {}
    for path in files:
        raw = path.read_bytes()
        signature.update(raw)
        newest = max(newest, path.stat().st_mtime)
        namespace = path.parent.name if path.parent != rules_dir else "root"
        sources.setdefault(namespace, []).append(raw.decode("utf-8", "replace"))

    cache_key = str(rules_dir.resolve())
    cached = _CACHE.get(cache_key)
    if cached and cached[0] == newest:
        return cached[1], cached[2]

    meta["hash"] = signature.hexdigest()
    meta["namespaces"] = {ns: len(srcs) for ns, srcs in sources.items()}
    try:
        compiled = yara.compile(sources={ns: "\n".join(srcs) for ns, srcs in sources.items()})
    except Exception as exc:  # invalid rules must not kill the scan
        meta["error"] = str(exc)
        return None, meta

    _CACHE[cache_key] = (newest, compiled, meta)
    return compiled, meta


@register_analyzer
class YaraAnalyzer(Analyzer):
    name = "yara"
    applies_to = None

    def run(self, ctx: SampleContext) -> list[Finding]:
        rules_dir: Path = ctx.config.rules_dir
        compiled, meta = load_ruleset(rules_dir)
        ctx.parsed["ruleset"] = meta
        if compiled is None:
            if meta.get("error"):
                ctx.add_error(f"yara compile: {meta['error']}")
            return []

        try:
            matches = compiled.match(data=ctx.read(), timeout=30)
        except Exception as exc:
            ctx.add_error(f"yara match: {exc}")
            return []

        findings: list[Finding] = []
        for match in matches:
            tags = list(match.tags)
            meta_sev = str(match.meta.get("severity", "")).lower()
            severity = SEVERITY_BY_NAME.get(meta_sev)
            if severity is None:
                severity = (
                    Severity.HIGH if match.namespace in MALWARE_NAMESPACES else Severity.MEDIUM
                )

            # The directory a rule lives in decides how much it weighs: rules/malware/
            # is a family match, everything else is behavioural signal.
            signal = "yara_malware" if match.namespace in MALWARE_NAMESPACES else "yara_suspicious"

            strings_hit = []
            for string_match in match.strings[:10]:
                for instance in getattr(string_match, "instances", [])[:1]:
                    strings_hit.append(
                        {
                            "identifier": string_match.identifier,
                            "offset": hex(instance.offset),
                            "data": instance.matched_data[:64].decode("latin-1", "replace"),
                        }
                    )
                if not getattr(string_match, "instances", None):
                    strings_hit.append({"identifier": str(string_match)})

            findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"YARA rule matched: {match.rule}",
                    severity=severity,
                    confidence=0.85,
                    description=str(match.meta.get("description", "Rule matched the sample.")),
                    signal=signal,
                    evidence={
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": tags,
                        "meta": {k: str(v) for k, v in match.meta.items()},
                        "strings": strings_hit,
                    },
                    tags=["yara", *tags],
                )
            )
        return findings

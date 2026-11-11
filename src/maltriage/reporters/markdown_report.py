"""Markdown report, sized for pasting into a ticket."""

from __future__ import annotations

from maltriage.iocs import defang as defang_value
from maltriage.models import Report

BAND_LABEL = {
    "clean": "clean / likely benign",
    "suspicious": "suspicious",
    "likely_malicious": "likely malicious",
    "malicious": "malicious",
}


class MarkdownRenderer:
    name = "markdown"
    suffix = ".md"

    def render(self, report: Report, *, defang: bool = True) -> str:
        lines: list[str] = []
        name = report.file.name
        lines.append(f"# Malware triage: `{name}`")
        lines.append("")
        lines.append(
            f"**Verdict:** {BAND_LABEL.get(report.verdict.band, report.verdict.band)} "
            f"— score **{report.verdict.score}/100** (confidence {report.verdict.confidence})"
        )
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| SHA-256 | `{report.file.sha256}` |")
        lines.append(f"| MD5 | `{report.file.md5}` |")
        lines.append(f"| Size | {report.file.size} bytes |")
        lines.append(f"| Type | {report.file.kind.value} |")
        lines.append(f"| ssdeep | `{report.file.ssdeep or '-'}` |")
        lines.append(f"| Ruleset | `{(report.ruleset or {}).get('hash') or '-'}` |")
        lines.append("")

        if report.verdict.breakdown:
            lines.append("## Score breakdown")
            lines.append("")
            lines.append("| Signal | Points |")
            lines.append("| --- | --- |")
            for item in report.verdict.breakdown:
                lines.append(f"| {item.label} | {item.applied_points:+d} |")
            lines.append("")

        lines.append("## Findings")
        lines.append("")
        if report.findings:
            lines.append("| Severity | Analyzer | Finding |")
            lines.append("| --- | --- | --- |")
            for finding in report.findings:
                title = finding.title.replace("|", "\\|")
                lines.append(f"| {finding.severity.value} | {finding.analyzer} | {title} |")
        else:
            lines.append("_No findings._")
        lines.append("")

        if report.enrichment:
            lines.append("## Enrichment")
            lines.append("")
            for result in report.enrichment:
                lines.append(f"- **{result.provider}** ({result.status}): {result.summary}")
            lines.append("")

        if report.iocs:
            lines.append(f"## Indicators ({len(report.iocs)})")
            lines.append("")
            for ioc in report.iocs[:100]:
                value = defang_value(ioc.value) if defang else ioc.value
                lines.append(f"- `{ioc.type.value}` {value}")
            lines.append("")

        if report.errors:
            lines.append("## Parser notes")
            lines.append("")
            for error in report.errors:
                lines.append(f"- {error}")
            lines.append("")

        lines.append("---")
        lines.append(
            f"_maltriage {report.tool_version} — static analysis only, "
            "the sample was never executed._"
        )
        return "\n".join(lines) + "\n"

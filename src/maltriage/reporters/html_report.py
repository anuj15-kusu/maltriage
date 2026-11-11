"""Self-contained HTML report (no CDN, works offline and in air-gapped labs)."""

from __future__ import annotations

from maltriage.iocs import defang as defang_value
from maltriage.models import Report
from maltriage.reporters.base import BAND_COLORS, SEVERITY_COLORS, template_dir


class HTMLRenderer:
    name = "html"
    suffix = ".html"

    def render(self, report: Report, *, defang: bool = True) -> str:
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(template_dir())),
            autoescape=select_autoescape(["html", "j2"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template("report.html.j2")

        def ioc_value(value: str) -> str:
            return defang_value(value) if defang else value

        iocs = [
            {"type": ioc.type.value, "value": ioc_value(ioc.value), "context": ioc.context}
            for ioc in report.iocs
        ]
        grouped: dict[str, int] = {}
        for ioc in report.iocs:
            grouped[ioc.type.value] = grouped.get(ioc.type.value, 0) + 1

        findings = sorted(
            report.findings,
            key=lambda f: ["info", "low", "medium", "high", "critical"].index(f.severity.value),
            reverse=True,
        )

        return template.render(
            report=report,
            findings=findings,
            iocs=iocs,
            grouped=grouped,
            sev_colors=SEVERITY_COLORS,
            band_colors=BAND_COLORS,
            defanged=defang,
        )

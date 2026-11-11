"""Canonical machine-readable report. This is the stable schema."""

from __future__ import annotations

import json

from maltriage.models import Report


class JSONRenderer:
    name = "json"
    suffix = ".json"

    def render(self, report: Report, *, defang: bool = True) -> str:
        # Raw indicators stay intact here so the file can be fed to other tooling.
        return json.dumps(json.loads(report.model_dump_json()), indent=2, ensure_ascii=False)

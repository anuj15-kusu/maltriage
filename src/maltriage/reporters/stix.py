"""STIX 2.1 bundle so indicators can be shared with other tooling."""

from __future__ import annotations

import json
import uuid

from maltriage.models import IOCType, Report

NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")
SPEC_VERSION = "2.1"

PATTERNS = {
    IOCType.URL: "url:value",
    IOCType.DOMAIN: "domain-name:value",
    IOCType.IPV4: "ipv4-addr:value",
    IOCType.EMAIL: "email-addr:value",
    IOCType.BTC: "cryptocurrency-wallet:value",
    IOCType.REGISTRY: None,
}


def _sid(*parts: str) -> str:
    return str(uuid.uuid5(NAMESPACE, "|".join(parts)))


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


class STIXRenderer:
    name = "stix"
    suffix = ".stix.json"

    def render(self, report: Report, *, defang: bool = True) -> str:
        # STIX must carry the real indicator, never the defanged form.
        objects: list[dict] = []

        file_id = f"file--{_sid('file', report.file.sha256)}"
        objects.append(
            {
                "type": "file",
                "spec_version": SPEC_VERSION,
                "id": file_id,
                "name": report.file.name,
                "size": report.file.size,
                "hashes": {
                    "SHA-256": report.file.sha256,
                    "SHA-1": report.file.sha1,
                    "MD5": report.file.md5,
                },
            }
        )

        objects.append(
            {
                "type": "malware-analysis",
                "spec_version": SPEC_VERSION,
                "id": f"malware-analysis--{_sid('analysis', report.file.sha256)}",
                "product": f"maltriage {report.tool_version}",
                "analysis_started": report.generated_at.isoformat(),
                "analysis_ended": report.generated_at.isoformat(),
                "result": "malicious"
                if report.verdict.band in {"malicious", "likely_malicious"}
                else "suspicious"
                if report.verdict.band == "suspicious"
                else "benign",
                "analysis_sco_refs": [file_id],
            }
        )

        for ioc in report.iocs:
            pattern_path = PATTERNS.get(ioc.type)
            if not pattern_path:
                continue
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": SPEC_VERSION,
                    "id": f"indicator--{_sid('ioc', ioc.type.value, ioc.value)}",
                    "created": report.generated_at.isoformat(),
                    "modified": report.generated_at.isoformat(),
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[{pattern_path} = '{_quote(ioc.value)}']",
                    "pattern_type": "stix",
                    "valid_from": report.generated_at.isoformat(),
                    "description": f"Extracted from {report.file.sha256}",
                }
            )

        bundle = {
            "type": "bundle",
            "id": f"bundle--{_sid('bundle', report.file.sha256)}",
            "objects": objects,
        }
        return json.dumps(bundle, indent=2)

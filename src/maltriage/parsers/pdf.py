"""PDF parser: active content flags, encryption and page count."""

from __future__ import annotations

import io
import re

from maltriage.models import FileKind, SampleContext
from maltriage.parsers.base import register_parser

ACTIVE_TOKENS = {
    b"/JavaScript": "javascript",
    b"/JS": "javascript",
    b"/OpenAction": "open_action",
    b"/AA": "additional_action",
    b"/Launch": "launch_action",
    b"/EmbeddedFile": "embedded_file",
    b"/RichMedia": "rich_media",
    b"/SubmitForm": "form_submission",
    b"/GoToE": "embedded_navigation",
    b"/JBIG2Decode": "jbig2_filter",
}

URL_RE = re.compile(rb"https?://[^\s\)\]>\"']{4,200}")


@register_parser
class PDFParser:
    name = "pdf"
    kinds = {FileKind.PDF}

    def parse(self, ctx: SampleContext) -> None:
        data = ctx.read()
        result: dict = {
            "active": {},
            "urls": [],
            "encrypted": False,
            "pages": None,
            "producer": None,
            "creator": None,
            "objects": None,
        }

        for token, label in ACTIVE_TOKENS.items():
            if token in data:
                result["active"][label] = result["active"].get(label, 0) + data.count(token)

        result["urls"] = [m.group().decode("ascii", "ignore") for m in URL_RE.finditer(data)][:20]

        producer = re.search(rb"/Producer\s*\(([^)]{0,200})\)", data)
        creator = re.search(rb"/Creator\s*\(([^)]{0,200})\)", data)
        result["producer"] = _clean(producer.group(1)) if producer else None
        result["creator"] = _clean(creator.group(1)) if creator else None

        # pikepdf sees compressed object streams that the raw scan cannot.
        try:
            import pikepdf

            with pikepdf.open(io.BytesIO(data)) as pdf:
                result["pages"] = len(pdf.pages)
                result["objects"] = len(pdf.objects)
                found: dict[str, int] = {}
                for obj in pdf.objects:
                    if isinstance(obj, pikepdf.Dictionary):
                        for key in obj.keys():
                            if key in (
                                "/JavaScript",
                                "/JS",
                                "/OpenAction",
                                "/AA",
                                "/Launch",
                                "/EmbeddedFile",
                                "/RichMedia",
                            ):
                                label = key.lstrip("/").lower()
                                found[label] = found.get(label, 0) + 1
                for label, count in found.items():
                    result["active"][label] = result["active"].get(label, 0) + count
        except Exception as exc:
            msg = str(exc).lower()
            if "password" in msg or "encrypted" in msg:
                result["encrypted"] = True
            else:
                ctx.add_error(f"pikepdf: {exc}")

        ctx.parsed["pdf"] = result


def _clean(raw: bytes) -> str:
    return raw.decode("latin-1", "ignore").strip()

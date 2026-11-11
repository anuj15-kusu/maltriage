"""Office document parser: OLE macros via oletools, OOXML structure via zip inspection."""

from __future__ import annotations

import io
import logging
import re
import zipfile

from maltriage.models import FileKind, SampleContext
from maltriage.parsers.base import register_parser

AUTOEXEC_KEYWORDS = [
    "AutoOpen",
    "Auto_Open",
    "AutoClose",
    "Auto_Close",
    "Document_Open",
    "Document_Close",
    "Workbook_Open",
    "Workbook_Activate",
    "Workbook_BeforeClose",
    "DocumentBeforeClose",
]

SUSPICIOUS_KEYWORDS = [
    "CreateObject",
    "WScript.Shell",
    "Shell.Application",
    "ShellExecute",
    "URLDownloadToFile",
    "MSXML2.XMLHTTP",
    "WinHttp.WinHttpRequest",
    "ADODB.Stream",
    "SaveToFile",
    "Base64",
    "FromBase64String",
    "Environ(",
    "Chr(",
    "ChrW(",
    "PowerShell",
    "cmd.exe",
    "schtasks",
    "reg add",
    "VBA7",
    "Declare PtrSafe",
    "ExecuteExcel4Macro",
    "vbHide",
    "VirtualAlloc",
]

DDE_RE = re.compile(rb"(?i)\bDDE(?:AUTO)?\b")
REMOTE_TEMPLATE_RE = re.compile(rb'(?i)(?:attachedTemplate|Target="https?://)')
EXTERNAL_REL_RE = re.compile(rb'(?i)TargetMode="External"')


@register_parser
class OfficeParser:
    name = "office"
    kinds = {FileKind.OLE, FileKind.OOXML}

    def parse(self, ctx: SampleContext) -> None:
        if ctx.kind is FileKind.OOXML:
            ctx.parsed["office"] = self._parse_ooxml(ctx)
        else:
            ctx.parsed["office"] = self._parse_ole(ctx)

    # --- OOXML (zip container) -----------------------------------------
    def _parse_ooxml(self, ctx: SampleContext) -> dict:
        data = ctx.read()
        result: dict = {
            "container": "ooxml",
            "macros": [],
            "autoexec": [],
            "suspicious": [],
            "has_vba": False,
            "remote_template": False,
            "external_rels": [],
            "embedded_objects": [],
            "dde": False,
            "members": 0,
        }
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                result["members"] = len(names)
                result["has_vba"] = any(n.lower().endswith("vbaproject.bin") for n in names)
                result["embedded_objects"] = [
                    n
                    for n in names
                    if n.lower().endswith((".bin", ".exe", ".dll", ".scr"))
                    and "vbaproject" not in n.lower()
                ][:20]
                for name in names:
                    if name.lower().endswith(".rels") or name.lower() == "word/settings.xml":
                        try:
                            blob = zf.read(name)[:200_000]
                        except Exception:
                            continue
                        if REMOTE_TEMPLATE_RE.search(blob):
                            result["remote_template"] = True
                        if EXTERNAL_REL_RE.search(blob):
                            result["external_rels"].append(name)
                    if name.lower() in {"word/document.xml", "xl/workbook.xml"}:
                        try:
                            blob = zf.read(name)[:500_000]
                        except Exception:
                            continue
                        if DDE_RE.search(blob):
                            result["dde"] = True
        except Exception as exc:
            ctx.add_error(f"ooxml parse failed: {exc}")
        return result

    # --- OLE (legacy Office) -------------------------------------------
    def _parse_ole(self, ctx: SampleContext) -> dict:
        logging.getLogger("olevba").setLevel(logging.CRITICAL)
        result: dict = {
            "container": "ole",
            "macros": [],
            "autoexec": [],
            "suspicious": [],
            "has_vba": False,
            "remote_template": False,
            "external_rels": [],
            "embedded_objects": [],
            "dde": False,
        }
        try:
            from oletools.olevba import VBA_Parser
        except Exception as exc:  # pragma: no cover
            ctx.add_error(f"oletools unavailable: {exc}")
            return result

        parser = None
        try:
            parser = VBA_Parser(str(ctx.path))
            result["has_vba"] = bool(parser.detect_vba_macros())
            if result["has_vba"]:
                for _filename, stream, vba_module, code in parser.extract_macros():
                    code = code or ""
                    result["macros"].append(
                        {"stream": stream, "module": vba_module, "code": code[:20000]}
                    )
                for kind, keyword, description in parser.detect_autoexec():
                    result["autoexec"].append(
                        {"keyword": keyword, "description": description, "kind": str(kind)}
                    )
                for kind, keyword, description in parser.detect_suspicious():
                    result["suspicious"].append(
                        {"keyword": keyword, "description": description, "kind": str(kind)}
                    )
        except Exception as exc:
            ctx.add_error(f"olevba failed: {exc}")
        finally:
            if parser is not None:
                try:
                    parser.close()
                except Exception:
                    pass

        blob = ctx.read()
        result["dde"] = bool(DDE_RE.search(blob[:2_000_000]))
        return result

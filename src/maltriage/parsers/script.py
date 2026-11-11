"""Script parser: PowerShell/VBS/JS/shell downloaders and obfuscation hints."""

from __future__ import annotations

from maltriage.models import FileKind, SampleContext
from maltriage.parsers.base import register_parser
from maltriage.strings import base64_blobs, printable_ratio, shannon_entropy

KEYWORDS = {
    "download": [
        "DownloadString",
        "DownloadFile",
        "DownloadData",
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "Start-BitsTransfer",
        "WebClient",
        "URLDownloadToFile",
        "XMLHTTP",
        "WinHttp",
        "certutil -urlcache",
        "certutil -decode",
        "bitsadmin",
        "mshta",
        "wget ",
        "curl ",
    ],
    "execution": [
        "Invoke-Expression",
        "IEX ",
        "iex(",
        "Start-Process",
        "ShellExecute",
        "WScript.Shell",
        "CreateObject",
        "cmd /c",
        "cmd.exe /c",
        "powershell -enc",
        "powershell.exe -enc",
        "-EncodedCommand",
        "msbuild.exe",
        "regsvr32",
        "rundll32",
    ],
    "persistence": [
        "schtasks",
        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "CurrentVersion\\Run",
        "New-Service",
        "sc create",
        "Startup",
    ],
    "evasion": [
        "FromBase64String",
        "Convert.ToBase64String",
        "bypass",
        "AMSI",
        "hidden",
        "-w hidden",
        "-nop",
        "-noprofile",
        "ExecutionPolicy Bypass",
        "Set-MpPreference",
        "Add-MpPreference",
    ],
    "credential": [
        "Get-Credential",
        "mimikatz",
        "sekurlsa",
        "lsass",
        "Password",
        "net user",
        "net localgroup",
    ],
}

MAX_LINE_TYPICAL = 300


@register_parser
class ScriptParser:
    name = "script"
    kinds = {FileKind.SCRIPT}

    def parse(self, ctx: SampleContext) -> None:
        data = ctx.read()
        text = _decode(data)
        lowered = text.lower()

        hits: dict[str, list[str]] = {}
        for category, keywords in KEYWORDS.items():
            matched = [kw for kw in keywords if kw.lower() in lowered]
            if matched:
                hits[category] = matched

        lines = text.splitlines() or [""]
        long_lines = [ln for ln in lines if len(ln) > MAX_LINE_TYPICAL]
        alnum = sum(1 for ch in text if ch.isalnum())
        obfuscation = 0.0
        if text:
            obfuscation = round(1.0 - (alnum / len(text)), 3)

        ctx.parsed["script"] = {
            "language": _guess_language(data, text),
            "lines": len(lines),
            "max_line_length": max((len(ln) for ln in lines), default=0),
            "long_lines": len(long_lines),
            "entropy": round(shannon_entropy(data), 2),
            "printable_ratio": round(printable_ratio(data), 3),
            "obfuscation_ratio": obfuscation,
            "keywords": hits,
            "base64_blobs": base64_blobs(data, min_len=64, limit=5),
            "preview": text[:800],
        }


def _decode(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if data.count(b"\x00") > len(data) // 4:
        return data.decode("utf-16-le", "replace")
    return data.decode("utf-8", "replace")


def _guess_language(data: bytes, text: str) -> str:
    head = data[:200].lower()
    if head.startswith(b"#!"):
        first = head.split(b"\n", 1)[0]
        return first.decode("ascii", "ignore").strip("#! ").split()[0] if first else "script"
    if b"@echo off" in head or head.startswith(b"@"):
        return "batch"
    if "param(" in text.lower() or "$env:" in text or "write-host" in text.lower():
        return "powershell"
    if "createobject" in text.lower() or "wscript" in text.lower():
        return "vbscript"
    if "function(" in text.lower() or "var " in text.lower():
        return "javascript"
    return "script"

"""Indicator-of-compromise extraction, normalisation and defanging."""

from __future__ import annotations

import ipaddress
import re

from maltriage.models import IOC, IOCType

URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\]\)]{3,300}", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|info|biz|ru|cn|su|top|xyz|site|online|club|pw|cc|io|co|in|de|uk|"
    r"us|br|nl|fr|pl|kr|jp|tk|ml|ga|cf|gq|icu|shop|live|pro|link|click|download)\b",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[\w.+-]{2,64}@(?:[\w-]+\.)+[a-z]{2,24}\b", re.IGNORECASE)
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
REGISTRY_RE = re.compile(
    r"(?i)\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|"
    r"SOFTWARE\\\\?Microsoft\\\\?Windows\\\\?CurrentVersion\\\\?Run)\b[^\s\"'<>]{0,120}"
)

# Domains that show up in nearly every binary and add no signal.
BENIGN_DOMAINS = {
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "msdn.com",
    "w3.org",
    "adobe.com",
    "verisign.com",
    "digicert.com",
    "sectigo.com",
    "globalsign.com",
    "python.org",
    "pythonhosted.org",
    "openssl.org",
    "gnu.org",
    "schemas.xmlsoap.org",
    "purl.org",
    "xmlsoap.org",
    "mozilla.org",
    "google.com",
    "gstatic.com",
    "github.com",
    "githubusercontent.com",
    "nuget.org",
    "apache.org",
}

MAX_IOCS = 200


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _is_benign_domain(value: str) -> bool:
    value = value.lower().strip(".")
    return any(value == d or value.endswith("." + d) for d in BENIGN_DOMAINS)


def extract(texts: list[str], context: str = "strings") -> list[IOC]:
    """Pull indicators out of extracted strings, de-duplicated."""
    found: dict[tuple[str, str], IOC] = {}

    def add(ioc_type: IOCType, value: str) -> None:
        key = (ioc_type.value, value.lower())
        if key not in found and len(found) < MAX_IOCS:
            found[key] = IOC(type=ioc_type, value=value, context=context)

    for text in texts:
        for match in URL_RE.finditer(text):
            add(IOCType.URL, match.group())
        for match in EMAIL_RE.finditer(text):
            add(IOCType.EMAIL, match.group())
        for match in IPV4_RE.finditer(text):
            if _is_public_ip(match.group()):
                add(IOCType.IPV4, match.group())
        for match in DOMAIN_RE.finditer(text):
            value = match.group()
            if not _is_benign_domain(value):
                add(IOCType.DOMAIN, value)
        for match in BTC_RE.finditer(text):
            add(IOCType.BTC, match.group())
        for match in REGISTRY_RE.finditer(text):
            add(IOCType.REGISTRY, match.group()[:200])

    return list(found.values())


def defang(value: str) -> str:
    """Make an indicator safe to click-free copy/paste."""
    out = re.sub(r"(?i)^http://", "hxxp://", value)
    out = re.sub(r"(?i)^https://", "hxxps://", out)
    out = re.sub(r"(?i)^ftp://", "fxp://", out)
    out = out.replace("@", "[at]")
    return out.replace(".", "[.]")


def grouped(iocs: list[IOC]) -> dict[str, list[str]]:
    """Group indicator values by type for reporting."""
    grouped_out: dict[str, list[str]] = {}
    for ioc in iocs:
        grouped_out.setdefault(ioc.type.value, []).append(ioc.value)
    return grouped_out

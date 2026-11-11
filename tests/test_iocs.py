from __future__ import annotations

from maltriage.iocs import defang, extract, grouped
from maltriage.models import IOCType


def _types(iocs) -> set[str]:
    return {ioc.type.value for ioc in iocs}


def test_extracts_url_ip_and_domain():
    iocs = extract(["connect to http://evil-example.com/gate.php from 93.184.216.34 now"])
    types = _types(iocs)
    assert "url" in types
    assert "domain" in types
    assert "ipv4" in types


def test_private_ips_are_ignored():
    iocs = extract(["callback 192.168.1.10 and 127.0.0.1 and 10.0.0.5"])
    assert "ipv4" not in _types(iocs)


def test_benign_vendor_domains_are_filtered():
    iocs = extract(["https://schemas.microsoft.com/2004/xml"])
    domains = [ioc.value for ioc in iocs if ioc.type is IOCType.DOMAIN]
    assert not any("microsoft.com" in d for d in domains)


def test_bitcoin_wallet():
    iocs = extract(["send to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"])
    assert "btc" in _types(iocs)


def test_email_and_registry():
    iocs = extract(
        [
            "contact dropper@evil-example.org",
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        ]
    )
    types = _types(iocs)
    assert "email" in types
    assert "registry" in types


def test_deduplication():
    iocs = extract(["http://a.example.com/x", "http://a.example.com/x"])
    urls = [ioc for ioc in iocs if ioc.type is IOCType.URL]
    assert len(urls) == 1


def test_defang():
    assert defang("http://evil.com/a") == "hxxp://evil[.]com/a"
    assert defang("https://evil.com") == "hxxps://evil[.]com"
    assert defang("bad@evil.com") == "bad[at]evil[.]com"


def test_grouping():
    iocs = extract(["http://a.example.com/1", "http://b.example.com/2"])
    grouped_iocs = grouped(iocs)
    assert len(grouped_iocs["url"]) == 2

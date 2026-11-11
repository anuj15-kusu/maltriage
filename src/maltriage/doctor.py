"""Environment diagnostics for `maltriage doctor`.

Checks are read-only apart from a writability probe. API key values are never
rendered — only whether a key is present and how long it is.
"""

from __future__ import annotations

import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from maltriage import __version__
from maltriage.config import Settings

OK = "ok"
WARN = "warn"
FAIL = "fail"

# EICAR test file hash: safe, well known, and present in the VirusTotal corpus.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str


def run_checks(settings: Settings, *, check_api: bool = False) -> list[Check]:
    checks = [
        _python_check(),
        _package_check(),
        _mode_check(settings),
        _key_check("VT_API_KEY", settings.vt_api_key),
        _key_check("MB_AUTH_KEY", settings.mb_auth_key),
        _rules_check(settings),
        _cache_check(settings),
        _report_dir_check(settings),
    ]
    if check_api:
        checks.append(_api_check(settings))
    return checks


def _python_check() -> Check:
    info = sys.version_info
    version = f"{info.major}.{info.minor}.{info.micro}"
    if info < (3, 11):
        return Check("Python", FAIL, f"{version} — 3.11 or newer is required")
    if info >= (3, 13):
        return Check("Python", WARN, f"{version} — 3.11/3.12 have the best wheel coverage")
    return Check("Python", OK, version)


def _package_check() -> Check:
    return Check("maltriage", OK, __version__)


def _mode_check(settings: Settings) -> Check:
    mode = "offline (no external calls)" if settings.offline else "online"
    return Check("Mode", OK, f"{mode}, max file {settings.max_file_mb} MiB")


def _key_check(name: str, value: str | None) -> Check:
    if not value:
        return Check(name, WARN, "not set — enrichment disabled")
    return Check(name, OK, f"set ({len(value)} characters, value never displayed)")


def _rules_check(settings: Settings) -> Check:
    from maltriage.analyzers.yara_scan import load_ruleset, rule_files

    directory = Path(settings.rules_dir)
    if not directory.is_dir():
        return Check("YARA rules", WARN, f"no rules directory at {directory}")
    files = rule_files(directory)
    if not files:
        return Check("YARA rules", WARN, f"no .yar files under {directory}")
    _compiled, meta = load_ruleset(directory)
    if meta.get("error"):
        return Check("YARA rules", FAIL, f"{len(files)} file(s), compile error: {meta['error']}")
    namespaces = ", ".join(sorted(meta.get("namespaces", {})))
    return Check("YARA rules", OK, f"{len(files)} file(s) — {namespaces}")


def _cache_check(settings: Settings) -> Check:
    from maltriage.cache import Cache

    try:
        cache = Cache(settings.cache_path)
        stats = cache.stats()
        cache.close()
    except Exception as exc:
        return Check("Cache", FAIL, f"{settings.cache_path}: {exc}")
    if not stats.get("enabled"):
        return Check("Cache", WARN, "disabled")
    return Check("Cache", OK, f"{settings.cache_path} — {stats.get('scans', 0)} scan(s) stored")


def _report_dir_check(settings: Settings) -> Check:
    directory = Path(settings.report_dir)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".doctor-", delete=True):
            pass
    except Exception as exc:
        return Check("Report directory", FAIL, f"{directory}: {exc}")
    return Check("Report directory", OK, str(directory.resolve()))


def _api_check(settings: Settings) -> Check:
    from maltriage.cache import Cache
    from maltriage.enrichment.virustotal import VirusTotal
    from maltriage.models import FileKind, SampleContext

    if not settings.vt_api_key:
        return Check("VirusTotal API", FAIL, "VT_API_KEY is not set")
    if settings.offline:
        return Check("VirusTotal API", FAIL, "offline mode is enabled")

    cache = Cache(settings.cache_path)
    try:
        ctx = SampleContext(
            path=Path("<doctor>"),
            size=0,
            kind=FileKind.UNKNOWN,
            config=settings,
            hashes={"sha256": EICAR_SHA256},
        )
        result, _findings = VirusTotal().enrich(ctx, cache, settings)
    finally:
        cache.close()

    if result is None:
        return Check("VirusTotal API", FAIL, "no response")
    if result.status == "ok":
        return Check("VirusTotal API", OK, result.summary)
    if result.status in {"not_found", "quota"}:
        return Check("VirusTotal API", WARN, result.summary)
    return Check("VirusTotal API", FAIL, result.summary)

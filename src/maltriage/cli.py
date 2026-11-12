"""maltriage command line interface."""

from __future__ import annotations

import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from maltriage import __version__, memory
from maltriage.config import Settings, get_settings
from maltriage.models import Report
from maltriage.pipeline import Pipeline, ScanOptions
from maltriage.reporters import available, get_renderer
from maltriage.safety import SafetyError

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Static malware triage. The sample is never executed.",
)
rules_app = typer.Typer(no_args_is_help=True, help="YARA rule utilities.")
db_app = typer.Typer(no_args_is_help=True, help="Inspect the local scan database.")
vt_app = typer.Typer(no_args_is_help=True, help="VirusTotal helpers.")
app.add_typer(rules_app, name="rules")
app.add_typer(db_app, name="db")
app.add_typer(vt_app, name="vt")

console = Console()

BAND_STYLE = {
    "clean": ("green", "CLEAN / LIKELY BENIGN"),
    "suspicious": ("yellow", "SUSPICIOUS"),
    "likely_malicious": ("red", "LIKELY MALICIOUS"),
    "malicious": ("bold red", "MALICIOUS"),
}
SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}
BAND_RANK = {"clean": 0, "suspicious": 1, "likely_malicious": 2, "malicious": 3}
MAX_AUTO_JOBS = 8
# Fallback until a real batch has been measured: the sample plus parser copies.
WORKER_FOOTPRINT_FACTOR = 2.5


def _auto_jobs() -> int:
    """Cores this process may use, capped so a default batch stays modest."""
    try:
        cores = len(os.sched_getaffinity(0))  # honours affinity and cgroup limits
    except AttributeError:
        cores = os.cpu_count() or 1
    return max(1, min(cores, MAX_AUTO_JOBS))


AUTO_JOBS = _auto_jobs()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"maltriage {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
    """Static malware triage."""


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="File to triage."),
    formats: str = typer.Option(
        "json,html", "--format", "-f", help=f"Report formats: {', '.join(available())}"
    ),
    out: Path = typer.Option(Path("out"), "--out", "-o", help="Report output directory."),
    offline: bool = typer.Option(False, "--offline", help="Never call external APIs."),
    no_enrich: bool = typer.Option(False, "--no-enrich", help="Skip enrichment entirely."),
    submit: bool = typer.Option(
        False, "--submit", help="Allow uploading the sample to VirusTotal."
    ),
    refresh: bool = typer.Option(False, "--refresh", help="Ignore the cached VirusTotal result."),
    no_defang: bool = typer.Option(False, "--no-defang", help="Keep indicators clickable."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Do not write to the local database."),
    fail_on: str = typer.Option(
        "never",
        "--fail-on",
        help="Exit non-zero at this band: never|suspicious|likely_malicious|malicious",
    ),
) -> None:
    """Triage a single file."""
    settings = get_settings()
    if offline:
        settings.offline = True
    if submit:
        settings.submit = True

    from maltriage.cache import Cache

    cache = Cache(settings.cache_path, enabled=not no_cache)
    if cache.reason:
        console.print(f"[yellow]cache disabled:[/yellow] {cache.reason}")
    pipeline = Pipeline(settings=settings, cache=cache)
    try:
        report = pipeline.scan(
            path, ScanOptions(enrich=not no_enrich, submit=submit, refresh=refresh)
        )
    except SafetyError as exc:
        console.print(f"[red]refused:[/red] {exc}")
        raise typer.Exit(code=3) from exc
    finally:
        pipeline.close()

    paths = _write_reports(report, formats, out, defang=not no_defang)
    _print_report(report, paths)

    threshold = BAND_RANK.get(fail_on, 99)
    if BAND_RANK.get(report.verdict.band, 0) >= threshold and fail_on != "never":
        raise typer.Exit(code=2)


@app.command()
def batch(
    ctx: typer.Context,
    directory: Path = typer.Argument(
        ..., exists=True, file_okay=False, help="Directory to triage."
    ),
    formats: str = typer.Option("json", "--format", "-f", help="Report formats."),
    out: Path = typer.Option(Path("out"), "--out", "-o", help="Report output directory."),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Walk sub-directories."),
    jobs: int = typer.Option(
        AUTO_JOBS,
        "--jobs",
        "-j",
        min=1,
        help=(
            "Worker processes to triage with (each holds one sample in memory). "
            f"Defaults to min(cores, {MAX_AUTO_JOBS}); refused when it cannot fit in RAM."
        ),
    ),
    offline: bool = typer.Option(False, "--offline", help="Never call external APIs."),
) -> None:
    """Triage every file in a directory."""
    settings = get_settings()
    if offline:
        settings.offline = True

    candidates = sorted(
        p
        for p in (directory.rglob("*") if recursive else directory.iterdir())
        if p.is_file() and not p.name.startswith(".")
    )
    if not candidates:
        console.print("[yellow]no files found[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title=f"Batch triage: {directory}", show_lines=False)
    table.add_column("File", overflow="fold")
    table.add_column("Score", justify="right")
    table.add_column("Verdict")
    table.add_column("Top finding", overflow="fold")

    options = ScanOptions(enrich=not settings.offline)
    workers = _worker_count(ctx, jobs, candidates, settings)
    if workers > 1:
        console.print(f"[dim]scanning with {workers} worker(s)[/dim]")

    counts: dict[str, int] = {}
    if workers == 1:
        pipeline = Pipeline(settings=settings)
        try:
            outcomes = [_scan_one(pipeline, item, options) for item in candidates]
        finally:
            pipeline.close()
    else:
        outcomes = _scan_many(candidates, options, workers, settings)
        _record_measurement(settings, outcomes)

    for outcome in outcomes:
        if outcome.report is None:
            table.add_row(
                outcome.item.name, "-", "[dim]skipped[/dim]", outcome.error or "not scanned"
            )
            continue
        report = outcome.report
        _write_reports(report, formats, out, defang=settings.defang)
        counts[report.verdict.band] = counts.get(report.verdict.band, 0) + 1
        style, label = BAND_STYLE.get(report.verdict.band, ("white", report.verdict.band))
        top = report.findings[0].title if report.findings else "-"
        table.add_row(
            outcome.item.name, str(report.verdict.score), f"[{style}]{label}[/{style}]", top
        )

    console.print(table)
    summary = ", ".join(f"{band}: {count}" for band, count in sorted(counts.items()))
    console.print(f"[bold]{len(candidates)} file(s)[/bold] — {summary or 'nothing scored'}")
    console.print(f"Reports written to [cyan]{out}[/cyan]")


@rules_app.command("lint")
def rules_lint(
    path: Path = typer.Argument(Path("rules"), help="Rules directory."),
) -> None:
    """Compile every YARA rule file and report syntax errors."""
    import yara

    from maltriage.analyzers.yara_scan import rule_files

    files = rule_files(path)
    if not files:
        console.print(f"[yellow]no .yar files under {path}[/yellow]")
        raise typer.Exit(code=1)

    table = Table(title=f"YARA lint: {path}")
    table.add_column("Rule file", overflow="fold")
    table.add_column("Status")
    failures = 0
    for file in files:
        try:
            yara.compile(filepath=str(file))
            table.add_row(str(file.relative_to(path)), "[green]ok[/green]")
        except Exception as exc:
            failures += 1
            table.add_row(str(file.relative_to(path)), f"[red]{exc}[/red]")
    console.print(table)
    raise typer.Exit(code=1 if failures else 0)


@db_app.command("stats")
def db_stats() -> None:
    """Show counts from the local scan database."""
    from maltriage.cache import Cache

    settings = get_settings()
    cache = Cache(settings.cache_path)
    stats = cache.stats()
    cache.close()

    if not stats.get("enabled"):
        console.print("[yellow]cache disabled[/yellow]")
        return

    table = Table(title=f"Database: {settings.cache_path}")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for key in ("samples", "scans", "findings", "iocs", "vt_cache"):
        table.add_row(key, str(stats.get(key, 0)))
    console.print(table)

    if stats.get("verdicts"):
        verdicts = Table(title="Verdicts")
        verdicts.add_column("Band")
        verdicts.add_column("Count", justify="right")
        for band, count in stats["verdicts"].items():
            verdicts.add_row(band, str(count))
        console.print(verdicts)


@vt_app.command("check")
def vt_check(
    target: str = typer.Argument(..., help="SHA-256 hash or path to a file."),
    refresh: bool = typer.Option(False, "--refresh", help="Ignore the cached result."),
) -> None:
    """Verify VT_API_KEY with a single hash lookup."""
    from maltriage.cache import Cache
    from maltriage.enrichment.virustotal import VirusTotal
    from maltriage.identity import resolve_hash
    from maltriage.models import FileKind, SampleContext

    settings = get_settings()
    if not settings.vt_api_key:
        console.print("[red]VT_API_KEY is not set.[/red] Add it to .env and retry.")
        raise typer.Exit(code=3)

    try:
        digest = resolve_hash(target)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=4) from exc

    cache = Cache(settings.cache_path)
    try:
        if refresh:
            cache.drop_vt(digest)
        ctx = SampleContext(
            path=Path(target),
            size=0,
            kind=FileKind.UNKNOWN,
            config=settings,
            hashes={"sha256": digest},
        )
        result, findings = VirusTotal().enrich(ctx, cache, settings)
    finally:
        cache.close()

    if result is None:
        console.print("[red]VirusTotal returned no result[/red]")
        raise typer.Exit(code=2)

    table = Table(title="VirusTotal hash lookup", show_header=False)
    table.add_column("Field")
    table.add_column("Value", overflow="fold")
    table.add_row("sha256", digest)
    table.add_row("status", result.status)
    table.add_row("summary", result.summary)
    if result.link:
        table.add_row("link", result.link)
    console.print(table)

    for finding in findings:
        console.print(f"[dim]signal:[/dim] {finding.signal} — {finding.title}")

    if result.status != "ok":
        raise typer.Exit(code=2)


@app.command()
def doctor(
    check_api: bool = typer.Option(
        False, "--check-api", help="Spend one VirusTotal request to validate the key."
    ),
) -> None:
    """Check Python, configuration, YARA rules, cache and API keys."""
    from maltriage.doctor import FAIL, WARN, run_checks

    settings = get_settings()
    checks = run_checks(settings, check_api=check_api)

    style = {"ok": "green", "warn": "yellow", "fail": "red"}
    table = Table(title="maltriage doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail", overflow="fold")
    for check in checks:
        table.add_row(
            check.name, f"[{style.get(check.status, 'white')}]{check.status}[/]", check.detail
        )
    console.print(table)

    failures = [c for c in checks if c.status == FAIL]
    warnings = [c for c in checks if c.status == WARN]
    if failures:
        console.print(f"[red]{len(failures)} failing check(s)[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]all checks passed[/green] ({len(warnings)} warning(s))")


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"maltriage {__version__}")


# --- helpers -----------------------------------------------------------
def _write_reports(report: Report, formats: str, out: Path, *, defang: bool) -> list[Path]:
    selected = [name.strip() for name in formats.split(",") if name.strip()]
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.print(f"[red]cannot use report directory {out}: {exc.strerror or exc}[/red]")
        raise typer.Exit(code=2) from exc
    stem = f"{report.file.sha256[:12]}_{Path(report.file.name).stem or 'sample'}"
    paths: list[Path] = []
    for name in selected:
        try:
            renderer = get_renderer(name)
        except KeyError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=4) from exc
        target = out / f"{stem}{renderer.suffix}"
        try:
            target.write_text(renderer.render(report, defang=defang), encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]cannot write {target}: {exc.strerror or exc}[/red]")
            raise typer.Exit(code=2) from exc
        paths.append(target)
    return paths


def _print_report(report: Report, paths: list[Path]) -> None:
    style, label = BAND_STYLE.get(report.verdict.band, ("white", report.verdict.band))
    panel = Panel(
        f"[{style}]{label}[/{style}]  score [bold]{report.verdict.score}/100[/bold]"
        f"  (confidence {report.verdict.confidence})",
        title=f"{report.file.name} — {report.file.kind.value}",
        subtitle=f"sha256 {report.file.sha256[:32]}…",
        border_style=style,
    )
    console.print(panel)

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Sev", width=8)
    table.add_column("Analyzer", width=18)
    table.add_column("Finding", overflow="fold")
    for finding in report.findings[:20]:
        table.add_row(
            f"[{SEVERITY_STYLE.get(finding.severity.value, 'white')}]{finding.severity.value}[/]",
            finding.analyzer,
            finding.title,
        )
    if report.findings:
        console.print(table)
    else:
        console.print("[dim]no findings[/dim]")

    if report.verdict.breakdown:
        breakdown = Table(title="Score breakdown")
        breakdown.add_column("Signal")
        breakdown.add_column("Points", justify="right")
        for item in report.verdict.breakdown:
            breakdown.add_row(item.label, f"{item.applied_points:+d}")
        console.print(breakdown)

    if report.enrichment:
        for result in report.enrichment:
            console.print(f"[dim]{result.provider}:[/dim] {result.status} — {result.summary}")

    if report.iocs:
        console.print(f"[bold]{len(report.iocs)}[/bold] indicator(s) extracted")

    for error in report.errors:
        console.print(f"[yellow]note:[/yellow] {error}")

    for path in paths:
        console.print(f"report: [cyan]{path}[/cyan]")


@dataclass
class _Outcome:
    """One file's result, kept so the table can be printed in input order."""

    item: Path
    report: Report | None = None
    error: str | None = None
    peak_bytes: int | None = None
    baseline_bytes: int | None = None


_WORKER: Pipeline | None = None
_WORKER_BASELINE: int | None = None


def _scan_one(pipeline: Pipeline, item: Path, options: ScanOptions) -> _Outcome:
    try:
        return _Outcome(item=item, report=pipeline.scan(item, options))
    except SafetyError as exc:
        return _Outcome(item=item, error=str(exc))


def _init_worker(payload: dict, vt_interval: float) -> None:
    """Give each worker process its own pipeline and SQLite connection."""
    global _WORKER, _WORKER_BASELINE
    from maltriage.cache import Cache
    from maltriage.enrichment import virustotal as vt_module
    from maltriage.enrichment.ratelimit import MinInterval

    worker_settings = Settings(**payload)
    # Pacing is per process, so widen it until the aggregate still sits inside the
    # tier's 4 requests per minute.
    vt_module._pacer = MinInterval(max(worker_settings.vt_min_interval, vt_interval))
    _WORKER = Pipeline(settings=worker_settings, cache=Cache(worker_settings.cache_path))
    _WORKER_BASELINE = memory.peak_rss_bytes()


def _scan_worker(task: tuple[str, ScanOptions]) -> _Outcome:
    path_value, options = task
    pipeline = _WORKER
    assert pipeline is not None, "worker pool started without its pipeline"
    outcome = _scan_one(pipeline, Path(path_value), options)
    outcome.peak_bytes = memory.peak_rss_bytes()
    outcome.baseline_bytes = _WORKER_BASELINE
    return outcome


def _available_memory_mb() -> int | None:
    """Free memory in MiB, or None when the platform has no cheap probe."""
    available = memory.available_bytes()
    return None if available is None else available // (1024 * 1024)


def _worker_footprint_mb(settings: Settings, sample_bytes: int) -> tuple[int, str]:
    """Per-worker memory in MiB, and whether it was measured or estimated."""
    measurement = memory.load(settings.cache_path)
    if measurement is not None:
        return measurement.expected_bytes(sample_bytes) // (1024 * 1024), "measured"
    return max(64, int(settings.max_file_mb * WORKER_FOOTPRINT_FACTOR)), "estimated"


def _memory_ceiling(
    settings: Settings, sample_bytes: int
) -> tuple[int | None, int, int | None, str]:
    """(workers that fit in 80% of free memory, per-worker MiB, free MiB, source)."""
    footprint, source = _worker_footprint_mb(settings, sample_bytes)
    available = _available_memory_mb()
    if available is None:
        return None, footprint, None, source
    return max(1, int(available * 0.8) // footprint), footprint, available, source


def _worker_count(ctx: typer.Context, jobs: int, candidates: list[Path], settings: Settings) -> int:
    """Resolve --jobs to an effective worker count, bounded by RAM and file count."""
    sample_bytes = max((item.stat().st_size for item in candidates), default=0)
    requested = max(1, jobs)
    ceiling, footprint, available, source = _memory_ceiling(settings, sample_bytes)
    if ceiling is not None and requested > ceiling:
        given = ctx.get_parameter_source("jobs")
        if getattr(given, "name", "") == "COMMANDLINE":
            console.print(
                f"[red]--jobs {requested} would not fit:[/red] about {footprint} MiB per "
                f"worker ({source}) and {available} MiB free. Use --jobs {ceiling} or "
                "lower MALTRIAGE_MAX_FILE_MB."
            )
            raise typer.Exit(code=2)
        console.print(f"[dim]--jobs {requested} limited to {ceiling} by free memory[/dim]")
        requested = ceiling

    # Forking a worker costs ~0.4 s of imports and YARA compilation, so a batch
    # needs at least two files per worker before parallelism pays for itself.
    return max(1, min(requested, len(candidates) // 2))


def _record_measurement(settings: Settings, outcomes: list[_Outcome]) -> None:
    """Store what the workers really used, so the next run does not have to guess."""
    peaks = [outcome.peak_bytes for outcome in outcomes if outcome.peak_bytes]
    if not peaks:
        return
    baselines = [outcome.baseline_bytes for outcome in outcomes if outcome.baseline_bytes]
    sample_bytes = max((outcome.item.stat().st_size for outcome in outcomes), default=0)
    measurement = memory.build(
        baseline_bytes=min(baselines) if baselines else 0,
        peak_bytes=max(peaks),
        sample_bytes=sample_bytes,
        workers=len(peaks),
        previous=memory.load(settings.cache_path),
    )
    if memory.save(settings.cache_path, measurement) is not None:
        console.print(
            f"[dim]measured {measurement.peak_bytes // (1024 * 1024)} MiB peak per worker "
            f"(largest sample {sample_bytes // 1024} KiB); future --jobs sizing uses it[/dim]"
        )


def _process_context() -> multiprocessing.context.BaseContext | None:
    """A fork context where the platform has one; the caller falls back to threads."""
    try:
        return multiprocessing.get_context("fork")
    except ValueError:
        return None


def _scan_many(
    candidates: list[Path], options: ScanOptions, workers: int, settings: Settings
) -> list[_Outcome]:
    """Scan files in parallel, returning the outcomes in the input order.

    Analysis is CPU bound, so threads buy nothing (measured: 0.99x on 24 files)
    while forked processes scale to the core count (measured: 7.8 s -> 3.5 s with
    four workers on the same set).
    """
    context = _process_context()
    if context is None:
        return _scan_threads(candidates, options, workers, settings)

    aggregate_interval = settings.vt_min_interval * workers
    tasks = [(str(item), options) for item in candidates]
    with ProcessPoolExecutor(
        max_workers=workers,
        mp_context=context,
        initializer=_init_worker,
        initargs=(settings.model_dump(), aggregate_interval),
    ) as pool:
        return list(pool.map(_scan_worker, tasks, chunksize=1))


def _scan_threads(
    candidates: list[Path], options: ScanOptions, workers: int, settings: Settings
) -> list[_Outcome]:
    """Fallback for platforms without fork; still overlaps enrichment waits."""
    pipeline = Pipeline(settings=settings)
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(lambda item: _scan_one(pipeline, item, options), candidates))
    finally:
        pipeline.close()


if __name__ == "__main__":
    app()

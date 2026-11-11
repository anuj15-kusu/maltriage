"""maltriage command line interface."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from maltriage import __version__
from maltriage.config import get_settings
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
    directory: Path = typer.Argument(
        ..., exists=True, file_okay=False, help="Directory to triage."
    ),
    formats: str = typer.Option("json", "--format", "-f", help="Report formats."),
    out: Path = typer.Option(Path("out"), "--out", "-o", help="Report output directory."),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Walk sub-directories."),
    offline: bool = typer.Option(False, "--offline", help="Never call external APIs."),
) -> None:
    """Triage every file in a directory."""
    settings = get_settings()
    if offline:
        settings.offline = True

    pipeline = Pipeline(settings=settings)
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

    counts: dict[str, int] = {}
    try:
        for item in candidates:
            try:
                report = pipeline.scan(item, ScanOptions(enrich=not settings.offline))
            except SafetyError as exc:
                table.add_row(item.name, "-", "[dim]skipped[/dim]", str(exc))
                continue
            _write_reports(report, formats, out, defang=settings.defang)
            counts[report.verdict.band] = counts.get(report.verdict.band, 0) + 1
            style, label = BAND_STYLE.get(report.verdict.band, ("white", report.verdict.band))
            top = report.findings[0].title if report.findings else "-"
            table.add_row(item.name, str(report.verdict.score), f"[{style}]{label}[/{style}]", top)
    finally:
        pipeline.close()

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
    out.mkdir(parents=True, exist_ok=True)
    stem = f"{report.file.sha256[:12]}_{Path(report.file.name).stem or 'sample'}"
    paths: list[Path] = []
    for name in selected:
        try:
            renderer = get_renderer(name)
        except KeyError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=4) from exc
        target = out / f"{stem}{renderer.suffix}"
        target.write_text(renderer.render(report, defang=defang), encoding="utf-8")
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


if __name__ == "__main__":
    app()

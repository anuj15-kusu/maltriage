# maltriage architecture

Static malware triage. **The sample is never executed**: every conclusion comes from
the bytes on disk plus optional reputation lookups.

## Pipeline

```
CLI (typer) -> Pipeline
  1. intake      safety.check_file: exists, not empty, size cap
  2. identity    md5/sha1/sha256 + ssdeep, SQLite dedupe record
  3. filetype    magic bytes -> FileKind (PE, ELF, OLE, OOXML, PDF, APK, archive, script)
  4. parse       one parser per kind, fills ctx.parsed["pe"|"office"|...]
  5. strings     ASCII + UTF-16LE extraction, IOC regexes
  6. analyzers   thread pool, per-analyzer timeout, failures isolated
  7. enrichment  VirusTotal / MalwareBazaar, cached and paced, optional
  8. scoring     weighted signals, per-category caps, 0-100 + band
  9. reporters   JSON (canonical), HTML, Markdown, STIX 2.1
```

Everything between stages travels in `SampleContext`; analyzers are stateless and only
read it, so a new check is one module with `@register_analyzer`.

## Layout

```
src/maltriage/
  cli.py            scan | batch | rules lint | db stats | version
  config.py         pydantic-settings, .env, limits
  models.py         Finding, IOC, Verdict, Report, SampleContext
  safety.py         size/empty checks, zip-bomb + path traversal guards
  identity.py       hashes + fuzzy hash
  filetype.py       magic detection (pure python)
  strings.py        string extraction, entropy, base64 blobs
  iocs.py           indicator regexes, defang
  cache.py          SQLite: samples, scans, findings, iocs, vt_cache
  registry.py       plugin auto-discovery
  scoring.py        weights.yaml -> explainable score
  pipeline.py       orchestrator
  parsers/          pe, elf, office, pdf, script, archive
  analyzers/        entropy, packer, imports, macro, pdf_active, script_behavior,
                    embedded, signature, yara_scan, indicators, type_mismatch
  enrichment/       virustotal, malwarebazaar, ratelimit
  reporters/        json, html, markdown, stix
  data/             weights.yaml, suspicious_apis.yaml, packers.yaml
rules/              malware/, suspicious/, packers/, local/ (gitignored)
```

## Scoring

Positive points are summed per signal (each counted once) and capped per category
(`enrichment` 40, `yara` 30, `static` 60). Negative signals (known-good vendor,
clean VirusTotal) subtract without a cap. The total is clamped to 0-100 and mapped to
a band: `clean` < 20, `suspicious` < 50, `likely_malicious` < 80, `malicious` >= 80.
Every point is reported in `verdict.breakdown`, so a verdict can always be explained.

## Enrichment limits

The free VirusTotal tier allows 4 requests/minute and 500/day. The client paces
requests at 15s, caches every response for 7 days in SQLite, honours `Retry-After`
on 429 and never uploads a sample unless `--submit` is passed.

## Safety

- Samples are opened read-only and never executed, unpacked or macro-run.
- Archives are inspected through the central directory only: depth, member count,
  declared size and compression ratio are bounded before anything is read.
- Member paths that would escape the extraction root, and symlink members, are rejected.
- Parser exceptions are caught per sample; malformed input degrades to a note in the report.
- `.env`, `rules/local/` and `samples/` are gitignored. Never commit live malware.

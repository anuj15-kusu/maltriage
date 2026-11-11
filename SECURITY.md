# Security policy

`maltriage` reads hostile files, so its own safety properties matter as much as its
verdicts. This document states what the tool does and does not do, which parts are
trusted, and how to report a problem.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |
| anything older | no |

## Threat model

The tool is a **static** triage pipeline. A sample is untrusted input that is only ever
parsed from bytes in memory.

### Assets in scope

1. **The analyst's host** — the machine running `maltriage`.
2. **The analyst's credentials** — `VT_API_KEY` and `MB_AUTH_KEY`.
3. **The sample set** — samples must not leak to a third party without a decision.
4. **The reports** — they contain real IOCs and are shared with other people and tools.

### Trust boundaries

| Component | Trust | Notes |
| --- | --- | --- |
| Sample bytes | **untrusted** | Everything a parser sees |
| Parsers (`pefile`, `oletools`, `pikepdf`, `pyelftools`, `filetype`, `zipfile`, `tarfile`) | **untrusted input, trusted code** | The main attack surface |
| YARA rules in `rules/local/` | **semi-trusted** | You supply them; they are data, but a pathological rule can burn CPU |
| VirusTotal / MalwareBazaar responses | **semi-trusted** | Remote data rendered into reports; treated as text, sanitised on output |
| `report.json` / `report.html` / `report.stix.json` | **untrusted output** | Contains attacker-controlled strings (file names, strings, IOCs) |
| `.env` | **secret** | Never logged, never rendered, never inside the container image |

### Threats this project defends against

- **Code execution through a malformed file.** Parsers never hand a sample to the OS.
  See the guarantee below.
- **Decompression bombs.** Zip metadata is inspected through limits on member count,
  uncompressed size and compression ratio; nothing is extracted.
- **Path traversal.** Archive member names are validated (`safe_member_name`) and are
  never used as filesystem paths, because nothing is extracted to disk.
- **Resource exhaustion.** File size, archive limits and an analyzer deadline are
  enforced; see the defaults below.
- **Accidental upload.** A hash lookup is the default; a sample reaches VirusTotal only
  with an explicit `--submit`.
- **Credential leakage.** Keys are read from the environment or `.env`, masked in
  `doctor`, and excluded from every report surface and the SQLite cache (asserted by
  `tests/test_key_hygiene.py`). `tools/secret_guard.py` plus the pre-commit hook stop a
  key from being committed; the key never enters the container image
  (`.dockerignore` excludes `.env`).
- **Report injection.** IOCs are defanged in every renderer, so a URL or domain in a
  report cannot be clicked straight into the attacker's infrastructure.

### Explicitly out of scope

- **Detection coverage.** This is a heuristic static triage tool. It does not emulate,
  unpack, decrypt or deobfuscate, so packed or novel samples can score low. A low score
  is not a safety statement.
- **A hostile analyst.** Anyone who can run commands as you already owns your account.
- **Third-party parser memory-safety bugs.** Python bindings in `pefile`, `pikepdf`,
  `yara-python` and friends are C extensions; a memory-safety defect there is upstream,
  which is why the container exists.
- **Network attackers.** TLS to the enrichment providers is the transport's job.
- **The truthfulness of reputation data.** VirusTotal verdicts are reported, not endorsed.
- **Samples run outside this tool.** Opening a sample in a debugger or a sandbox is your
  own containment decision.

## The never-execute guarantee

The sample is treated as bytes. It is hashed, typed, parsed, scanned, scored and
reported — **never run, loaded, imported or unpacked**.

Concretely:

- **No process is spawned for a sample.** `src/` contains no `subprocess`, `os.system`,
  `os.popen`, `ctypes`, `eval` or `exec` call. Verify it yourself:

  ```bash
  grep -rnE '\b(eval|exec)\(|os\.system|os\.popen|subprocess|ctypes' src/
  ```

  The command produces no output. (`detect_autoexec` in `parsers/office.py` is an
  oletools call that *reads* an autoexec macro, not an `exec`.)
- **No sample is imported or unpickled.** No `pickle`, `marshal` or `runpy` in `src/`.
  `importlib` appears only in `registry.py`, which imports this project's own parser and
  analyzer packages from fixed names so their decorators register — never a name taken
  from a sample.
- **Archives are never extracted.** `parsers/archive.py` reads the central directory
  (zip) or member table (tar) and reports names, sizes and compression ratio. Member
  bytes are not written to disk, so there is no traversal and no unpacking stage.
- **Office macros are read, not run.** OLE/OOXML parts are parsed as containers; VBA is
  extracted as text for keyword analysis. No VBA interpreter is involved.
- **PDF active content is inspected, not executed.** Objects and their names are
  inspected with `pikepdf`; no JavaScript engine exists in this tool.
- **PE/ELF files are parsed, not loaded.** Headers, sections, imports and resources are
  read with `pefile` / `pyelftools`. Nothing is mapped or executed.
- **Enrichment is hash-only.** VirusTotal is queried by SHA-256; MalwareBazaar returns
  metadata for a known hash. `--submit` is the only path that sends a sample, and it is
  off by default (`MALTRIAGE_SUBMIT=false`).

**What this guarantee does not mean.** It is a property of the code, not an OS sandbox.
A memory-safety defect inside a third-party parser could still hurt the process. That is
exactly why the container recipe exists: unprivileged uid, read-only root filesystem, no
capabilities, no network, bounded memory and PIDs.

## Defaults and how to tighten them

| Control | Default | Setting |
| --- | --- | --- |
| Maximum input size | 256 MiB | `MALTRIAGE_MAX_FILE_MB` |
| Archive members inspected | 200 | `MALTRIAGE_MAX_ARCHIVE_FILES` |
| Archive uncompressed budget | 200 MiB | `MALTRIAGE_MAX_ARCHIVE_MB` |
| Compression ratio ceiling | 100:1 | `MALTRIAGE_MAX_ARCHIVE_RATIO` |
| Nested archive depth | 2 | `MALTRIAGE_MAX_ARCHIVE_DEPTH` |
| Analyzer deadline | 60 s (pool waits 2×) | `MALTRIAGE_ANALYZER_TIMEOUT` |
| External calls | enabled | `MALTRIAGE_OFFLINE=true` disables all of them |
| Sample upload | disabled | `MALTRIAGE_SUBMIT` / `--submit` |

Hardening checklist:

- Run inside the container for untrusted samples (`docker compose run --rm triage`).
- Use `--offline` when a sample must not be attributed to your API key.
- Keep `rules/local/` under review; a rule is code-adjacent data you chose to trust.
- Treat generated reports as sensitive: they name the IOCs you are investigating.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

1. Use the repository's **Security → Report a vulnerability** (GitHub private security
   advisory) so the report, the discussion and the fix stay private until a release
   exists.
2. Include the version (`maltriage version`), the command line, a minimal reproducer if
   you can share one safely, and the impact you believe it has.
3. **Never attach live malware.** A crafted, harmless file that triggers the same parser
   path is enough; describe the sample family in text instead.
4. Do not include real API keys. Redact them.

You will get an acknowledgement as soon as the report is seen, then an assessment of
severity and scope. Please allow time for a fix and a release before any public write-up;
credit is given in the advisory unless you ask otherwise.

If the problem is in a third-party parser rather than in this code, it will be reported
upstream and tracked here so that the pinned version can be raised.

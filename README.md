# maltriage

Static malware triage tool. The sample is **never executed** — every conclusion comes
from the bytes on disk plus optional reputation lookups.

## Features

- Hashing + fuzzy hashing and a local dedupe cache (SQLite)
- File type identification (PE, ELF, OLE/OOXML, PDF, APK, archive, script)
- Strings, entropy, packer/protector detection, suspicious import combinations
- Office macro (VBA), DDE and remote-template analysis; PDF active content
- YARA scanning with local rule packs (`rules/malware`, `rules/suspicious`, `rules/packers`)
- Optional VirusTotal / MalwareBazaar enrichment — cached, rate limited, offline capable
- Explainable 0-100 score with a verdict band; every point names its signal
- Reports: JSON (canonical), HTML, Markdown, STIX 2.1

## Setup

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # Windows PowerShell
python -m pip install -e ".[dev]"
maltriage --version
```

Requires Python 3.11 or 3.12.

## Usage

```bash
maltriage scan suspicious.exe                       # triage one file
maltriage scan invoice.pdf -f json,html,markdown -o out
maltriage scan sample.dll --offline                 # no external API calls
maltriage batch ./inbox -r --jobs 4                 # triage a directory in parallel
maltriage rules lint rules                          # compile-check YARA rules
maltriage db stats                                  # local scan history
maltriage doctor                                    # environment + config check
maltriage doctor --check-api                        # also validate VT_API_KEY
```

`--fail-on suspicious` (or `likely_malicious` / `malicious`) makes the command exit 2,
which is what you want in CI or a cron job.

`--jobs N` triages N files at once using forked worker processes (one pipeline and one
SQLite connection each). Threads were measured first and bought nothing, because the
analysis is CPU bound; processes cut a 24-file, 5 MB batch from 7.8 s to 3.5 s on four
workers. Each worker holds one sample in memory, so keep the count modest relative to
`MALTRIAGE_MAX_FILE_MB`. VirusTotal pacing is per process, so the limiter is widened by
the worker count to keep the aggregate inside the free tier's 4 requests per minute. On a
platform without `fork`, the pool falls back to threads.

## API keys

Copy `.env.example` to `.env` and fill in the keys. `.env` is gitignored — never commit it.

```bash
VT_API_KEY=...        # VirusTotal API v3, free tier: 4 requests/minute, 500/day
MB_AUTH_KEY=...       # optional, MalwareBazaar (abuse.ch)
```

Verify the key with a single lookup before scanning anything:

```bash
maltriage vt check <sha256-or-file>
```

The tool only ever looks up a hash. It uploads a sample to VirusTotal **only** when you
pass `--submit`, and every response is cached for 7 days, so repeat scans cost no quota.

### Where `.env` is read from

`.env` is resolved against the **project root**, not the directory you happen to run
the command from, so `maltriage` behaves the same from any folder:

1. `MALTRIAGE_ENV_FILE=/path/to/file` — load exactly this file, skip the search
2. `MALTRIAGE_PROJECT_ROOT=/path/to/project` — treat this as the project root
3. otherwise the project root is found by walking up from the installed package and
   then from the current directory, looking for this project's `pyproject.toml`

The project root's `.env` wins over a `.env` in the working directory, and OS
environment variables win over both. `maltriage doctor` prints the file it loaded.

## Isolated container

Parsers are the only attack surface in this tool, so the container exists to keep
that work away from the host: unprivileged user, read-only root filesystem, no
capabilities, no network, bounded memory and PIDs.

```bash
docker build -t maltriage:latest .
mkdir -p samples out
cp /path/to/suspicious.exe samples/

docker compose run --rm triage                       # batch ./samples, offline
docker compose run --rm triage scan /samples/x.exe -o /work/out -f json,html
```

Without compose, the same guarantees by hand:

```bash
docker run --rm \
  --network none --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 1g -u 10001:10001 \
  -v "$PWD/samples:/samples:ro" -v "$PWD/out:/work/out" \
  maltriage:latest scan /samples/sample.exe -o /work/out
```

Notes:

- Samples mount read-only at `/samples`; only `out/` and the cache volume are writable.
- Enrichment needs egress: set `network_mode: bridge` and `env_file: [.env]` in the
  compose file, or pass `--env-file .env` to `docker run`. `.env` is in
  `.dockerignore`, so a key never ends up inside the image.
- `--read-only` needs the `/tmp` tmpfs (already in the compose file) because Python
  writes temp files there.

## Guardrails

### The key guard

`tools/secret_guard.py` fails when a credential-shaped value reaches a file git
tracks: a filled `.env.example`, a `.env` that got committed, or a key pasted into a
config, comment or source file. It uses only the standard library, prints
`file:line variable` and never the value itself, so its output is safe in CI logs.

The same scan runs as `tests/test_secret_guard.py`, so the test suite and the hook
share one implementation.

### Pre-commit hook

Enable it once per clone:

```bash
git config core.hooksPath .githooks
```

Every commit then runs the guard before it is created, so a leaked key never
reaches history. `git commit --no-verify` skips it for one commit.

### Continuous integration

`.github/workflows/ci.yml` runs `ruff` and `pytest` on Python 3.11 and 3.12, then
builds the container, asserts it runs as uid 10001, triages a sample with the
hardened run flags and checks the report it wrote back to the host.

## Safety

Run only on samples you are authorized to analyse. The threat model, the
never-execute guarantee and the vulnerability reporting process are in
[SECURITY.md](SECURITY.md). Never commit live malware;
`rules/local/` and `samples/` are gitignored on purpose.

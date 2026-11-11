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
maltriage scan ./inbox -r                           # batch a directory
maltriage rules lint rules                          # compile-check YARA rules
maltriage db stats                                  # local scan history
maltriage doctor                                    # environment + config check
maltriage doctor --check-api                        # also validate VT_API_KEY
```

`--fail-on suspicious` (or `likely_malicious` / `malicious`) makes the command exit 2,
which is what you want in CI or a cron job.

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

## Safety

Run only on samples you are authorized to analyse. Never commit live malware;
`rules/local/` and `samples/` are gitignored on purpose.

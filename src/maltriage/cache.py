"""SQLite persistence: scan history, findings and the enrichment cache."""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sha256      TEXT PRIMARY KEY,
    md5         TEXT,
    sha1        TEXT,
    ssdeep      TEXT,
    size        INTEGER,
    kind        TEXT,
    first_seen  TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256      TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT,
    tool_version TEXT,
    ruleset_hash TEXT,
    score       INTEGER,
    verdict     TEXT,
    report_json TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    analyzer    TEXT,
    severity    TEXT,
    confidence  REAL,
    title       TEXT,
    signal      TEXT,
    evidence_json TEXT
);
CREATE TABLE IF NOT EXISTS iocs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  INTEGER NOT NULL,
    type     TEXT,
    value    TEXT
);
CREATE TABLE IF NOT EXISTS vt_cache (
    sha256     TEXT PRIMARY KEY,
    fetched_at TEXT,
    malicious  INTEGER,
    suspicious INTEGER,
    total      INTEGER,
    payload    TEXT
);
CREATE TABLE IF NOT EXISTS enrichment_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT,
    endpoint TEXT,
    ts       TEXT,
    status   TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_scans_sha ON scans(sha256);
"""


class Cache:
    """Thin, thread-safe SQLite wrapper. Disabled mode is a no-op."""

    def __init__(self, path: Path | None, enabled: bool = True) -> None:
        self.enabled = enabled
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        if not enabled:
            return
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path) if path else ":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # --- lifecycle -----------------------------------------------------
    def close(self) -> None:
        if self._conn is not None:
            with self._lock:
                self._conn.close()
            self._conn = None

    # --- scans ---------------------------------------------------------
    def remember_sample(
        self, sha256: str, md5: str, sha1: str, ssdeep: str | None, size: int, kind: str
    ) -> None:
        if self._conn is None:
            return
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO samples VALUES (?,?,?,?,?,?,?)",
                (sha256, md5, sha1, ssdeep, size, kind, _now()),
            )
            self._conn.commit()

    def save_report(self, report: Any) -> int | None:
        if self._conn is None:
            return None
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (sha256, started_at, finished_at, tool_version, ruleset_hash,"
                " score, verdict, report_json) VALUES (?,?,?,?,?,?,?,?)",
                (
                    report.file.sha256,
                    report.generated_at.isoformat(),
                    _now(),
                    report.tool_version,
                    report.ruleset.get("hash"),
                    report.verdict.score,
                    report.verdict.band,
                    report.model_dump_json(),
                ),
            )
            scan_id = int(cur.lastrowid or 0)
            for finding in report.findings:
                self._conn.execute(
                    "INSERT INTO findings (scan_id, analyzer, severity, confidence, title, signal,"
                    " evidence_json) VALUES (?,?,?,?,?,?,?)",
                    (
                        scan_id,
                        finding.analyzer,
                        finding.severity.value,
                        finding.confidence,
                        finding.title,
                        finding.signal,
                        _json(finding.evidence),
                    ),
                )
            for ioc in report.iocs:
                self._conn.execute(
                    "INSERT INTO iocs (scan_id, type, value) VALUES (?,?,?)",
                    (scan_id, ioc.type.value, ioc.value),
                )
            self._conn.commit()
            return scan_id

    def previous_scan(self, sha256: str) -> dict[str, Any] | None:
        if self._conn is None:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT score, verdict, finished_at FROM scans WHERE sha256 = ?"
                " ORDER BY id DESC LIMIT 1",
                (sha256,),
            ).fetchone()
        return dict(row) if row else None

    # --- VirusTotal cache ----------------------------------------------
    def get_vt(self, sha256: str, max_age_days: int) -> dict[str, Any] | None:
        if self._conn is None:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM vt_cache WHERE sha256 = ?", (sha256,)
            ).fetchone()
        if not row:
            return None
        fetched = datetime.fromisoformat(row["fetched_at"])
        if datetime.now(UTC) - fetched > timedelta(days=max_age_days):
            return None
        return dict(row)

    def put_vt(
        self, sha256: str, malicious: int, suspicious: int, total: int, payload: dict[str, Any]
    ) -> None:
        if self._conn is None:
            return
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO vt_cache VALUES (?,?,?,?,?,?)",
                (sha256, _now(), malicious, suspicious, total, _json(payload)),
            )
            self._conn.commit()

    def drop_vt(self, sha256: str) -> None:
        """Force the next lookup to hit the API again."""
        if self._conn is None:
            return
        with self._lock:
            self._conn.execute("DELETE FROM vt_cache WHERE sha256 = ?", (sha256,))
            self._conn.commit()

    def log_enrichment(self, provider: str, endpoint: str, status: str) -> None:
        if self._conn is None:
            return
        with self._lock:
            self._conn.execute(
                "INSERT INTO enrichment_log (provider, endpoint, ts, status) VALUES (?,?,?,?)",
                (provider, endpoint, _now(), status),
            )
            self._conn.commit()

    # --- reporting -----------------------------------------------------
    def stats(self) -> dict[str, Any]:
        if self._conn is None:
            return {"enabled": False}
        with self._lock:

            def count(table: str) -> int:
                return int(self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

            rows = self._conn.execute(
                "SELECT verdict, COUNT(*) c FROM scans GROUP BY verdict ORDER BY c DESC"
            ).fetchall()
            top_iocs = self._conn.execute(
                "SELECT value, COUNT(*) c FROM iocs GROUP BY value ORDER BY c DESC LIMIT 10"
            ).fetchall()
        return {
            "enabled": True,
            "samples": count("samples"),
            "scans": count("scans"),
            "findings": count("findings"),
            "iocs": count("iocs"),
            "vt_cache": count("vt_cache"),
            "verdicts": {row["verdict"]: row["c"] for row in rows},
            "top_iocs": [(row["value"], row["c"]) for row in top_iocs],
        }


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json(payload: Any) -> str:
    import json

    return json.dumps(payload, default=str)

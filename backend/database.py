"""
database.py — SmartFuzz Persistence Layer
=========================================
Uses local SQLite by default.  Set TURSO_URL + TURSO_TOKEN env vars to
switch to Turso (cloud SQLite) for persistent storage on platforms with
ephemeral filesystems such as Render's free tier.

Tables:
  SCAN           — one row per scan job
  VULNERABILITY  — one row per confirmed finding
  REPORT         — one row per generated PDF report
"""

import sqlite3
import json
import os
import threading
import tempfile
from datetime import datetime

TURSO_URL   = os.environ.get("TURSO_URL", "")
TURSO_TOKEN = os.environ.get("TURSO_TOKEN", "")
_USE_TURSO  = bool(TURSO_URL and TURSO_TOKEN)

# Embedded-replica tuning. The replica is a local SQLite file kept in sync with
# the Turso primary: READS hit the local file (microseconds), WRITES auto-push
# to the primary so data persists even when the file is wiped on redeploy.
_REPLICA_PATH  = os.environ.get(
    "TURSO_REPLICA_PATH",
    os.path.join(tempfile.gettempdir(), "smartfuzz_replica.db"),
)
_SYNC_INTERVAL = int(os.environ.get("TURSO_SYNC_INTERVAL", "30"))  # seconds

# Shared singleton state for the embedded replica.
_turso_conn   = None            # the long-lived libsql connection
_turso_lock   = threading.Lock()  # serialises access (libsql conn isn't thread-safe)
_turso_remote = False           # True if we fell back to plain remote mode

if _USE_TURSO:
    import libsql_experimental as _libsql  # type: ignore
    DB_PATH  = None
    _SEED_DB = None
else:
    import shutil as _shutil
    _DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
    DB_PATH   = os.path.join(_DATA_DIR, "smartfuzz.db")
    _SEED_DB  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smartfuzz.db")
    print(f"[db] Using local SQLite: {DB_PATH}")


# ── Seed helper (local mode only) ────────────────────────────────────────────

def _seed_persistent_db() -> None:
    """On first deploy to a Render disk the path is empty — copy the seed DB
    baked into the image.  No-op on every subsequent restart."""
    if DB_PATH == _SEED_DB or os.path.exists(DB_PATH):
        return
    os.makedirs(_DATA_DIR, exist_ok=True)
    if os.path.exists(_SEED_DB):
        _shutil.copy2(_SEED_DB, DB_PATH)
        print(f"[db] Seeded persistent DB: {_SEED_DB} → {DB_PATH}")


# ── Turso connection setup ────────────────────────────────────────────────────

def _init_turso_conn() -> None:
    """Open the embedded-replica connection once and hydrate it from the primary.
    Falls back to plain remote mode if the replica can't be created — that path
    is slower but proven, so the app never breaks and data is never lost."""
    global _turso_conn, _turso_remote
    try:
        conn = _libsql.connect(
            _REPLICA_PATH,
            sync_url=TURSO_URL,
            auth_token=TURSO_TOKEN,
            sync_interval=_SYNC_INTERVAL,
            _check_same_thread=False,
        )
        conn.sync()  # pull the full DB down once at startup
        _turso_conn   = conn
        _turso_remote = False
        print(f"[db] Turso embedded replica ready at {_REPLICA_PATH} "
              f"(local reads, {_SYNC_INTERVAL}s background sync)")
    except Exception as e:
        # Fall back to a plain remote connection — slower, but guaranteed to work.
        _turso_remote = True
        try:
            _turso_conn = _libsql.connect(
                TURSO_URL, auth_token=TURSO_TOKEN, _check_same_thread=False
            )
            print(f"[db] Embedded replica unavailable ({e}); using remote mode")
        except Exception as e2:
            _turso_conn = None
            print(f"[db] Turso connection failed entirely: {e2}")


# ── libsql row/cursor/connection wrappers ────────────────────────────────────
# libsql_experimental doesn't support row_factory, so we wrap its objects to
# give the same dict-style row access (row["col"], dict(row)) the rest of this
# module relies on. Results are fetched eagerly under the shared lock so no live
# cursor outlives the lock — that keeps the single shared connection thread-safe.

class _Row(dict):
    def __init__(self, description, values):
        super().__init__(zip([d[0] for d in description], values))
        self._values = values
    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)

class _EagerCursor:
    """Holds rows already fetched under the lock; iterated lock-free afterwards."""
    def __init__(self, rows):
        self._rows = rows
        self._idx  = 0
    def fetchone(self):
        if self._idx < len(self._rows):
            row = self._rows[self._idx]
            self._idx += 1
            return row
        return None
    def fetchall(self):
        rest = self._rows[self._idx:]
        self._idx = len(self._rows)
        return rest

class _TursoConn:
    """Wraps the shared libsql connection. Every op runs under _turso_lock and
    fetches results eagerly so the connection is touched by one thread at a time.
    close() is a no-op — the underlying connection is a long-lived singleton."""
    def __init__(self, conn):
        self._c = conn
    def execute(self, sql, params=None):
        with _turso_lock:
            cur  = self._c.execute(sql, params) if params is not None else self._c.execute(sql)
            desc = cur.description
            rows = [_Row(desc, r) for r in cur.fetchall()] if desc else []
        return _EagerCursor(rows)
    def commit(self):
        with _turso_lock:
            self._c.commit()
    def close(self):
        pass  # singleton — never actually closed


# ── Connection helper ─────────────────────────────────────────────────────────

def _get_conn():
    if _USE_TURSO:
        if _turso_conn is None:
            _init_turso_conn()
        return _TursoConn(_turso_conn)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS SCAN (
        id                       TEXT PRIMARY KEY,
        target_url               TEXT NOT NULL,
        scan_type                TEXT NOT NULL DEFAULT 'GET',
        vuln_classes             TEXT NOT NULL DEFAULT '[]',
        status                   TEXT NOT NULL DEFAULT 'queued',
        progress                 INTEGER NOT NULL DEFAULT 0,
        current_step             TEXT NOT NULL DEFAULT 'Queued...',
        created_at               TEXT NOT NULL,
        completed_at             TEXT,
        forms_crawled            INTEGER DEFAULT 0,
        get_params_found         INTEGER DEFAULT 0,
        total_payloads_generated INTEGER DEFAULT 0,
        page_title               TEXT DEFAULT ''
    )""",
    """CREATE TABLE IF NOT EXISTS VULNERABILITY (
        id               TEXT PRIMARY KEY,
        scan_id          TEXT NOT NULL REFERENCES SCAN(id),
        vuln_type        TEXT NOT NULL,
        parameter        TEXT NOT NULL,
        payload          TEXT NOT NULL,
        severity         TEXT NOT NULL,
        signature_label  TEXT,
        url              TEXT NOT NULL,
        method           TEXT NOT NULL DEFAULT 'GET',
        status_code      INTEGER,
        response_time_s  REAL,
        response_snippet TEXT,
        timestamp        TEXT,
        remediation      TEXT,
        cvss_score       REAL,
        cvss_vector      TEXT,
        owasp_category   TEXT,
        owasp_name       TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS REPORT (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id      TEXT NOT NULL REFERENCES SCAN(id),
        generated_at TEXT NOT NULL,
        file_path    TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_vuln_scan_id ON VULNERABILITY(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_scan_status  ON SCAN(status)",
    "CREATE INDEX IF NOT EXISTS idx_scan_created ON SCAN(created_at)",
]

_MIGRATIONS = [
    "ALTER TABLE VULNERABILITY ADD COLUMN cvss_score REAL",
    "ALTER TABLE VULNERABILITY ADD COLUMN cvss_vector TEXT",
    "ALTER TABLE VULNERABILITY ADD COLUMN owasp_category TEXT",
    "ALTER TABLE VULNERABILITY ADD COLUMN owasp_name TEXT",
]


def init_db():
    """Create all tables if they don't exist. Called once on startup."""
    if not _USE_TURSO:
        _seed_persistent_db()

    conn = _get_conn()

    for stmt in _SCHEMA:
        conn.execute(stmt)
    conn.commit()

    for stmt in _MIGRATIONS:
        try:
            conn.execute(stmt)
        except Exception:
            pass
    conn.commit()

    # Backfill OWASP columns for rows predating that feature.
    conn.execute("""
        UPDATE VULNERABILITY
        SET
            owasp_category = CASE vuln_type
                WHEN 'SQLi'              THEN 'A03:2021'
                WHEN 'NoSQL'             THEN 'A03:2021'
                WHEN 'XSS'               THEN 'A03:2021'
                WHEN 'RCE'               THEN 'A03:2021'
                WHEN 'Command Injection' THEN 'A03:2021'
                WHEN 'SSTI'              THEN 'A03:2021'
                WHEN 'XXE'               THEN 'A05:2021'
                WHEN 'SSRF'              THEN 'A10:2021'
                WHEN 'Auth Bypass'       THEN 'A07:2021'
                WHEN 'IDOR'              THEN 'A01:2021'
                WHEN 'Open Redirect'     THEN 'A01:2021'
                WHEN 'Path Traversal'    THEN 'A01:2021'
                WHEN 'Info Disclosure'   THEN 'A05:2021'
                ELSE owasp_category
            END,
            owasp_name = CASE vuln_type
                WHEN 'SQLi'              THEN 'Injection'
                WHEN 'NoSQL'             THEN 'Injection'
                WHEN 'XSS'               THEN 'Injection'
                WHEN 'RCE'               THEN 'Injection'
                WHEN 'Command Injection' THEN 'Injection'
                WHEN 'SSTI'              THEN 'Injection'
                WHEN 'XXE'               THEN 'Security Misconfiguration'
                WHEN 'SSRF'              THEN 'Server-Side Request Forgery'
                WHEN 'Auth Bypass'       THEN 'Identification and Authentication Failures'
                WHEN 'IDOR'              THEN 'Broken Access Control'
                WHEN 'Open Redirect'     THEN 'Broken Access Control'
                WHEN 'Path Traversal'    THEN 'Broken Access Control'
                WHEN 'Info Disclosure'   THEN 'Security Misconfiguration'
                ELSE owasp_name
            END
        WHERE (owasp_category IS NULL OR owasp_category = '')
          AND vuln_type IN (
                'SQLi','NoSQL','XSS','RCE','Command Injection','SSTI',
                'XXE','SSRF','Auth Bypass','IDOR','Open Redirect',
                'Path Traversal','Info Disclosure'
          )
    """)
    conn.commit()
    conn.close()


# ── SCAN helpers ──────────────────────────────────────────────────────────────

def create_scan(scan_id: str, target_url: str, scan_type: str,
                vuln_classes: list[str], created_at: str):
    conn = _get_conn()
    conn.execute("""
        INSERT INTO SCAN (id, target_url, scan_type, vuln_classes,
                          status, progress, current_step, created_at)
        VALUES (?, ?, ?, ?, 'queued', 0, 'Scan queued, waiting to start...', ?)
    """, (scan_id, target_url, scan_type, json.dumps(vuln_classes), created_at))
    conn.commit()
    conn.close()


def update_scan_progress(scan_id: str, progress: int, current_step: str, status: str = None):
    conn = _get_conn()
    if status:
        conn.execute("""
            UPDATE SCAN SET progress=?, current_step=?, status=?
            WHERE id=? AND status NOT IN ('cancelled', 'failed', 'completed')
        """, (progress, current_step, status, scan_id))
    else:
        conn.execute("""
            UPDATE SCAN SET progress=?, current_step=?
            WHERE id=? AND status NOT IN ('cancelled', 'failed', 'completed')
        """, (progress, current_step, scan_id))
    conn.commit()
    conn.close()


def complete_scan(scan_id: str, completed_at: str, forms_crawled: int,
                  get_params_found: int, total_payloads: int, page_title: str):
    conn = _get_conn()
    conn.execute("""
        UPDATE SCAN
        SET status='completed', progress=100,
            current_step='Scan complete.',
            completed_at=?,
            forms_crawled=?,
            get_params_found=?,
            total_payloads_generated=?,
            page_title=?
        WHERE id=? AND status NOT IN ('cancelled', 'failed')
    """, (completed_at, forms_crawled, get_params_found,
          total_payloads, page_title, scan_id))
    conn.commit()
    conn.close()


def fail_scan(scan_id: str, reason: str):
    conn = _get_conn()
    conn.execute("""
        UPDATE SCAN SET status='failed', current_step=?
        WHERE id=? AND status NOT IN ('cancelled', 'completed')
    """, (reason, scan_id))
    conn.commit()
    conn.close()


def is_scan_cancelled(scan_id: str) -> bool:
    conn = _get_conn()
    row = conn.execute("SELECT status FROM SCAN WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return row is not None and row["status"] == "cancelled"


def cancel_scan_db(scan_id: str, cancelled_at: str):
    conn = _get_conn()
    conn.execute("""
        UPDATE SCAN
        SET status='cancelled',
            current_step='Scan cancelled by user.',
            completed_at=?
        WHERE id=?
    """, (cancelled_at, scan_id))
    conn.commit()
    conn.close()


def get_scan(scan_id: str) -> dict | None:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM SCAN WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return _scan_row_to_dict(row)


def _scan_row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["vuln_classes"] = json.loads(d.get("vuln_classes") or "[]")
    except Exception:
        d["vuln_classes"] = []
    return d


# ── VULNERABILITY helpers ─────────────────────────────────────────────────────

def insert_finding(scan_id: str, finding: dict):
    rt = finding.get("response_time_s")
    if rt is None:
        rt_ms = finding.get("response_time_ms", 0)
        rt = rt_ms / 1000.0 if rt_ms else None

    conn = _get_conn()
    conn.execute("""
        INSERT OR IGNORE INTO VULNERABILITY
            (id, scan_id, vuln_type, parameter, payload, severity,
             signature_label, url, method, status_code,
             response_time_s, response_snippet, timestamp, remediation,
             cvss_score, cvss_vector, owasp_category, owasp_name)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        finding.get("id") or str(__import__("uuid").uuid4()),
        scan_id,
        finding.get("vuln_type", ""),
        finding.get("parameter", ""),
        finding.get("payload", ""),
        finding.get("severity", "Low"),
        finding.get("signature_label") or finding.get("evidence", ""),
        finding.get("url", ""),
        finding.get("method", "GET"),
        finding.get("status_code"),
        rt,
        finding.get("response_snippet") or finding.get("evidence", ""),
        finding.get("timestamp", ""),
        finding.get("remediation", ""),
        finding.get("cvss_score"),
        finding.get("cvss_vector"),
        finding.get("owasp_category"),
        finding.get("owasp_name"),
    ))
    conn.commit()
    conn.close()


def get_findings(scan_id: str) -> list[dict]:
    _SEV = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM VULNERABILITY WHERE scan_id=?", (scan_id,)
    ).fetchall()
    conn.close()
    findings = [dict(r) for r in rows]
    findings.sort(key=lambda f: _SEV.get(f.get("severity", "Low"), 0), reverse=True)
    return findings


def count_findings(scan_id: str) -> int:
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM VULNERABILITY WHERE scan_id=?", (scan_id,)
    ).fetchone()
    conn.close()
    return row["cnt"] if row else 0


def get_findings_stats(scan_id: str) -> dict:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM VULNERABILITY WHERE scan_id=? GROUP BY severity",
        (scan_id,)
    ).fetchall()
    conn.close()

    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for row in rows:
        stats[row["severity"]] = row["cnt"]

    scan  = get_scan(scan_id)
    total = sum(stats.values())
    return {
        "total_findings":           total,
        "critical":                 stats["Critical"],
        "high":                     stats["High"],
        "medium":                   stats["Medium"],
        "low":                      stats["Low"],
        "forms_crawled":            scan.get("forms_crawled", 0) if scan else 0,
        "get_params_found":         scan.get("get_params_found", 0) if scan else 0,
        "total_payloads_generated": scan.get("total_payloads_generated", 0) if scan else 0,
        "page_title":               scan.get("page_title", "") if scan else "",
    }


# ── REPORT helpers ────────────────────────────────────────────────────────────

def save_report(scan_id: str, file_path: str):
    conn = _get_conn()
    conn.execute("""
        INSERT INTO REPORT (scan_id, generated_at, file_path)
        VALUES (?, ?, ?)
    """, (scan_id, datetime.utcnow().isoformat() + "Z", file_path))
    conn.commit()
    conn.close()


def get_report(scan_id: str) -> dict | None:
    conn = _get_conn()
    row = conn.execute("""
        SELECT * FROM REPORT WHERE scan_id=?
        ORDER BY generated_at DESC LIMIT 1
    """, (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_reports() -> list[dict]:
    conn = _get_conn()
    rows = conn.execute("""
        SELECT r.id, r.scan_id, r.generated_at, r.file_path,
               s.target_url, s.completed_at,
               COUNT(v.id) as total_findings
        FROM REPORT r
        JOIN SCAN s ON s.id = r.scan_id
        LEFT JOIN VULNERABILITY v ON v.scan_id = r.scan_id
        GROUP BY r.id
        ORDER BY r.generated_at DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Dashboard stats ───────────────────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    conn = _get_conn()

    total_scans = conn.execute(
        "SELECT COUNT(*) as cnt FROM SCAN"
    ).fetchone()["cnt"]

    completed_scans = conn.execute(
        "SELECT COUNT(*) as cnt FROM SCAN WHERE status='completed'"
    ).fetchone()["cnt"]

    total_vulns = conn.execute(
        "SELECT COUNT(*) as cnt FROM VULNERABILITY"
    ).fetchone()["cnt"]

    sev_rows = conn.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM VULNERABILITY GROUP BY severity
    """).fetchall()
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for row in sev_rows:
        sev[row["severity"]] = row["cnt"]

    top_vuln_row = conn.execute("""
        SELECT vuln_type, COUNT(*) as cnt
        FROM VULNERABILITY GROUP BY vuln_type
        ORDER BY cnt DESC LIMIT 1
    """).fetchone()
    top_vuln = top_vuln_row["vuln_type"] if top_vuln_row else "—"

    recent_scans = conn.execute("""
        SELECT s.id, s.target_url, s.status, s.created_at, s.completed_at,
               COUNT(v.id) as total_findings
        FROM SCAN s
        LEFT JOIN VULNERABILITY v ON v.scan_id = s.id
        GROUP BY s.id
        ORDER BY s.created_at DESC LIMIT 5
    """).fetchall()

    by_owasp = {
        "A01:2021": 0, "A02:2021": 0, "A03:2021": 0, "A04:2021": 0,
        "A05:2021": 0, "A06:2021": 0, "A07:2021": 0, "A08:2021": 0,
        "A09:2021": 0, "A10:2021": 0,
    }
    owasp_rows = conn.execute("""
        SELECT owasp_category, COUNT(*) as cnt
        FROM VULNERABILITY
        WHERE owasp_category IS NOT NULL AND owasp_category != ''
        GROUP BY owasp_category
    """).fetchall()
    for row in owasp_rows:
        cat = row["owasp_category"]
        if cat in by_owasp:
            by_owasp[cat] = row["cnt"]

    conn.close()

    return {
        "total_scans":     total_scans,
        "completed_scans": completed_scans,
        "total_vulns":     total_vulns,
        "by_severity":     sev,
        "by_owasp":        by_owasp,
        "top_vuln_type":   top_vuln,
        "recent_scans":    [dict(r) for r in recent_scans],
    }


# ── get_all_scans ─────────────────────────────────────────────────────────────

def get_all_scans() -> list[dict]:
    conn = _get_conn()
    rows = conn.execute("""
        SELECT
            s.id,
            s.target_url,
            s.status,
            s.progress,
            s.current_step,
            s.created_at,
            s.completed_at,
            s.vuln_classes,
            COUNT(v.id) AS findings_count
        FROM SCAN s
        LEFT JOIN VULNERABILITY v ON v.scan_id = s.id
        GROUP BY s.id
        ORDER BY s.created_at DESC
    """).fetchall()
    conn.close()

    return [
        {
            "id":             row["id"],
            "target_url":     row["target_url"],
            "status":         row["status"],
            "progress":       row["progress"],
            "current_step":   row["current_step"],
            "created_at":     row["created_at"],
            "completed_at":   row["completed_at"],
            "vuln_classes":   json.loads(row["vuln_classes"] or "[]"),
            "findings_count": row["findings_count"],
        }
        for row in rows
    ]

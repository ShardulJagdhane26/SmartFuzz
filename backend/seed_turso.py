"""
seed_turso.py — One-time migration: local smartfuzz.db → Turso
Run once after setting up Turso:
  python seed_turso.py <TURSO_URL> <TURSO_TOKEN>
"""

import sys
import sqlite3
import json
import requests

def main():
    if len(sys.argv) != 3:
        print("Usage: python seed_turso.py <TURSO_URL> <TURSO_TOKEN>")
        print("Example: python seed_turso.py libsql://smartfuzz-xxx.turso.io eyJ...")
        sys.exit(1)

    raw_url  = sys.argv[1]
    token    = sys.argv[2]

    # Convert libsql:// → https:// for the HTTP API
    http_url = raw_url.replace("libsql://", "https://") + "/v2/pipeline"
    headers  = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def turso(sql, args=None):
        stmt = {"type": "execute", "stmt": {"sql": sql, "args": []}}
        if args:
            for a in args:
                if a is None:
                    stmt["stmt"]["args"].append({"type": "null"})
                elif isinstance(a, int):
                    stmt["stmt"]["args"].append({"type": "integer", "value": str(a)})
                elif isinstance(a, float):
                    stmt["stmt"]["args"].append({"type": "float", "value": a})
                else:
                    stmt["stmt"]["args"].append({"type": "text", "value": str(a)})
        payload  = {"requests": [stmt, {"type": "close"}]}
        resp     = requests.post(http_url, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        if result["results"][0]["type"] == "error":
            raise RuntimeError(result["results"][0]["error"])
        return result

    # ── Create schema in Turso ────────────────────────────────────────────────
    print("Creating schema in Turso...")
    schema_stmts = [
        """CREATE TABLE IF NOT EXISTS SCAN (
            id TEXT PRIMARY KEY, target_url TEXT NOT NULL,
            scan_type TEXT NOT NULL DEFAULT 'GET', vuln_classes TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'queued', progress INTEGER NOT NULL DEFAULT 0,
            current_step TEXT NOT NULL DEFAULT 'Queued...', created_at TEXT NOT NULL,
            completed_at TEXT, forms_crawled INTEGER DEFAULT 0,
            get_params_found INTEGER DEFAULT 0, total_payloads_generated INTEGER DEFAULT 0,
            page_title TEXT DEFAULT '')""",
        """CREATE TABLE IF NOT EXISTS VULNERABILITY (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES SCAN(id),
            vuln_type TEXT NOT NULL, parameter TEXT NOT NULL, payload TEXT NOT NULL,
            severity TEXT NOT NULL, signature_label TEXT, url TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'GET', status_code INTEGER,
            response_time_s REAL, response_snippet TEXT, timestamp TEXT,
            remediation TEXT, cvss_score REAL, cvss_vector TEXT,
            owasp_category TEXT, owasp_name TEXT)""",
        """CREATE TABLE IF NOT EXISTS REPORT (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL REFERENCES SCAN(id),
            generated_at TEXT NOT NULL, file_path TEXT NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS idx_vuln_scan_id ON VULNERABILITY(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_status  ON SCAN(status)",
        "CREATE INDEX IF NOT EXISTS idx_scan_created ON SCAN(created_at)",
    ]
    for stmt in schema_stmts:
        turso(stmt)
    print("  Schema ready.")

    # ── Read local SQLite ─────────────────────────────────────────────────────
    local = sqlite3.connect("smartfuzz.db")
    local.row_factory = sqlite3.Row

    # ── Migrate SCAN ──────────────────────────────────────────────────────────
    scans = local.execute("SELECT * FROM SCAN").fetchall()
    print(f"Migrating {len(scans)} scans...")
    for i, row in enumerate(scans):
        try:
            turso("""INSERT OR IGNORE INTO SCAN
                (id, target_url, scan_type, vuln_classes, status, progress,
                 current_step, created_at, completed_at, forms_crawled,
                 get_params_found, total_payloads_generated, page_title)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [row["id"], row["target_url"], row["scan_type"], row["vuln_classes"],
                 row["status"], row["progress"], row["current_step"], row["created_at"],
                 row["completed_at"], row["forms_crawled"], row["get_params_found"],
                 row["total_payloads_generated"], row["page_title"]])
        except Exception as e:
            print(f"  Scan {row['id'][:8]} skipped: {e}")
        if (i + 1) % 10 == 0:
            print(f"  {i + 1}/{len(scans)} scans done...")
    print(f"  All {len(scans)} scans migrated.")

    # ── Migrate VULNERABILITY ─────────────────────────────────────────────────
    vulns = local.execute("SELECT * FROM VULNERABILITY").fetchall()
    print(f"Migrating {len(vulns)} vulnerabilities...")
    for i, row in enumerate(vulns):
        try:
            turso("""INSERT OR IGNORE INTO VULNERABILITY
                (id, scan_id, vuln_type, parameter, payload, severity, signature_label,
                 url, method, status_code, response_time_s, response_snippet, timestamp,
                 remediation, cvss_score, cvss_vector, owasp_category, owasp_name)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [row["id"], row["scan_id"], row["vuln_type"], row["parameter"],
                 row["payload"], row["severity"], row["signature_label"], row["url"],
                 row["method"], row["status_code"], row["response_time_s"],
                 row["response_snippet"], row["timestamp"], row["remediation"],
                 row["cvss_score"], row["cvss_vector"], row["owasp_category"],
                 row["owasp_name"]])
        except Exception as e:
            print(f"  Vuln {str(row['id'])[:8]} skipped: {e}")
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{len(vulns)} vulns done...")
    print(f"  All {len(vulns)} vulnerabilities migrated.")

    local.close()
    print("\nMigration complete! Your Turso database is ready.")

if __name__ == "__main__":
    main()

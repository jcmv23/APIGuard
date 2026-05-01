"""
APIGuard Enterprise — Remediation Tracker
==========================================
Track the lifecycle of security findings: open → in_progress → fixed / accepted_risk / false_positive.
Assign findings to team members, add notes, and compute MTTR.
"""

import sqlite3
import time
import hashlib
import json
from typing import Optional


DB_FILE = "apiguard_remediation.db"


def init_remediation_db(db_path: str = DB_FILE):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS finding_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            finding_hash TEXT NOT NULL,
            vulnerability_type TEXT,
            endpoint TEXT,
            severity TEXT,
            status TEXT DEFAULT 'open',
            assigned_to TEXT,
            notes TEXT DEFAULT '',
            created_at TEXT,
            updated_at TEXT,
            resolved_at TEXT,
            UNIQUE(scan_id, finding_hash)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS remediation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            old_status TEXT,
            new_status TEXT,
            changed_by TEXT,
            note TEXT,
            timestamp TEXT,
            FOREIGN KEY (finding_id) REFERENCES finding_status(id)
        )
    """)
    conn.commit()
    conn.close()

init_remediation_db()


class RemediationTracker:
    """Tracks the remediation lifecycle of security findings."""

    VALID_STATUSES = {'open', 'in_progress', 'fixed', 'accepted_risk', 'false_positive'}

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path

    def _conn(self):
        return sqlite3.connect(self.db_path)

    @staticmethod
    def _hash_finding(finding: dict) -> str:
        """Generate a unique hash for a finding based on its key properties."""
        key = f"{finding.get('vulnerability_type', '')}{finding.get('endpoint', '')}{finding.get('method', '')}{finding.get('severity', '')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def ingest_scan_findings(self, scan_id: str, report: dict):
        """Import all findings from a scan report into the tracking system."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = self._conn()
        count = 0

        for mod_name, mod_data in report.get("modules", {}).items():
            if not isinstance(mod_data, dict):
                continue
            for finding in mod_data.get("findings", []):
                fhash = self._hash_finding(finding)
                try:
                    conn.execute(
                        """INSERT OR IGNORE INTO finding_status 
                           (scan_id, finding_hash, vulnerability_type, endpoint, severity, status, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, 'open', ?, ?)""",
                        (str(scan_id), fhash,
                         finding.get("vulnerability_type", finding.get("finding_type", "Unknown")),
                         finding.get("endpoint", finding.get("path", "")),
                         finding.get("severity", "MEDIUM"),
                         now, now)
                    )
                    count += 1
                except Exception:
                    pass

        conn.commit()
        conn.close()
        return count

    def update_status(self, finding_id: int, new_status: str, changed_by: str = None, note: str = ""):
        """Update the status of a finding."""
        if new_status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {new_status}. Must be one of {self.VALID_STATUSES}")

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = self._conn()

        # Get current status
        row = conn.execute("SELECT status FROM finding_status WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Finding {finding_id} not found")
        old_status = row[0]

        # Update 
        resolved_at = now if new_status in ('fixed', 'accepted_risk', 'false_positive') else None
        conn.execute(
            "UPDATE finding_status SET status = ?, updated_at = ?, resolved_at = COALESCE(?, resolved_at), notes = ? WHERE id = ?",
            (new_status, now, resolved_at, note, finding_id)
        )

        # Record history
        conn.execute(
            "INSERT INTO remediation_history (finding_id, old_status, new_status, changed_by, note, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (finding_id, old_status, new_status, changed_by, note, now)
        )

        conn.commit()
        conn.close()
        return {"id": finding_id, "old_status": old_status, "new_status": new_status}

    def assign_finding(self, finding_id: int, assigned_to: str):
        """Assign a finding to a user."""
        conn = self._conn()
        conn.execute("UPDATE finding_status SET assigned_to = ?, updated_at = ? WHERE id = ?",
                     (assigned_to, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), finding_id))
        conn.commit()
        conn.close()

    def list_findings(self, scan_id: str = None, status: str = None, severity: str = None) -> list:
        """List findings with optional filters."""
        conn = self._conn()
        query = "SELECT id, scan_id, finding_hash, vulnerability_type, endpoint, severity, status, assigned_to, notes, created_at, updated_at, resolved_at FROM finding_status WHERE 1=1"
        params = []
        if scan_id:
            query += " AND scan_id = ?"
            params.append(str(scan_id))
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, created_at DESC"

        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [{
            "id": r[0], "scan_id": r[1], "finding_hash": r[2], "vulnerability_type": r[3],
            "endpoint": r[4], "severity": r[5], "status": r[6], "assigned_to": r[7],
            "notes": r[8], "created_at": r[9], "updated_at": r[10], "resolved_at": r[11]
        } for r in rows]

    def get_metrics(self) -> dict:
        """Compute remediation metrics: MTTR, open/closed counts, security debt."""
        conn = self._conn()

        # Status counts
        counts = {}
        for status in self.VALID_STATUSES:
            row = conn.execute("SELECT COUNT(*) FROM finding_status WHERE status = ?", (status,)).fetchone()
            counts[status] = row[0]

        # Severity breakdown for open findings
        severity_open = {}
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            row = conn.execute("SELECT COUNT(*) FROM finding_status WHERE status = 'open' AND severity = ?", (sev,)).fetchone()
            severity_open[sev] = row[0]

        # MTTR — Mean Time to Remediate (for resolved findings)
        rows = conn.execute(
            "SELECT created_at, resolved_at FROM finding_status WHERE resolved_at IS NOT NULL"
        ).fetchall()
        
        mttr_hours = 0.0
        if rows:
            total_hours = 0
            for created, resolved in rows:
                try:
                    t1 = time.mktime(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))
                    t2 = time.mktime(time.strptime(resolved, "%Y-%m-%dT%H:%M:%SZ"))
                    total_hours += (t2 - t1) / 3600
                except Exception:
                    pass
            mttr_hours = total_hours / len(rows) if rows else 0

        # Security Debt Score (weighted: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1)
        weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}
        debt = sum(severity_open.get(s, 0) * w for s, w in weights.items())

        total = sum(counts.values())
        resolved = counts.get('fixed', 0) + counts.get('accepted_risk', 0) + counts.get('false_positive', 0)

        conn.close()
        return {
            "total_findings": total,
            "status_breakdown": counts,
            "severity_open": severity_open,
            "resolved": resolved,
            "resolution_rate": round(resolved / max(total, 1) * 100, 1),
            "mttr_hours": round(mttr_hours, 1),
            "security_debt_score": debt,
        }


remediation_tracker = RemediationTracker()

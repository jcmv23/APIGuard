"""
APIGuard Enterprise — Scan Scheduler v4.0
==========================================
Background thread checks every 30s for due scans and executes them.
Supports both cron expressions and human-friendly date/time + repeat interval.
"""

import sqlite3
import time
import uuid
import threading
import json
from typing import Optional
from datetime import datetime, timedelta

from core.logging_config import get_logger

logger = get_logger("scheduler")

DB_FILE = "apiguard_schedules.db"

def init_scheduler_db(db_path: str = DB_FILE):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            target_url TEXT NOT NULL,
            cron_expr TEXT NOT NULL DEFAULT '0 3 * * 1',
            modules TEXT NOT NULL DEFAULT '["bola","bfla","auth","rate","injection","ssl","graphql","data_exposure"]',
            enabled INTEGER DEFAULT 1,
            timeout INTEGER DEFAULT 10,
            notify INTEGER DEFAULT 1,
            last_run TEXT,
            next_run TEXT,
            last_status TEXT DEFAULT 'pending',
            last_scan_id TEXT,
            run_count INTEGER DEFAULT 0,
            repeat_interval_min INTEGER DEFAULT 0,
            max_runs INTEGER DEFAULT 0,
            created_by TEXT,
            created_at TEXT
        )
    """)
    # Migration: add new columns to existing tables
    for col, col_type in [("repeat_interval_min", "INTEGER DEFAULT 0"), ("max_runs", "INTEGER DEFAULT 0")]:
        try:
            c.execute(f"ALTER TABLE scheduled_scans ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError:
            pass
    conn.commit()
    conn.close()

init_scheduler_db()


class ScanScheduler:
    """Manages scheduled recurring scans with background execution."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scan_callback = None  # Set by api_server to actually run scans

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def set_scan_callback(self, callback):
        """Set the function to call when a scan is due. Signature: callback(target_url, modules, timeout, notify) -> scan_id"""
        self._scan_callback = callback

    def create_schedule(self, name: str, target_url: str, cron_expr: str = "0 3 * * 1",
                        modules: list = None, timeout: int = 10, notify: bool = True,
                        created_by: str = None, start_at: str = None,
                        repeat_interval_min: int = 0, max_runs: int = 0) -> dict:
        """Create a new scheduled scan."""
        schedule_id = f"sched_{uuid.uuid4().hex[:12]}"
        mods = json.dumps(modules or ["bola", "bfla", "auth", "rate", "injection", "ssl", "graphql", "data_exposure"])
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Determine next_run
        if start_at:
            next_run = start_at
        else:
            next_run = self._compute_next_run(cron_expr, repeat_interval_min)

        conn = self._conn()
        conn.execute(
            """INSERT INTO scheduled_scans
               (id, name, target_url, cron_expr, modules, enabled, timeout, notify, next_run, repeat_interval_min, max_runs, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)""",
            (schedule_id, name, target_url, cron_expr, mods, timeout, int(notify), next_run, repeat_interval_min, max_runs, created_by, now)
        )
        conn.commit()
        conn.close()

        logger.info("schedule_created", id=schedule_id, name=name, next_run=next_run)
        return {
            "id": schedule_id, "name": name, "target_url": target_url,
            "cron_expr": cron_expr, "modules": modules, "enabled": True,
            "next_run": next_run, "repeat_interval_min": repeat_interval_min,
            "max_runs": max_runs, "created_at": now
        }

    def list_schedules(self) -> list:
        conn = self._conn()
        rows = conn.execute(
            "SELECT id, name, target_url, cron_expr, modules, enabled, last_run, next_run, last_status, run_count, created_at, repeat_interval_min, max_runs FROM scheduled_scans ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return [{
            "id": r[0], "name": r[1], "target_url": r[2], "cron_expr": r[3],
            "modules": json.loads(r[4]), "enabled": bool(r[5]),
            "last_run": r[6], "next_run": r[7], "last_status": r[8],
            "run_count": r[9], "created_at": r[10],
            "repeat_interval_min": r[11] or 0, "max_runs": r[12] or 0
        } for r in rows]

    def get_schedule(self, schedule_id: str) -> Optional[dict]:
        conn = self._conn()
        r = conn.execute("SELECT * FROM scheduled_scans WHERE id = ?", (schedule_id,)).fetchone()
        conn.close()
        if not r:
            return None
        return {"id": r[0], "name": r[1], "target_url": r[2], "cron_expr": r[3],
                "modules": json.loads(r[4]), "enabled": bool(r[5])}

    def toggle_schedule(self, schedule_id: str, enabled: bool):
        conn = self._conn()
        conn.execute("UPDATE scheduled_scans SET enabled = ? WHERE id = ?", (int(enabled), schedule_id))
        conn.commit()
        conn.close()

    def delete_schedule(self, schedule_id: str):
        conn = self._conn()
        conn.execute("DELETE FROM scheduled_scans WHERE id = ?", (schedule_id,))
        conn.commit()
        conn.close()

    def record_run(self, schedule_id: str, status: str, scan_id: str = None):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = self._conn()
        row = conn.execute("SELECT cron_expr, repeat_interval_min, run_count, max_runs FROM scheduled_scans WHERE id = ?", (schedule_id,)).fetchone()
        if not row:
            conn.close()
            return
        cron_expr, interval_min, run_count, max_runs = row
        next_run = self._compute_next_run(cron_expr, interval_min)

        new_count = (run_count or 0) + 1
        # Auto-disable if max_runs reached
        should_disable = max_runs > 0 and new_count >= max_runs

        conn.execute(
            "UPDATE scheduled_scans SET last_run = ?, last_status = ?, last_scan_id = ?, run_count = ?, next_run = ?, enabled = ? WHERE id = ?",
            (now, status, scan_id, new_count, next_run, 0 if should_disable else 1, schedule_id)
        )
        conn.commit()
        conn.close()

    def get_due_schedules(self) -> list:
        """Get all enabled schedules that are due to run."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = self._conn()
        rows = conn.execute(
            "SELECT id, target_url, modules, timeout, notify FROM scheduled_scans WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ?", (now,)
        ).fetchall()
        conn.close()
        return [{"id": r[0], "target_url": r[1], "modules": json.loads(r[2]), "timeout": r[3], "notify": bool(r[4])} for r in rows]

    # ── Background Runner ──
    def start(self):
        """Start the background scheduler thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="SchedulerThread")
        self._thread.start()
        logger.info("scheduler_started", msg="Background scheduler running (30s interval)")

    def stop(self):
        self._running = False

    def _run_loop(self):
        """Check for due scans every 30 seconds."""
        while self._running:
            try:
                due = self.get_due_schedules()
                for sched in due:
                    logger.info("schedule_triggered", id=sched["id"], target=sched["target_url"])
                    if self._scan_callback:
                        try:
                            scan_id = self._scan_callback(
                                sched["target_url"],
                                sched["modules"],
                                sched["timeout"],
                                sched["notify"]
                            )
                            self.record_run(sched["id"], "completed", str(scan_id))
                            logger.info("schedule_completed", id=sched["id"], scan_id=scan_id)
                        except Exception as e:
                            self.record_run(sched["id"], "failed")
                            logger.error("schedule_run_failed", id=sched["id"], error=str(e))
                    else:
                        logger.warning("schedule_no_callback", msg="No scan callback registered")
                        self.record_run(sched["id"], "no_callback")
            except Exception as e:
                logger.error("scheduler_loop_error", error=str(e))
            time.sleep(30)

    @staticmethod
    def _compute_next_run(cron_expr: str, repeat_interval_min: int = 0) -> str:
        """Compute the next run time."""
        now = datetime.utcnow()

        # If repeat_interval_min is set, use simple interval
        if repeat_interval_min and repeat_interval_min > 0:
            next_dt = now + timedelta(minutes=repeat_interval_min)
            return next_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Parse cron expression
        parts = cron_expr.split()
        if len(parts) != 5:
            return (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

        minute, hour, dom, month, dow = parts

        # Handle common patterns
        if minute.startswith("*/"):
            interval = int(minute[2:])
            next_dt = now + timedelta(minutes=interval)
        elif hour.startswith("*/"):
            interval = int(hour[2:])
            next_dt = now + timedelta(hours=interval)
        elif dow != '*' and dom == '*':
            # Specific day of week
            h = int(hour) if hour != '*' else 3
            m = int(minute) if minute != '*' else 0
            target_dow = int(dow)
            days_ahead = target_dow - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            next_dt = (now + timedelta(days=days_ahead)).replace(hour=h, minute=m, second=0, microsecond=0)
        else:
            # Daily at specific time
            h = int(hour) if hour != '*' else 3
            m = int(minute) if minute != '*' else 0
            next_dt = now.replace(hour=h, minute=m, second=0, microsecond=0)
            if next_dt <= now:
                next_dt += timedelta(days=1)

        return next_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


scan_scheduler = ScanScheduler()

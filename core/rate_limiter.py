"""
APIGuard Enterprise — Persistent Rate Limiter
================================================
SQLite-backed rate limiting that persists across server restarts.
Tracks request counts per IP/key with sliding windows.
"""

import sqlite3
import time
import threading
from typing import Optional


DB_FILE = "apiguard_ratelimit.db"
_local = threading.local()


def _get_conn():
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(DB_FILE)
        _local.conn.execute("PRAGMA journal_mode=WAL")
    return _local.conn


def init_ratelimit_db(db_path: str = DB_FILE):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            timestamp REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_key ON rate_limits(key, endpoint, timestamp)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            blocked_at TEXT,
            expires_at TEXT
        )
    """)
    conn.commit()
    conn.close()


init_ratelimit_db()


class PersistentRateLimiter:
    """SQLite-backed rate limiter with sliding window."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path

    def _conn(self):
        return _get_conn()

    def is_allowed(self, key: str, endpoint: str, max_requests: int, window_seconds: int) -> bool:
        """Check if a request is allowed within the rate limit window."""
        conn = self._conn()
        now = time.time()
        cutoff = now - window_seconds

        # Clean old entries
        conn.execute("DELETE FROM rate_limits WHERE timestamp < ?", (cutoff,))

        # Count requests in window
        row = conn.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE key = ? AND endpoint = ? AND timestamp >= ?",
            (key, endpoint, cutoff)
        ).fetchone()
        count = row[0] if row else 0

        if count >= max_requests:
            return False

        # Record this request
        conn.execute(
            "INSERT INTO rate_limits (key, endpoint, timestamp) VALUES (?, ?, ?)",
            (key, endpoint, now)
        )
        conn.commit()
        return True

    def get_remaining(self, key: str, endpoint: str, max_requests: int, window_seconds: int) -> int:
        """Get remaining requests in the current window."""
        conn = self._conn()
        cutoff = time.time() - window_seconds
        row = conn.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE key = ? AND endpoint = ? AND timestamp >= ?",
            (key, endpoint, cutoff)
        ).fetchone()
        count = row[0] if row else 0
        return max(0, max_requests - count)

    def block_ip(self, ip: str, reason: str = "Rate limit exceeded", duration_minutes: int = 60):
        """Temporarily block an IP."""
        conn = self._conn()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + duration_minutes * 60))
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at) VALUES (?, ?, ?, ?)",
            (ip, reason, now, expires)
        )
        conn.commit()

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        conn = self._conn()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        row = conn.execute(
            "SELECT 1 FROM blocked_ips WHERE ip = ? AND expires_at > ?", (ip, now)
        ).fetchone()
        return row is not None

    def unblock_ip(self, ip: str):
        conn = self._conn()
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit()

    def get_stats(self) -> dict:
        """Get rate limiting statistics."""
        conn = self._conn()
        now = time.time()

        total_1h = conn.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE timestamp >= ?", (now - 3600,)
        ).fetchone()[0]

        unique_keys = conn.execute(
            "SELECT COUNT(DISTINCT key) FROM rate_limits WHERE timestamp >= ?", (now - 3600,)
        ).fetchone()[0]

        blocked = conn.execute(
            "SELECT COUNT(*) FROM blocked_ips WHERE expires_at > ?",
            (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),)
        ).fetchone()[0]

        # Top endpoints
        top = conn.execute(
            "SELECT endpoint, COUNT(*) as cnt FROM rate_limits WHERE timestamp >= ? GROUP BY endpoint ORDER BY cnt DESC LIMIT 5",
            (now - 3600,)
        ).fetchall()

        return {
            "requests_last_hour": total_1h,
            "unique_clients": unique_keys,
            "blocked_ips": blocked,
            "top_endpoints": [{"endpoint": r[0], "count": r[1]} for r in top],
        }

    def cleanup(self, older_than_hours: int = 24):
        """Clean up old rate limit records."""
        conn = self._conn()
        cutoff = time.time() - (older_than_hours * 3600)
        conn.execute("DELETE FROM rate_limits WHERE timestamp < ?", (cutoff,))
        conn.execute(
            "DELETE FROM blocked_ips WHERE expires_at < ?",
            (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),)
        )
        conn.commit()


persistent_limiter = PersistentRateLimiter()

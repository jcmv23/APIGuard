"""
APIGuard Enterprise — Database Abstraction Layer
====================================================
Supports both SQLite (development) and PostgreSQL (production).
Switches automatically based on DATABASE_URL environment variable.

Usage:
    from core.database import db

    # Use exactly like sqlite3:
    with db.connect() as conn:
        conn.execute("INSERT INTO ...", (val1, val2))
        rows = conn.execute("SELECT * FROM ...").fetchall()
"""

import os
import sqlite3
import threading
import time
from typing import Any, Optional
from contextlib import contextmanager

from core.logging_config import get_logger

logger = get_logger("database")


# ─────────────────────────────────────────────
# PostgreSQL adapter (same interface as sqlite3)
# ─────────────────────────────────────────────

class PostgresConnection:
    """Wraps psycopg2 connection to provide sqlite3-like interface."""

    def __init__(self, conn):
        self._conn = conn
        self._cursor = None

    def execute(self, query: str, params: tuple = ()) -> 'PostgresCursor':
        # Convert SQLite ? placeholders to PostgreSQL %s
        pg_query = query.replace("?", "%s")
        # Handle SQLite-specific syntax
        pg_query = pg_query.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        pg_query = pg_query.replace("PRAGMA journal_mode=WAL", "-- WAL mode (N/A for PG)")
        pg_query = pg_query.replace("INSERT OR REPLACE", "INSERT ... ON CONFLICT DO UPDATE")

        cursor = self._conn.cursor()
        try:
            cursor.execute(pg_query, params)
        except Exception as e:
            logger.error("pg_query_error", query=pg_query[:100], error=str(e))
            raise
        return PostgresCursor(cursor)

    def executemany(self, query: str, params_list: list):
        pg_query = query.replace("?", "%s")
        cursor = self._conn.cursor()
        cursor.executemany(pg_query, params_list)
        return PostgresCursor(cursor)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


class PostgresCursor:
    """Wraps psycopg2 cursor to provide sqlite3-like interface."""

    def __init__(self, cursor):
        self._cursor = cursor

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount


# ─────────────────────────────────────────────
# Database Manager
# ─────────────────────────────────────────────

class DatabaseManager:
    """
    Unified database interface supporting SQLite and PostgreSQL.
    
    Config via environment:
        DATABASE_URL=postgresql://user:pass@host:5432/dbname  → PostgreSQL
        DATABASE_URL=sqlite:///path/to/db.sqlite              → SQLite
        (no DATABASE_URL)                                     → SQLite (default)
    """

    def __init__(self):
        self.database_url = os.environ.get("DATABASE_URL", "")
        self.is_postgres = self.database_url.startswith("postgresql://") or self.database_url.startswith("postgres://")
        self._pg_pool = None

        if self.is_postgres:
            logger.info("database_init", backend="PostgreSQL", url=self._mask_url(self.database_url))
        else:
            logger.info("database_init", backend="SQLite")

    def _mask_url(self, url: str) -> str:
        """Mask password in connection URL for logging."""
        if "@" in url:
            prefix = url.split("://")[0]
            after_at = url.split("@", 1)[1]
            return f"{prefix}://***:***@{after_at}"
        return url

    def connect(self, db_path: str = "") -> Any:
        """
        Get a database connection.
        For SQLite: uses db_path as the file path.
        For PostgreSQL: uses DATABASE_URL (db_path ignored).
        """
        if self.is_postgres:
            return self._pg_connect()
        else:
            return self._sqlite_connect(db_path)

    def _sqlite_connect(self, db_path: str) -> sqlite3.Connection:
        """Standard SQLite connection with WAL mode."""
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _pg_connect(self) -> PostgresConnection:
        """PostgreSQL connection using psycopg2."""
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError:
            logger.error("psycopg2_not_installed",
                         msg="Install psycopg2-binary: pip install psycopg2-binary")
            raise ImportError(
                "PostgreSQL support requires psycopg2. "
                "Install it: pip install psycopg2-binary"
            )

        conn = psycopg2.connect(self.database_url)
        conn.autocommit = False
        return PostgresConnection(conn)

    @contextmanager
    def transaction(self, db_path: str = ""):
        """Context manager for database transactions."""
        conn = self.connect(db_path)
        try:
            yield conn
            if not self.is_postgres:
                conn.commit()
        except Exception:
            if self.is_postgres:
                conn.rollback()
            raise
        finally:
            conn.close()

    def execute(self, db_path: str, query: str, params: tuple = ()) -> list:
        """Execute a query and return all results."""
        conn = self.connect(db_path)
        try:
            result = conn.execute(query, params).fetchall()
            conn.commit()
            return result
        finally:
            conn.close()

    def execute_one(self, db_path: str, query: str, params: tuple = ()) -> Optional[Any]:
        """Execute a query and return one result."""
        conn = self.connect(db_path)
        try:
            result = conn.execute(query, params).fetchone()
            conn.commit()
            return result
        finally:
            conn.close()

    def execute_write(self, db_path: str, query: str, params: tuple = ()) -> int:
        """Execute an INSERT/UPDATE/DELETE and return affected rows."""
        conn = self.connect(db_path)
        try:
            cursor = conn.execute(query, params)
            conn.commit()
            return cursor.rowcount if hasattr(cursor, 'rowcount') else 0
        finally:
            conn.close()

    @property
    def backend(self) -> str:
        return "postgresql" if self.is_postgres else "sqlite"

    def health_check(self) -> dict:
        """Check database connectivity."""
        try:
            if self.is_postgres:
                conn = self.connect()
                conn.execute("SELECT 1")
                conn.close()
            return {
                "status": "healthy",
                "backend": self.backend,
                "url": self._mask_url(self.database_url) if self.is_postgres else "local",
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "backend": self.backend,
                "error": str(e),
            }


# Singleton instance
db = DatabaseManager()

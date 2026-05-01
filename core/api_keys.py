"""
APIGuard Enterprise — API Key Management
==========================================
Allows users to generate, revoke, and validate API keys for programmatic access.
Keys are hashed with SHA-256 before storage (never stored in plaintext).

Usage:
    from core.api_keys import api_key_manager

    key = api_key_manager.create(user_id, name="CI Pipeline")
    user = api_key_manager.validate("ag_live_abc123...")
    api_key_manager.revoke(key_id, user_id)
"""

import hashlib
import secrets
import sqlite3
import time
from typing import Optional

from core.config import settings
from core.logging_config import get_logger

logger = get_logger("api_keys")

DB_FILE = settings.AUTH_DB
PREFIX = "ag_live_"


def _hash_key(raw_key: str) -> str:
    """SHA-256 hash of the raw key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _init_table():
    """Ensure the api_keys table exists."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            key_hash TEXT UNIQUE NOT NULL,
            key_prefix TEXT NOT NULL,
            scopes TEXT DEFAULT '*',
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            expires_at TEXT,
            revoked INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

_init_table()


class APIKeyManager:
    """
    Manages API key lifecycle: creation, validation, revocation, and listing.
    
    Security Design:
    - Raw keys are 32-byte hex (64 chars) prefixed with 'ag_live_'
    - Only SHA-256 hash is stored in DB
    - User sees the full key only once (at creation)
    - Keys can have scopes: '*' (full), 'scan', 'read', 'ci'
    - Keys can have optional expiration
    """

    def create(self, user_id: str, name: str, scopes: str = "*",
               expires_days: Optional[int] = None) -> dict:
        """
        Create a new API key for a user.
        Returns the raw key (shown only once) and key metadata.
        """
        raw_key = PREFIX + secrets.token_hex(32)
        key_hash = _hash_key(raw_key)
        key_prefix = raw_key[:16] + "..."
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        expires_at = None
        if expires_days:
            expires_at = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(time.time() + expires_days * 86400)
            )

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute(
            """INSERT INTO api_keys (user_id, name, key_hash, key_prefix, scopes, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, key_hash, key_prefix, scopes, now, expires_at)
        )
        key_id = c.lastrowid
        conn.commit()
        conn.close()

        logger.info("api_key_created", user_id=user_id, name=name, key_id=key_id)

        return {
            "id": key_id,
            "name": name,
            "key": raw_key,          # ← shown only once!
            "prefix": key_prefix,
            "scopes": scopes,
            "created_at": now,
            "expires_at": expires_at,
        }

    def validate(self, raw_key: str) -> Optional[dict]:
        """
        Validate an API key and return the associated user info.
        Returns None if key is invalid, expired, or revoked.
        """
        if not raw_key or not raw_key.startswith(PREFIX):
            return None

        key_hash = _hash_key(raw_key)
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            """SELECT ak.id, ak.user_id, ak.name, ak.scopes, ak.expires_at, ak.revoked,
                      u.email, u.name as user_name, u.role
               FROM api_keys ak
               JOIN users u ON u.id = ak.user_id
               WHERE ak.key_hash = ?""",
            (key_hash,)
        )
        row = c.fetchone()

        if not row:
            conn.close()
            return None

        # Check revoked
        if row["revoked"]:
            conn.close()
            return None

        # Check expiration
        if row["expires_at"]:
            exp = time.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
            if time.mktime(exp) < time.time():
                conn.close()
                return None

        # Update last_used_at
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        c.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now, row["id"]))
        conn.commit()
        conn.close()

        return {
            "key_id": row["id"],
            "user_id": row["user_id"],
            "email": row["email"],
            "name": row["user_name"],
            "role": row["role"],
            "scopes": row["scopes"],
            "key_name": row["name"],
        }

    def list_keys(self, user_id: str) -> list:
        """List all API keys for a user (without the actual key values)."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT id, name, key_prefix, scopes, created_at, last_used_at, expires_at, revoked
               FROM api_keys WHERE user_id = ? ORDER BY id DESC""",
            (user_id,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def revoke(self, key_id: int, user_id: str) -> bool:
        """Revoke an API key. Only the owning user can revoke."""
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute(
            "UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?",
            (key_id, user_id)
        )
        affected = c.rowcount
        conn.commit()
        conn.close()

        if affected > 0:
            logger.info("api_key_revoked", key_id=key_id, user_id=user_id)
            return True
        return False

    def delete(self, key_id: int, user_id: str) -> bool:
        """Permanently delete an API key."""
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute(
            "DELETE FROM api_keys WHERE id = ? AND user_id = ?",
            (key_id, user_id)
        )
        affected = c.rowcount
        conn.commit()
        conn.close()
        return affected > 0


# Singleton
api_key_manager = APIKeyManager()

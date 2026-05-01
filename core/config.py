"""
APIGuard - Centralized Configuration
======================================
All environment-based configuration lives here.
Uses pydantic-like patterns for validation with python-dotenv for .env file loading.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int = 0) -> int:
    return int(os.environ.get(key, str(default)))


def _env_bool(key: str, default: bool = False) -> bool:
    return os.environ.get(key, str(default)).lower() in ("true", "1", "yes")


def _env_list(key: str, default: str = "") -> list[str]:
    raw = os.environ.get(key, default)
    return [s.strip() for s in raw.split(",") if s.strip()] if raw else []


@dataclass(frozen=True)
class AppConfig:
    """Immutable application configuration loaded from environment variables."""

    # ── App Metadata ──────────────────────────────
    APP_NAME: str = "APIGuard"
    APP_VERSION: str = "4.0.0"
    ENV: str = _env("APIGUARD_ENV", "development")
    DEBUG: bool = _env_bool("APIGUARD_DEBUG", True)

    # ── Server ────────────────────────────────────
    HOST: str = _env("APIGUARD_HOST", "0.0.0.0")
    PORT: int = _env_int("APIGUARD_PORT", 8000)

    # ── Security ──────────────────────────────────
    JWT_SECRET_KEY: str = _env("APIGUARD_JWT_SECRET", "apiguard-change-this-secret-in-production-2026")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = _env_int("APIGUARD_JWT_EXPIRE_MINUTES", 60)
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = _env_int("APIGUARD_JWT_REFRESH_DAYS", 7)
    BCRYPT_ROUNDS: int = _env_int("APIGUARD_BCRYPT_ROUNDS", 12)

    # ── CORS ──────────────────────────────────────
    CORS_ORIGINS: list[str] = field(default_factory=lambda: _env_list(
        "APIGUARD_CORS_ORIGINS",
        "http://localhost:3000,http://localhost:3001,http://localhost:8000"
    ))

    # ── Rate Limiting ─────────────────────────────
    RATE_LIMIT_DEFAULT: str = _env("APIGUARD_RATE_LIMIT", "60/minute")
    RATE_LIMIT_SCAN: str = _env("APIGUARD_RATE_LIMIT_SCAN", "10/minute")

    # ── Database ──────────────────────────────────
    HISTORY_DB: str = _env("APIGUARD_DB", "apiguard_history.db")
    AUTH_DB: str = _env("APIGUARD_AUTH_DB", "apiguard_auth.db")

    # ── Webhooks ──────────────────────────────────
    WEBHOOK_SLACK_URL: str = _env("APIGUARD_WEBHOOK_SLACK", "")
    WEBHOOK_DISCORD_URL: str = _env("APIGUARD_WEBHOOK_DISCORD", "")
    WEBHOOK_TEAMS_URL: str = _env("APIGUARD_WEBHOOK_TEAMS", "")
    WEBHOOK_EMAIL_SMTP_HOST: str = _env("APIGUARD_SMTP_HOST", "")
    WEBHOOK_EMAIL_SMTP_PORT: int = _env_int("APIGUARD_SMTP_PORT", 587)
    WEBHOOK_EMAIL_FROM: str = _env("APIGUARD_EMAIL_FROM", "")
    WEBHOOK_EMAIL_TO: str = _env("APIGUARD_EMAIL_TO", "")
    WEBHOOK_EMAIL_PASSWORD: str = _env("APIGUARD_EMAIL_PASSWORD", "")
    WEBHOOK_MIN_SEVERITY: str = _env("APIGUARD_WEBHOOK_MIN_SEVERITY", "HIGH")

    # ── Scanner Defaults ──────────────────────────
    SCAN_TIMEOUT: int = _env_int("APIGUARD_SCAN_TIMEOUT", 10)
    SCAN_DELAY: float = float(_env("APIGUARD_SCAN_DELAY", "0.1"))
    SCAN_RATE_REQUESTS: int = _env_int("APIGUARD_SCAN_RATE_REQUESTS", 50)


# Singleton configuration instance
settings = AppConfig()

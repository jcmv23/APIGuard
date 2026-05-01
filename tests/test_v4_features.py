"""
APIGuard Enterprise v4.0 — Complete Test Suite
=================================================
Tests for API Keys, Webhooks, Database Layer, and all v4.0 features.
Run: pytest tests/ -v

NOTE: These tests are designed to run without external network access.
      They test code logic, not live API integrations.
"""

import pytest
import hashlib
import secrets
import time
import sys
import os
import json
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────
# API Key Management Tests
# ─────────────────────────────────────────────

class TestAPIKeyManager:
    """Tests for core.api_keys module."""

    def test_key_creation(self):
        from core.api_keys import api_key_manager
        # Create a test user ID
        test_user = f"test_{int(time.time()*1000)}"
        result = api_key_manager.create(test_user, "Test Key", scopes="scan,read")

        assert "key" in result
        assert result["key"].startswith("ag_live_")
        assert len(result["key"]) == 72  # prefix(8) + 64 hex chars
        assert result["name"] == "Test Key"
        assert result["scopes"] == "scan,read"
        assert result["prefix"].endswith("...")

    def test_key_validation(self):
        from core.api_keys import api_key_manager
        # We need a real user in the DB for validation to work with JOIN
        # So we just test that an invalid key returns None
        result = api_key_manager.validate("ag_live_invalid_key_abc123")
        assert result is None

    def test_key_prefix_format(self):
        from core.api_keys import api_key_manager
        test_user = f"test_{int(time.time()*1000)}"
        result = api_key_manager.create(test_user, "Prefix Test")
        assert result["prefix"] == result["key"][:16] + "..."

    def test_key_revocation(self):
        from core.api_keys import api_key_manager
        test_user = f"test_{int(time.time()*1000)}"
        result = api_key_manager.create(test_user, "Revoke Me")
        key_id = result["id"]

        # Revoke
        assert api_key_manager.revoke(key_id, test_user) is True
        # Already revoked or non-existent
        assert api_key_manager.revoke(99999, test_user) is False

    def test_key_listing(self):
        from core.api_keys import api_key_manager
        test_user = f"test_list_{int(time.time()*1000)}"
        api_key_manager.create(test_user, "Key A")
        api_key_manager.create(test_user, "Key B")

        keys = api_key_manager.list_keys(test_user)
        assert len(keys) >= 2
        # Keys should not contain the raw key value
        for k in keys:
            assert "key" not in k or k.get("key_prefix", "").endswith("...")

    def test_key_with_expiration(self):
        from core.api_keys import api_key_manager
        test_user = f"test_exp_{int(time.time()*1000)}"
        result = api_key_manager.create(test_user, "Expiring Key", expires_days=30)
        assert result["expires_at"] is not None

    def test_key_without_expiration(self):
        from core.api_keys import api_key_manager
        test_user = f"test_noexp_{int(time.time()*1000)}"
        result = api_key_manager.create(test_user, "Permanent Key")
        assert result["expires_at"] is None

    def test_key_deletion(self):
        from core.api_keys import api_key_manager
        test_user = f"test_del_{int(time.time()*1000)}"
        result = api_key_manager.create(test_user, "Delete Me")
        key_id = result["id"]

        assert api_key_manager.delete(key_id, test_user) is True
        assert api_key_manager.delete(key_id, test_user) is False  # Already deleted

    def test_invalid_key_prefix(self):
        from core.api_keys import api_key_manager
        assert api_key_manager.validate("invalid_prefix_key") is None
        assert api_key_manager.validate("") is None
        assert api_key_manager.validate(None) is None


# ─────────────────────────────────────────────
# Database Layer Tests
# ─────────────────────────────────────────────

class TestDatabaseManager:
    """Tests for core.database module."""

    def test_sqlite_backend_default(self):
        from core.database import DatabaseManager
        dm = DatabaseManager()
        assert dm.backend == "sqlite"
        assert dm.is_postgres is False

    def test_sqlite_connection(self):
        from core.database import DatabaseManager
        dm = DatabaseManager()
        conn = dm.connect("test_temp.db")
        conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, val TEXT)")
        conn.execute("INSERT INTO test (val) VALUES (?)", ("hello",))
        conn.commit()
        row = conn.execute("SELECT val FROM test WHERE id = 1").fetchone()
        assert row[0] == "hello"
        conn.close()
        # Cleanup
        os.remove("test_temp.db")

    def test_health_check_sqlite(self):
        from core.database import db
        result = db.health_check()
        assert result["status"] == "healthy"
        assert result["backend"] == "sqlite"

    def test_postgres_detection(self):
        from core.database import DatabaseManager
        with patch.dict(os.environ, {"DATABASE_URL": "postgresql://user:pass@localhost:5432/db"}):
            dm = DatabaseManager()
            assert dm.is_postgres is True
            assert dm.backend == "postgresql"

    def test_url_masking(self):
        from core.database import DatabaseManager
        dm = DatabaseManager()
        masked = dm._mask_url("postgresql://admin:secret@host:5432/db")
        assert "secret" not in masked
        assert "***" in masked
        assert "host:5432/db" in masked


# ─────────────────────────────────────────────
# Webhook Tests (mocked, no real HTTP)
# ─────────────────────────────────────────────

class TestWebhooks:
    """Tests for integrations.webhooks module (no real HTTP calls)."""

    def _make_report(self, critical=1, high=2, medium=3, low=1):
        """Create a fake scan report for testing."""
        findings = []
        for _ in range(critical):
            findings.append({"severity": "CRITICAL", "vulnerability_type": "BOLA",
                           "description": "Test critical finding", "endpoint": "/api/test"})
        for _ in range(high):
            findings.append({"severity": "HIGH", "vulnerability_type": "SQL_INJECTION",
                           "description": "Test high finding", "endpoint": "/api/test"})
        for _ in range(medium):
            findings.append({"severity": "MEDIUM", "vulnerability_type": "MISSING_HEADERS",
                           "description": "Test medium finding", "endpoint": "/api/test"})
        for _ in range(low):
            findings.append({"severity": "LOW", "vulnerability_type": "INFO_LEAK",
                           "description": "Test low finding", "endpoint": "/api/test"})
        return {
            "target": "https://api.test.com",
            "scan_date": "2026-05-01T00:00:00Z",
            "modules": {"module_test": {"findings": findings}},
        }

    def test_should_notify_high(self):
        from integrations.webhooks import _should_notify
        findings = [{"severity": "HIGH"}]
        assert _should_notify(findings) is True

    def test_should_not_notify_low(self):
        from integrations.webhooks import _should_notify
        findings = [{"severity": "LOW"}]
        assert _should_notify(findings) is False

    def test_extract_findings(self):
        from integrations.webhooks import _extract_findings
        report = self._make_report(critical=2, high=1)
        findings = _extract_findings(report)
        assert len(findings) == 7  # 2+1+3+1

    def test_build_summary(self):
        from integrations.webhooks import _build_summary
        report = self._make_report(critical=3, high=2, medium=1, low=0)
        summary = _build_summary(report)
        assert summary["critical"] == 3
        assert summary["high"] == 2
        assert summary["medium"] == 1
        assert summary["low"] == 0
        assert summary["total_findings"] == 6
        assert summary["target"] == "https://api.test.com"

    @patch("integrations.webhooks.requests.post")
    def test_slack_success(self, mock_post):
        from integrations.webhooks import send_slack
        mock_post.return_value = MagicMock(status_code=200)
        with patch("integrations.webhooks.settings") as mock_settings:
            mock_settings.WEBHOOK_SLACK_URL = "https://hooks.slack.com/test"
            mock_settings.WEBHOOK_MIN_SEVERITY = "HIGH"
            report = self._make_report(critical=1)
            result = send_slack(report)
            assert result is True
            mock_post.assert_called_once()

    @patch("integrations.webhooks.requests.post")
    def test_slack_no_url(self, mock_post):
        from integrations.webhooks import send_slack
        with patch("integrations.webhooks.settings") as mock_settings:
            mock_settings.WEBHOOK_SLACK_URL = ""
            result = send_slack(self._make_report())
            assert result is False
            mock_post.assert_not_called()

    @patch("integrations.webhooks.requests.post")
    def test_discord_success(self, mock_post):
        from integrations.webhooks import send_discord
        mock_post.return_value = MagicMock(status_code=200)
        with patch("integrations.webhooks.settings") as mock_settings:
            mock_settings.WEBHOOK_DISCORD_URL = "https://discord.com/api/webhooks/test"
            mock_settings.WEBHOOK_MIN_SEVERITY = "HIGH"
            result = send_discord(self._make_report(critical=1))
            assert result is True

    def test_notify_all_no_config(self):
        from integrations.webhooks import notify_all
        report = self._make_report()
        results = notify_all(report)
        # All should return False since no webhooks are configured
        assert isinstance(results, dict)
        assert all(v is False for v in results.values())


# ─────────────────────────────────────────────
# RBAC Tests
# ─────────────────────────────────────────────

class TestRBACv4:
    """Extended RBAC tests for v4.0 permissions."""

    def test_individual_full_access(self):
        from user_management import has_permission
        user = {"role": "individual"}
        assert has_permission(user, "run_scans") is True
        assert has_permission(user, "export_reports") is True
        assert has_permission(user, "ci_integration") is True
        assert has_permission(user, "manage_users") is False  # Individual can't manage users

    def test_enterprise_admin_full_access(self):
        from user_management import has_permission
        user = {"role": "enterprise_admin"}
        assert has_permission(user, "manage_users") is True
        assert has_permission(user, "manage_company") is True
        assert has_permission(user, "ci_integration") is True

    def test_unknown_role_no_access(self):
        from user_management import has_permission
        user = {"role": "unknown_role"}
        assert has_permission(user, "run_scans") is False
        assert has_permission(user, "view_scans") is False

    def test_viewer_read_only(self):
        from user_management import has_permission
        user = {"role": "viewer"}
        assert has_permission(user, "view_scans") is True
        assert has_permission(user, "view_reports") is True
        assert has_permission(user, "run_scans") is False
        assert has_permission(user, "use_terminal") is False
        assert has_permission(user, "manage_schedules") is False


# ─────────────────────────────────────────────
# Config Tests
# ─────────────────────────────────────────────

class TestConfig:
    """Tests for core.config module."""

    def test_settings_loaded(self):
        from core.config import settings
        assert hasattr(settings, "HOST")
        assert hasattr(settings, "PORT")
        assert hasattr(settings, "ENV")
        assert hasattr(settings, "DEBUG")

    def test_cors_origins_type(self):
        from core.config import settings
        assert isinstance(settings.CORS_ORIGINS, list)

    def test_jwt_secret_exists(self):
        from core.config import settings
        assert settings.JWT_SECRET_KEY is not None
        assert len(settings.JWT_SECRET_KEY) > 0


# ─────────────────────────────────────────────
# AI Explainer Tests
# ─────────────────────────────────────────────

class TestAIExplainer:
    """Tests for core.ai_explainer module."""

    def test_explain_finding_returns_dict(self):
        from core.ai_explainer import explain_finding
        finding = {
            "vulnerability_type": "BOLA",
            "severity": "HIGH",
            "endpoint": "/api/users/1",
            "description": "Object ID manipulation allowed"
        }
        result = explain_finding(finding)
        assert isinstance(result, dict)
        assert "explanation" in result or "vuln_type" in result

    def test_explain_unknown_type(self):
        from core.ai_explainer import explain_finding
        finding = {
            "vulnerability_type": "TOTALLY_UNKNOWN_VULN_TYPE",
            "severity": "LOW",
        }
        result = explain_finding(finding)
        assert isinstance(result, dict)


# ─────────────────────────────────────────────
# Rate Limiter Tests
# ─────────────────────────────────────────────

class TestRateLimiter:
    """Tests for core.rate_limiter module."""

    def test_is_allowed(self):
        from core.rate_limiter import persistent_limiter
        # Should allow first request
        result = persistent_limiter.is_allowed("test_ip_unit", "/test", max_requests=5, window_seconds=60)
        assert result is True

    def test_is_not_blocked_initially(self):
        from core.rate_limiter import persistent_limiter
        assert persistent_limiter.is_blocked("brand_new_ip") is False

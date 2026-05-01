"""
APIGuard Enterprise — Automated Test Suite
============================================
Comprehensive tests for all modules, endpoints, and enterprise features.
Run: pytest tests/ -v
"""

import pytest
import requests
import json
import time
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = "http://127.0.0.1:8000"
TOKEN = None


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def setup_auth():
    """Register a test user and get a token for authenticated tests."""
    global TOKEN
    email = f"test_{int(time.time())}@apiguard.test"
    r = requests.post(f"{BASE}/api/auth/register/individual", json={
        "email": email, "password": "TestPass123!", "name": "Test User"
    })
    if r.status_code == 200:
        TOKEN = r.json().get("access_token")
    elif r.status_code == 400:  # Already exists
        r = requests.post(f"{BASE}/api/auth/login", json={
            "email": email, "password": "TestPass123!"
        })
        if r.status_code == 200:
            TOKEN = r.json().get("access_token")
    yield
    # Cleanup not needed for SQLite test


def auth_headers():
    return {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}


# ─────────────────────────────────────────────
# Health & Core
# ─────────────────────────────────────────────

class TestHealth:
    def test_health_endpoint(self):
        r = requests.get(f"{BASE}/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_docs_available(self):
        r = requests.get(f"{BASE}/docs")
        assert r.status_code == 200


# ─────────────────────────────────────────────
# Authentication
# ─────────────────────────────────────────────

class TestAuth:
    def test_register_individual(self):
        email = f"ind_{int(time.time()*1000)}@test.com"
        r = requests.post(f"{BASE}/api/auth/register/individual", json={
            "email": email, "password": "Secure123!", "name": "Individual"
        })
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_register_duplicate_fails(self):
        email = f"dup_{int(time.time()*1000)}@test.com"
        requests.post(f"{BASE}/api/auth/register/individual", json={
            "email": email, "password": "Pass123!", "name": "First"
        })
        r = requests.post(f"{BASE}/api/auth/register/individual", json={
            "email": email, "password": "Pass123!", "name": "Second"
        })
        assert r.status_code == 400

    def test_login_success(self):
        email = f"login_{int(time.time()*1000)}@test.com"
        requests.post(f"{BASE}/api/auth/register/individual", json={
            "email": email, "password": "Pass123!", "name": "LoginUser"
        })
        r = requests.post(f"{BASE}/api/auth/login", json={
            "email": email, "password": "Pass123!"
        })
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_login_wrong_password(self):
        email = f"wrong_{int(time.time()*1000)}@test.com"
        requests.post(f"{BASE}/api/auth/register/individual", json={
            "email": email, "password": "Pass123!", "name": "WrongPassUser"
        })
        r = requests.post(f"{BASE}/api/auth/login", json={
            "email": email, "password": "WrongPassword"
        })
        assert r.status_code == 401

    def test_me_with_token(self):
        r = requests.get(f"{BASE}/api/auth/me", headers=auth_headers())
        assert r.status_code == 200
        data = r.json()
        assert "email" in data

    def test_me_without_token(self):
        r = requests.get(f"{BASE}/api/auth/me")
        assert r.status_code == 401


# ─────────────────────────────────────────────
# Scans
# ─────────────────────────────────────────────

class TestScans:
    def test_list_scans(self):
        r = requests.get(f"{BASE}/api/v1/scans")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_async_scan_returns_202(self):
        r = requests.post(f"{BASE}/api/v1/scan", json={
            "url": "http://localhost:9999",
            "modules": ["ssl"],
            "timeout": 2,
            "notify": False
        })
        assert r.status_code == 202
        assert "scan_id" in r.json()

    def test_sync_scan_returns_report(self):
        r = requests.post(f"{BASE}/api/v1/scan/sync", json={
            "url": "http://localhost:9999",
            "modules": ["ssl"],
            "timeout": 2,
            "notify": False
        })
        assert r.status_code == 200
        data = r.json()
        assert "modules" in data
        assert "module_8_ssl" in data["modules"]

    def test_get_nonexistent_scan(self):
        r = requests.get(f"{BASE}/api/v1/scan/nonexistent_id_xyz")
        assert r.status_code == 404


# ─────────────────────────────────────────────
# Scheduler
# ─────────────────────────────────────────────

class TestScheduler:
    def test_create_schedule(self):
        r = requests.post(f"{BASE}/api/v1/schedules", json={
            "name": "Test Schedule",
            "target_url": "https://api.test.com",
            "cron_expr": "0 3 * * *"
        })
        assert r.status_code == 201
        assert "id" in r.json()

    def test_list_schedules(self):
        r = requests.get(f"{BASE}/api/v1/schedules")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_delete_schedule(self):
        # Create then delete
        r = requests.post(f"{BASE}/api/v1/schedules", json={
            "name": "Delete Me", "target_url": "https://example.com"
        })
        sched_id = r.json()["id"]
        r2 = requests.delete(f"{BASE}/api/v1/schedules/{sched_id}")
        assert r2.status_code == 200


# ─────────────────────────────────────────────
# Remediation
# ─────────────────────────────────────────────

class TestRemediation:
    def test_list_findings(self):
        r = requests.get(f"{BASE}/api/v1/findings")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_metrics(self):
        r = requests.get(f"{BASE}/api/v1/metrics")
        assert r.status_code == 200
        data = r.json()
        assert "mttr_hours" in data
        assert "security_debt_score" in data
        assert "resolution_rate" in data


# ─────────────────────────────────────────────
# Custom Rules
# ─────────────────────────────────────────────

class TestRules:
    def test_list_rules(self):
        r = requests.get(f"{BASE}/api/v1/rules")
        assert r.status_code == 200
        rules = r.json()
        assert isinstance(rules, list)
        assert len(rules) >= 4  # 4 default rules

    def test_create_rule(self):
        r = requests.post(f"{BASE}/api/v1/rules", json={
            "name": "Test Custom Rule",
            "yaml_content": "name: test\ncondition:\n  type: response_contains_field\n  fields: [test]\nmessage: Test rule",
            "severity": "LOW"
        })
        assert r.status_code == 200
        assert "id" in r.json()

    def test_create_invalid_rule(self):
        r = requests.post(f"{BASE}/api/v1/rules", json={
            "name": "Bad Rule",
            "yaml_content": "name: bad\nno_condition: true",
            "severity": "HIGH"
        })
        assert r.status_code == 400

    def test_toggle_rule(self):
        rules = requests.get(f"{BASE}/api/v1/rules").json()
        if rules:
            r = requests.patch(f"{BASE}/api/v1/rules/{rules[0]['id']}/toggle?enabled=false")
            assert r.status_code == 200
            # Re-enable
            requests.patch(f"{BASE}/api/v1/rules/{rules[0]['id']}/toggle?enabled=true")


# ─────────────────────────────────────────────
# API Discovery
# ─────────────────────────────────────────────

class TestDiscovery:
    def test_discover_self(self):
        """Discover APIGuard's own API."""
        r = requests.post(f"{BASE}/api/v1/discover?url=http://127.0.0.1:8000")
        assert r.status_code == 200
        data = r.json()
        assert data["total_probed"] > 0
        assert data["total_found"] > 0


# ─────────────────────────────────────────────
# CI/CD
# ─────────────────────────────────────────────

class TestCICD:
    def test_ci_scan_returns_sarif(self):
        r = requests.post(f"{BASE}/api/v1/ci/scan", json={
            "url": "http://localhost:9999",
            "modules": "ssl",
            "timeout": 2
        })
        assert r.status_code == 200
        data = r.json()
        assert "exit_code" in data
        assert "sarif" in data
        assert data["sarif"]["version"] == "2.1.0"


# ─────────────────────────────────────────────
# Scan Compare
# ─────────────────────────────────────────────

class TestCompare:
    def test_compare_nonexistent(self):
        r = requests.post(f"{BASE}/api/v1/scan/compare", json={
            "scan_id_before": 99999, "scan_id_after": 99998
        })
        assert r.status_code == 404


# ─────────────────────────────────────────────
# Terminal
# ─────────────────────────────────────────────

class TestTerminal:
    def test_execute_command(self):
        r = requests.post(f"{BASE}/api/terminal/execute", json={"command": "help"})
        assert r.status_code == 200
        assert "output" in r.json()

    def test_modules_command(self):
        r = requests.post(f"{BASE}/api/terminal/execute", json={"command": "modules"})
        assert r.status_code == 200
        assert len(r.json()["output"]) > 0


# ─────────────────────────────────────────────
# Parser Probe Mode
# ─────────────────────────────────────────────

class TestParser:
    def test_probe_mode_finds_endpoints(self):
        """Ensure parser finds endpoints — via spec or probing."""
        from module_1_parser.parser import OpenAPIParser
        parser = OpenAPIParser(base_url="http://127.0.0.1:8000", timeout=3)
        endpoints = parser.parse()
        assert len(endpoints) > 0
        # APIGuard has an OpenAPI spec, so parser should find it
        assert parser._spec_version in ("probed", "3.1.0", "3.0.3", "3.0.0", "2.0")

    def test_parser_with_invalid_url(self):
        from module_1_parser.parser import OpenAPIParser
        parser = OpenAPIParser(base_url="http://localhost:19999", timeout=2)
        endpoints = parser.parse()
        # Should not crash, just return empty
        assert isinstance(endpoints, list)


# ─────────────────────────────────────────────
# RBAC
# ─────────────────────────────────────────────

class TestRBAC:
    def test_viewer_permissions(self):
        from user_management import has_permission
        viewer = {"role": "viewer"}
        assert has_permission(viewer, "view_scans") is True
        assert has_permission(viewer, "run_scans") is False
        assert has_permission(viewer, "manage_users") is False

    def test_analyst_permissions(self):
        from user_management import has_permission
        analyst = {"role": "analyst"}
        assert has_permission(analyst, "view_scans") is True
        assert has_permission(analyst, "run_scans") is True
        assert has_permission(analyst, "manage_users") is False

    def test_admin_permissions(self):
        from user_management import has_permission
        admin = {"role": "admin"}
        assert has_permission(admin, "view_scans") is True
        assert has_permission(admin, "run_scans") is True
        assert has_permission(admin, "manage_users") is True
        assert has_permission(admin, "ci_integration") is True

"""
Tests for Module 3 - BFLA Scanner
Run: python -m pytest test_bfla.py -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock, patch
import pytest

from module_3_bfla.bfla_scanner import (
    BFLAScanner, BFLAFinding, BFLAScanResult, Severity,
    is_admin_endpoint, ADMIN_PATH_PATTERNS,
)
from module_1_parser.parser import Endpoint, Parameter


# ── Fixtures ──────────────────────────────────────────────────

def make_endpoint(path="/admin/users/{userId}", method="DELETE", tags=None):
    return Endpoint(
        method=method,
        path=path,
        full_url=f"https://api.example.com{path}",
        summary="Admin operation",
        tags=tags or ["admin"],
    )


def mock_response(status_code: int, body: str = '{"ok":true}'):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = body
    return resp


def make_scanner():
    return BFLAScanner(
        low_priv_token="Bearer low-priv-token",
        low_priv_username="john_user",
    )


# ── Admin endpoint detection ──────────────────────────────────

class TestAdminEndpointDetection:
    def test_admin_in_path(self):
        ep = make_endpoint("/admin/settings")
        assert is_admin_endpoint(ep) is True

    def test_internal_in_path(self):
        ep = make_endpoint("/internal/config")
        assert is_admin_endpoint(ep) is True

    def test_system_in_path(self):
        ep = make_endpoint("/system/status")
        assert is_admin_endpoint(ep) is True

    def test_admin_tag(self):
        ep = Endpoint(method="GET", path="/config", full_url="https://x.com/config",
                      summary="", tags=["administration"])
        assert is_admin_endpoint(ep) is True

    def test_delete_reset_endpoint(self):
        ep = make_endpoint("/users/{id}/reset", method="DELETE", tags=[])
        assert is_admin_endpoint(ep) is True

    def test_delete_method_with_sensitive_word(self):
        ep = make_endpoint("/data/purge", method="DELETE", tags=[])
        assert is_admin_endpoint(ep) is True

    def test_normal_get_not_admin(self):
        ep = Endpoint(method="GET", path="/users", full_url="https://x.com/users",
                      summary="", tags=["users"])
        assert is_admin_endpoint(ep) is False

    def test_normal_post_not_admin(self):
        ep = Endpoint(method="POST", path="/users", full_url="https://x.com/users",
                      summary="", tags=[])
        assert is_admin_endpoint(ep) is False

    def test_patch_on_non_sensitive_path(self):
        ep = Endpoint(method="PATCH", path="/users/{id}", full_url="https://x.com/users/1",
                      summary="", tags=[])
        # PATCH alone without sensitive word should not flag
        assert is_admin_endpoint(ep) is False


# ── BFLA Detection ────────────────────────────────────────────

class TestBFLADetection:

    @patch("requests.Session.delete")
    def test_detects_bfla_when_delete_returns_200(self, mock_delete):
        mock_delete.return_value = mock_response(200)
        scanner = make_scanner()
        result = scanner.scan([make_endpoint(method="DELETE")])

        assert result.vulnerable_endpoints == 1
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.vulnerability_type == "BFLA"
        assert finding.severity == Severity.CRITICAL
        assert "john_user" in finding.proof

    @patch("requests.Session.delete")
    def test_no_finding_when_delete_returns_403(self, mock_delete):
        mock_delete.return_value = mock_response(403)
        scanner = make_scanner()
        result = scanner.scan([make_endpoint(method="DELETE")])
        assert result.vulnerable_endpoints == 0

    @patch("requests.Session.delete")
    def test_no_finding_when_delete_returns_401(self, mock_delete):
        mock_delete.return_value = mock_response(401)
        scanner = make_scanner()
        result = scanner.scan([make_endpoint(method="DELETE")])
        assert result.vulnerable_endpoints == 0

    @patch("requests.Session.get")
    def test_detects_bfla_on_admin_get(self, mock_get):
        mock_get.return_value = mock_response(200)
        scanner = make_scanner()
        ep = make_endpoint("/admin/users", method="GET", tags=["admin"])
        result = scanner.scan([ep])
        assert result.vulnerable_endpoints == 1
        assert result.findings[0].severity == Severity.HIGH

    @patch("requests.Session.delete")
    def test_skips_non_admin_endpoints(self, mock_delete):
        scanner = make_scanner()
        ep = Endpoint(method="DELETE", path="/users/{id}",
                      full_url="https://x.com/users/1", summary="", tags=[])
        # DELETE on /users/{id} alone is not flagged as admin
        result = scanner.scan([ep])
        mock_delete.assert_not_called()

    @patch("requests.Session.delete")
    def test_handles_network_error_gracefully(self, mock_delete):
        import requests as req
        mock_delete.side_effect = req.RequestException("Connection refused")
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        assert result.vulnerable_endpoints == 0

    @patch("requests.Session.delete")
    def test_two_phase_check_skips_dead_endpoint(self, mock_delete):
        """When admin_token is provided and admin gets 404, skip the endpoint."""
        mock_delete.return_value = mock_response(404)
        scanner = BFLAScanner(
            low_priv_token="Bearer low",
            admin_token="Bearer admin",
        )
        with patch.object(scanner.admin_session, "delete", return_value=mock_response(404)):
            result = scanner.scan([make_endpoint()])
        assert result.vulnerable_endpoints == 0

    @patch("requests.Session.delete")
    def test_result_to_dict(self, mock_delete):
        mock_delete.return_value = mock_response(200)
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        d = result.to_dict()
        assert d["scan_type"] == "BFLA"
        assert d["vulnerable_endpoints"] == 1
        assert d["findings"][0]["severity"] == "CRITICAL"

    @patch("requests.Session.delete")
    def test_summary_with_finding(self, mock_delete):
        mock_delete.return_value = mock_response(200)
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        s = result.summary()
        assert "CRITICAL" in s
        assert "admin" in s.lower() or "DELETE" in s

    @patch("requests.Session.delete")
    def test_summary_no_vulns(self, mock_delete):
        mock_delete.return_value = mock_response(403)
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        assert "No BFLA vulnerabilities detected" in result.summary()

    @patch("requests.Session.delete")
    def test_finding_str_representation(self, mock_delete):
        mock_delete.return_value = mock_response(200)
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        s = str(result.findings[0])
        assert "BFLA" in s
        assert "CRITICAL" in s
        assert "Remediation" in s or "remediation" in s.lower()


class TestSeverityClassification:
    def test_delete_is_critical(self):
        scanner = make_scanner()
        ep = make_endpoint(method="DELETE")
        sev = scanner._classify_severity(ep)
        assert sev == Severity.CRITICAL

    def test_reset_endpoint_is_critical(self):
        scanner = make_scanner()
        ep = make_endpoint("/admin/db/reset", method="POST")
        sev = scanner._classify_severity(ep)
        assert sev == Severity.CRITICAL

    def test_admin_get_is_high(self):
        scanner = make_scanner()
        ep = make_endpoint("/admin/users", method="GET")
        sev = scanner._classify_severity(ep)
        assert sev == Severity.HIGH


class TestDummyBodyBuilding:
    def test_builds_body_from_schema(self):
        scanner = make_scanner()
        ep = make_endpoint(method="POST")
        ep.request_body_schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
                "active": {"type": "boolean"},
            }
        }
        body = scanner._build_dummy_body(ep)
        assert body["name"] == "test"
        assert body["age"] == 1
        assert body["active"] is False

    def test_returns_none_for_get(self):
        scanner = make_scanner()
        ep = make_endpoint(method="GET")
        assert scanner._build_dummy_body(ep) is None

    def test_returns_empty_dict_when_no_schema(self):
        scanner = make_scanner()
        ep = make_endpoint(method="POST")
        ep.request_body_schema = {}
        assert scanner._build_dummy_body(ep) == {}
"""
Tests for Module 2 - BOLA Scanner
Run: python -m pytest test_bola.py -v
Uses unittest.mock to simulate HTTP responses (no real network needed).
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock, patch
import pytest

from module_2_bola.bola_scanner import BOLAScanner, BOLAFinding, BOLAScanResult, Severity
from module_1_parser.parser import Endpoint, Parameter


# ── Fixtures ──────────────────────────────────────────────────

def make_endpoint(path="/users/{userId}", method="GET"):
    return Endpoint(
        method=method,
        path=path,
        full_url=f"https://api.example.com{path}",
        summary="Test endpoint",
        tags=["users"],
        parameters=[
            Parameter(name="userId", location="path", required=True,
                      param_type="integer", param_format="int64")
        ],
    )


def mock_response(status_code: int, body: str = '{"name":"Alice"}'):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = body
    return resp


def make_scanner():
    return BOLAScanner(
        token_user_a="Bearer test-token-user-a",
        id_user_a="123",
        id_user_b="456",
    )


# ── Tests ─────────────────────────────────────────────────────

class TestBOLADetection:

    @patch("requests.Session.get")
    def test_detects_bola_when_both_return_200(self, mock_get):
        # Both User A's resource and User B's resource return 200 → VULNERABLE
        mock_get.side_effect = [
            mock_response(200, '{"id":123,"name":"Alice"}'),   # user A's resource
            mock_response(200, '{"id":456,"name":"Bob"}'),     # user B's resource (leaked!)
        ]
        scanner = make_scanner()
        ep = make_endpoint()
        result = scanner.scan([ep])

        assert result.vulnerable_endpoints == 1
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.status_code_a == 200
        assert finding.status_code_b == 200
        assert "456" in finding.proof

    @patch("requests.Session.get")
    def test_no_finding_when_b_returns_403(self, mock_get):
        # User B's resource returns 403 → NOT vulnerable
        mock_get.side_effect = [
            mock_response(200, '{"id":123,"name":"Alice"}'),
            mock_response(403, '{"error":"Forbidden"}'),
        ]
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        assert result.vulnerable_endpoints == 0
        assert len(result.findings) == 0

    @patch("requests.Session.get")
    def test_no_finding_when_b_returns_404(self, mock_get):
        mock_get.side_effect = [
            mock_response(200, '{"id":123}'),
            mock_response(404, '{"error":"Not found"}'),
        ]
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        assert result.vulnerable_endpoints == 0

    @patch("requests.Session.get")
    def test_skips_post_endpoints(self, mock_get):
        # POST endpoints with path params are NOT tested (BOLA is for object reads)
        scanner = make_scanner()
        post_ep = make_endpoint(path="/users/{userId}", method="POST")
        result = scanner.scan([post_ep])
        mock_get.assert_not_called()
        assert result.total_endpoints_tested == 0

    @patch("requests.Session.get")
    def test_skips_non_resource_endpoints(self, mock_get):
        # Endpoint without path params (collection)
        ep = Endpoint(
            method="GET", path="/users",
            full_url="https://api.example.com/users",
            summary="List users", tags=["users"],
        )
        scanner = make_scanner()
        result = scanner.scan([ep])
        mock_get.assert_not_called()
        assert result.total_endpoints_tested == 0

    @patch("requests.Session.get")
    def test_handles_network_error_gracefully(self, mock_get):
        import requests as req
        mock_get.side_effect = req.RequestException("Connection refused")
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        # Should not raise, should log an error
        assert result.vulnerable_endpoints == 0

    @patch("requests.Session.get")
    def test_scans_multiple_endpoints(self, mock_get):
        responses = [
            mock_response(200), mock_response(200),   # ep1 → VULN
            mock_response(200), mock_response(403),   # ep2 → SAFE
            mock_response(200), mock_response(200),   # ep3 → VULN
        ]
        mock_get.side_effect = responses
        scanner = make_scanner()
        eps = [
            make_endpoint("/users/{userId}"),
            make_endpoint("/posts/{postId}"),
            make_endpoint("/orders/{orderId}"),
        ]
        result = scanner.scan(eps)
        assert result.total_endpoints_tested == 3
        assert result.vulnerable_endpoints == 2

    @patch("requests.Session.get")
    def test_finding_str_representation(self, mock_get):
        mock_get.side_effect = [mock_response(200), mock_response(200)]
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        s = str(result.findings[0])
        assert "BOLA" in s
        assert "CRITICAL" in s
        assert "remediation" in s.lower() or "Remediation" in s

    @patch("requests.Session.get")
    def test_result_to_dict(self, mock_get):
        mock_get.side_effect = [mock_response(200), mock_response(200)]
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        d = result.to_dict()
        assert d["scan_type"] == "BOLA"
        assert d["vulnerable_endpoints"] == 1
        assert isinstance(d["findings"], list)
        assert d["findings"][0]["severity"] == "CRITICAL"

    @patch("requests.Session.get")
    def test_summary_no_vulns(self, mock_get):
        mock_get.side_effect = [mock_response(200), mock_response(403)]
        scanner = make_scanner()
        result = scanner.scan([make_endpoint()])
        s = result.summary()
        assert "No BOLA vulnerabilities detected" in s


class TestBOLAScannerInit:
    def test_custom_headers_applied(self):
        scanner = BOLAScanner(
            token_user_a="Bearer tok",
            id_user_a="1",
            id_user_b="2",
            extra_headers={"X-Tenant": "acme"},
        )
        assert scanner.session.headers.get("X-Tenant") == "acme"

    def test_token_in_session_headers(self):
        scanner = make_scanner()
        assert scanner.session.headers.get("Authorization") == "Bearer test-token-user-a"

    def test_id_substitution(self):
        scanner = make_scanner()
        ep = make_endpoint("/items/{itemId}/sub/{subId}")
        url = scanner._substitute_id(ep.full_url, ep.path, "99")
        assert url == "https://api.example.com/items/99/sub/99"
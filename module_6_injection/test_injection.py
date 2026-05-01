"""
Tests for Module 6 - Injection/Secrets/CORS Scanner
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock, patch
import pytest

from module_6_injection.injection_scanner import InjectionScanner, InjFindingType
from module_1_parser.parser import Endpoint, Parameter

def make_endpoint(path="/data", method="GET"):
    return Endpoint(
        method=method,
        path=path,
        full_url=f"https://api.example.com{path}",
        summary="",
        tags=[],
        requires_auth=True
    )

def mock_response(status_code: int, text='{"ok": true}', headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    return resp

class TestInjectionScanner:
    @patch("requests.Session.get")
    def test_sql_injection_error_based(self, mock_get):
        mock_get.side_effect = [
            mock_response(200),  # Baseline
            mock_response(500, "you have an error in your sql syntax") # Injected
        ]
        scanner = InjectionScanner(test_cors=False, test_mass_assignment=False, test_secrets=False)
        ep = make_endpoint()
        ep.parameters = [Parameter("id", "query", False, "integer", "")]
        result = scanner.scan([ep])
        assert any(f.finding_type == InjFindingType.SQL_INJECTION for f in result.findings)

    @patch("requests.Session.options")
    def test_cors_wildcard(self, mock_options):
        mock_options.return_value = mock_response(200, headers={"Access-Control-Allow-Origin": "*"})
        scanner = InjectionScanner(test_sqli=False, test_mass_assignment=False, test_secrets=False)
        result = scanner.scan([make_endpoint()])
        assert any(f.finding_type == InjFindingType.CORS_WILDCARD for f in result.findings)

    @patch("requests.Session.get")
    def test_exposed_secrets(self, mock_get):
        mock_get.return_value = mock_response(200, '{"key": "AKIA1234567890123456"}')
        scanner = InjectionScanner(test_sqli=False, test_mass_assignment=False, test_cors=False)
        result = scanner.scan([make_endpoint()])
        assert any(f.finding_type == InjFindingType.EXPOSED_SECRET for f in result.findings)

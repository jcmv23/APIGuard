"""
Tests for Module 5 - Rate Limit Scanner
Run: python -m pytest test_rate.py -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock, patch
import pytest

from module_5_ratelimit.rate_scanner import RateLimitScanner, RateLimitFinding, RateLimitScanResult, Severity
from module_1_parser.parser import Endpoint

def make_endpoint(path="/users", method="GET"):
    return Endpoint(
        method=method,
        path=path,
        full_url=f"https://api.example.com{path}",
        summary="",
        tags=[],
    )

def mock_response(status_code: int):
    resp = MagicMock()
    resp.status_code = status_code
    return resp

class TestRateLimitDetection:
    @patch("requests.Session.get")
    def test_vulnerable_when_all_succeed(self, mock_get):
        mock_get.return_value = mock_response(200)
        scanner = RateLimitScanner(requests_to_send=10, concurrency=2)
        result = scanner.scan([make_endpoint()])
        
        assert result.vulnerable_endpoints == 1
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.HIGH
        assert "10 concurrent requests" in f.proof or " burst of 10 " in f.description

    @patch("requests.Session.get")
    def test_safe_when_429_returned(self, mock_get):
        responses = [mock_response(200)] * 5 + [mock_response(429)] * 5
        mock_get.side_effect = responses
        scanner = RateLimitScanner(requests_to_send=10, concurrency=1)
        result = scanner.scan([make_endpoint()])
        assert result.vulnerable_endpoints == 0

    @patch("requests.Session.get")
    def test_handles_exceptions(self, mock_get):
        import requests as req
        mock_get.side_effect = req.RequestException("Timeout")
        scanner = RateLimitScanner(requests_to_send=5, concurrency=1)
        result = scanner.scan([make_endpoint()])
        assert result.vulnerable_endpoints == 0

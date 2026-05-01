"""
Tests for Module 4 - Auth Scanner
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock, patch
import pytest
import time

from module_4_auth.auth_scanner import AuthScanner, AuthFindingType, sign_jwt_hs256, make_alg_none_token
from module_1_parser.parser import Endpoint

def make_endpoint(path="/data", method="GET"):
    return Endpoint(
        method=method,
        path=path,
        full_url=f"https://api.example.com{path}",
        summary="",
        tags=[],
        requires_auth=True
    )

def mock_response(status_code: int, ct="application/json", text='{"data":"secret"}'):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"Content-Type": ct}
    resp.text = text
    def json_fn(): return {"data": "secret"}
    resp.json = json_fn
    return resp

class TestAuthScanner:
    @patch("requests.Session.get")
    def test_missing_auth(self, mock_get):
        mock_get.return_value = mock_response(200)
        scanner = AuthScanner()
        result = scanner.scan([make_endpoint()])
        assert any(f.finding_type == AuthFindingType.MISSING_AUTH for f in result.findings)

    def test_jwt_no_exp(self):
        token = sign_jwt_hs256({"alg": "HS256", "typ": "JWT"}, {"sub": "123"}, "secret")
        scanner = AuthScanner(valid_token=token, weak_secrets=["secret"])
        analysis = scanner._analyse_jwt(token)
        findings = scanner._check_jwt_properties(token, analysis, [make_endpoint()])
        assert any(f.finding_type == AuthFindingType.JWT_NO_EXPIRY for f in findings)
        assert any(f.finding_type == AuthFindingType.JWT_WEAK_SECRET for f in findings)

    def test_jwt_alg_none(self):
        token = make_alg_none_token({"sub": "123"})
        scanner = AuthScanner()
        analysis = scanner._analyse_jwt(token)
        findings = scanner._check_jwt_properties(token, analysis, [make_endpoint()])
        assert any(f.finding_type == AuthFindingType.JWT_ALG_NONE for f in findings)

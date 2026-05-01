"""
APIGuard - Module 10: Excessive Data Exposure Scanner
=======================================================
Detects when API responses contain more data than necessary (OWASP API3:2023).

Vulnerabilities covered:
  DATA-1  PII leakage (emails, SSNs, credit cards, phone numbers)
  DATA-2  Excessive response size (potential data dump)
  DATA-3  Sensitive field exposure (passwords, tokens, internal IDs)
  DATA-4  Debug/internal fields in production responses
  DATA-5  Unfiltered collection responses (no pagination)
"""

import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any

import requests

try:
    from module_1_parser.parser import Endpoint
    from module_2_bola.bola_scanner import Severity
except ImportError:
    from enum import Enum
    class Severity(str, Enum):
        CRITICAL = "CRITICAL"
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"
        INFO = "INFO"


# ── PII Detection Patterns ──────────────────
PII_PATTERNS = {
    "email_address": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    "phone_number": re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"),
    "ip_address_private": re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    "date_of_birth": re.compile(r"\b(?:dob|date_of_birth|birth_date|birthdate)\b", re.IGNORECASE),
}

# ── Sensitive field names ────────────────────
SENSITIVE_FIELDS = re.compile(
    r"(password|passwd|pwd|secret|token|private_key|"
    r"ssn|social_security|credit_card|card_number|cvv|"
    r"bank_account|routing_number|salary|"
    r"internal_id|_internal|__debug|_private|"
    r"session_id|refresh_token|api_secret)",
    re.IGNORECASE,
)

DEBUG_FIELDS = re.compile(
    r"(debug|_debug|__v|__typename|_raw|_meta|"
    r"stack_trace|stacktrace|traceback|"
    r"sql_query|db_query|query_log|"
    r"elapsed_ms|execution_time|_internal)",
    re.IGNORECASE,
)

MAX_SAFE_RESPONSE_SIZE = 100_000   # 100 KB
MAX_SAFE_ARRAY_LENGTH = 100        # Items in a collection


@dataclass
class DataFinding:
    vulnerability_type: str = ""
    severity: Severity = Severity.MEDIUM
    endpoint: str = ""
    method: str = ""
    description: str = ""
    proof: str = ""
    remediation: str = ""
    pii_type: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class DataScanResult:
    target_url: str
    total_endpoints_tested: int = 0
    vulnerable_endpoints: int = 0
    findings: list[DataFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "DATA_EXPOSURE",
            "target_url": self.target_url,
            "total_endpoints_tested": self.total_endpoints_tested,
            "vulnerable_endpoints": self.vulnerable_endpoints,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── DATA EXPOSURE SCAN SUMMARY ──────────────────────",
            f"  Target            : {self.target_url}",
            f"  Endpoints tested  : {self.total_endpoints_tested}",
            f"  Vulnerable        : {self.vulnerable_endpoints}",
            f"  Duration          : {self.scan_duration_seconds:.1f}s",
        ]
        if self.findings:
            lines.append("\n  Findings:")
            for f in self.findings:
                lines.append(f"    [{f.severity.value}] {f.vulnerability_type} @ {f.method} {f.endpoint}")
        else:
            lines.append("  ✅  No excessive data exposure detected.")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


class DataExposureScanner:
    """
    Scans API responses for excessive data exposure and PII leakage.
    
    Usage:
        scanner = DataExposureScanner(token="Bearer eyJ...")
        result = scanner.scan(endpoints)
    """

    def __init__(self, token: str | None = None, timeout: int = 10, delay: float = 0.1):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        if token:
            self.session.headers["Authorization"] = token

    def scan(self, endpoints: list) -> DataScanResult:
        t0 = time.monotonic()
        from urllib.parse import urlparse
        target = ""
        if endpoints:
            p = urlparse(endpoints[0].full_url)
            target = f"{p.scheme}://{p.netloc}"

        result = DataScanResult(target_url=target)

        for ep in endpoints:
            if ep.method.upper() not in ("GET", "HEAD"):
                continue

            try:
                ep_findings = self._check_endpoint(ep)
                result.total_endpoints_tested += 1
                if ep_findings:
                    result.findings.extend(ep_findings)
                    result.vulnerable_endpoints += 1
            except Exception as exc:
                result.errors.append(f"{ep.method} {ep.path} → {exc}")

            time.sleep(self.delay)

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    def _check_endpoint(self, ep) -> list[DataFinding]:
        findings = []
        url = re.sub(r"\{[^}]+\}", "1", ep.full_url)

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return findings

        if resp.status_code not in (200, 201):
            return findings

        # Check 1: Response size
        if len(resp.content) > MAX_SAFE_RESPONSE_SIZE:
            findings.append(DataFinding(
                vulnerability_type="EXCESSIVE_RESPONSE_SIZE",
                severity=Severity.MEDIUM,
                endpoint=ep.full_url,
                method=ep.method,
                description=f"Response is {len(resp.content):,} bytes — potentially leaking excessive data.",
                proof=f"Response size: {len(resp.content):,} bytes (threshold: {MAX_SAFE_RESPONSE_SIZE:,}).",
                remediation="Implement pagination, field filtering (sparse fieldsets), and response size limits.",
            ))

        # Parse JSON
        try:
            body = resp.json()
        except Exception:
            return findings

        # Check 2: PII in response
        resp_text = resp.text
        for pii_type, pattern in PII_PATTERNS.items():
            matches = pattern.findall(resp_text)
            if matches and len(matches) > 1:  # Multiple matches = likely real data
                findings.append(DataFinding(
                    vulnerability_type="PII_LEAKAGE",
                    severity=Severity.HIGH,
                    endpoint=ep.full_url,
                    method=ep.method,
                    description=f"Response contains {len(matches)} instances of PII type '{pii_type}'.",
                    proof=f"Found {len(matches)} matches. Sample: {matches[0][:40] if matches else 'N/A'}",
                    remediation="Filter sensitive PII from API responses. Use DTOs to control which fields are returned.",
                    pii_type=pii_type,
                ))

        # Check 3: Sensitive fields
        sensitive_found = self._find_sensitive_fields(body)
        if sensitive_found:
            findings.append(DataFinding(
                vulnerability_type="SENSITIVE_FIELD_EXPOSURE",
                severity=Severity.HIGH,
                endpoint=ep.full_url,
                method=ep.method,
                description=f"Response contains sensitive fields: {', '.join(sensitive_found[:5])}.",
                proof=f"Sensitive keys found in JSON response: {sensitive_found[:5]}",
                remediation="Never expose sensitive fields like passwords, tokens, or internal IDs in API responses.",
            ))

        # Check 4: Debug fields
        debug_found = self._find_debug_fields(body)
        if debug_found:
            findings.append(DataFinding(
                vulnerability_type="DEBUG_FIELD_EXPOSURE",
                severity=Severity.MEDIUM,
                endpoint=ep.full_url,
                method=ep.method,
                description=f"Response contains debug/internal fields: {', '.join(debug_found[:5])}.",
                proof=f"Debug keys found: {debug_found[:5]}",
                remediation="Remove debug and internal fields from production API responses.",
            ))

        # Check 5: Unpaginated collection
        if isinstance(body, list) and len(body) > MAX_SAFE_ARRAY_LENGTH:
            findings.append(DataFinding(
                vulnerability_type="NO_PAGINATION",
                severity=Severity.MEDIUM,
                endpoint=ep.full_url,
                method=ep.method,
                description=f"Endpoint returned {len(body)} items without pagination.",
                proof=f"Array response with {len(body)} elements (threshold: {MAX_SAFE_ARRAY_LENGTH}).",
                remediation="Implement cursor or offset-based pagination. Default limit: 20-50 items.",
            ))

        return findings

    def _find_sensitive_fields(self, obj: Any, depth: int = 0) -> list[str]:
        if depth > 4:
            return []
        found = []
        if isinstance(obj, dict):
            for key in obj:
                if SENSITIVE_FIELDS.search(str(key)):
                    found.append(key)
                found.extend(self._find_sensitive_fields(obj[key], depth + 1))
        elif isinstance(obj, list):
            for item in obj[:5]:
                found.extend(self._find_sensitive_fields(item, depth + 1))
        return list(set(found))

    def _find_debug_fields(self, obj: Any, depth: int = 0) -> list[str]:
        if depth > 4:
            return []
        found = []
        if isinstance(obj, dict):
            for key in obj:
                if DEBUG_FIELDS.search(str(key)):
                    found.append(key)
                found.extend(self._find_debug_fields(obj[key], depth + 1))
        elif isinstance(obj, list):
            for item in obj[:5]:
                found.extend(self._find_debug_fields(item, depth + 1))
        return list(set(found))

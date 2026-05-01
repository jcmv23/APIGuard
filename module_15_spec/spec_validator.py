"""
APIGuard — Spec vs Reality Validator (Module 15)
==================================================
Compares OpenAPI/Swagger specification against actual API behavior:
  SPEC-1  Undocumented endpoints (exist but not in spec)
  SPEC-2  Missing endpoints (in spec but return 404)
  SPEC-3  Schema mismatches (response differs from spec)
  SPEC-4  Undocumented response codes
  SPEC-5  Extra fields in response (not in spec)
  SPEC-6  Missing required fields
  SPEC-7  Type mismatches (string vs number, etc.)
  SPEC-8  Authentication bypass (spec says auth, but works without)
"""

import re
import time
import json
from dataclasses import dataclass, field, asdict
from typing import Any

import requests

try:
    from module_1_parser.parser import Endpoint
    from module_2_bola.bola_scanner import Severity
except ImportError:
    from parser import Endpoint
    from bola_scanner import Severity


# ─────────────────────────────────────────────
# Common undocumented endpoints to probe
# ─────────────────────────────────────────────

SHADOW_ENDPOINTS = [
    # Admin / Management
    "/admin", "/api/admin", "/api/v1/admin",
    "/admin/login", "/admin/dashboard",
    "/management", "/manager", "/console",
    # Debug / Internal
    "/debug", "/debug/vars", "/debug/pprof",
    "/_debug", "/api/debug", "/internal",
    "/api/internal", "/api/_internal",
    # Status / Health
    "/health", "/healthz", "/ready", "/readyz",
    "/status", "/ping", "/api/health",
    "/api/status", "/api/ping",
    # Documentation
    "/docs", "/swagger", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs",
    "/redoc", "/graphql", "/graphiql",
    # Version / Info
    "/version", "/api/version", "/info",
    "/api/info", "/api/v1/info",
    # Config / Env
    "/env", "/config", "/settings",
    "/api/config", "/api/settings",
    "/.env", "/config.json", "/config.yaml",
    # Database
    "/phpmyadmin", "/adminer", "/pgadmin",
    "/api/db", "/api/database",
    # Backup / Dump
    "/backup", "/dump", "/export",
    "/api/backup", "/api/export",
    # Auth / Users
    "/api/users", "/api/v1/users",
    "/api/tokens", "/api/sessions",
    "/api/auth/sessions",
    # Metrics
    "/metrics", "/prometheus", "/grafana",
    "/api/metrics", "/api/stats",
    # Files
    "/uploads", "/files", "/static",
    "/media", "/assets",
    # Old versions
    "/api/v0/", "/api/v2/", "/api/v3/",
    "/api/beta/", "/api/alpha/", "/api/test/",
    # Framework-specific
    "/actuator", "/actuator/env", "/actuator/health",  # Spring Boot
    "/__inspect", "/_profiler",  # Django/Symfony
    "/elmah.axd", "/trace.axd",  # ASP.NET
    "/server-status", "/server-info",  # Apache
    "/wp-admin", "/wp-json",  # WordPress
]


# ─────────────────────────────────────────────
# Type mapping for schema validation
# ─────────────────────────────────────────────

JSONSCHEMA_TYPE_MAP = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
}


# ─────────────────────────────────────────────
# Result Models
# ─────────────────────────────────────────────

class SpecFindingType:
    UNDOCUMENTED_ENDPOINT = "UNDOCUMENTED_ENDPOINT"
    MISSING_ENDPOINT = "MISSING_ENDPOINT"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    UNDOCUMENTED_STATUS = "UNDOCUMENTED_STATUS"
    EXTRA_FIELD = "EXTRA_FIELD"
    MISSING_FIELD = "MISSING_FIELD"
    TYPE_MISMATCH = "TYPE_MISMATCH"
    AUTH_BYPASS = "AUTH_BYPASS"





from enum import Enum as _Enum
SPEC_SEVERITY = {
    "UNDOCUMENTED_ENDPOINT": "HIGH",
    "MISSING_ENDPOINT": "LOW",
    "SCHEMA_MISMATCH": "MEDIUM",
    "UNDOCUMENTED_STATUS": "LOW",
    "EXTRA_FIELD": "MEDIUM",
    "MISSING_FIELD": "LOW",
    "TYPE_MISMATCH": "LOW",
    "AUTH_BYPASS": "CRITICAL",
}

SPEC_REMEDIATION = {
    "UNDOCUMENTED_ENDPOINT": "Document all endpoints in the OpenAPI spec or disable them if not intended for production.",
    "MISSING_ENDPOINT": "Implement the endpoint as documented or remove it from the spec.",
    "SCHEMA_MISMATCH": "Update the spec to match implementation, or fix the implementation to match the spec.",
    "UNDOCUMENTED_STATUS": "Document all possible response status codes in the OpenAPI spec.",
    "EXTRA_FIELD": "Review extra fields — they may leak internal data. Add to spec or remove from response.",
    "MISSING_FIELD": "Ensure all required fields defined in the spec are present in responses.",
    "TYPE_MISMATCH": "Fix field types to match the spec. Type mismatches can cause client-side parsing errors.",
    "AUTH_BYPASS": "Enforce authentication on all protected endpoints. The spec declares auth but the endpoint works without it.",
}


@dataclass
class SpecFinding:
    finding_type: str
    severity: str
    endpoint: str
    method: str
    description: str
    proof: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SpecScanResult:
    target_url: str
    spec_endpoints: int = 0
    actual_endpoints: int = 0
    undocumented_found: int = 0
    missing_found: int = 0
    schema_issues: int = 0
    findings: list[SpecFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "SPEC_VALIDATOR",
            "target_url": self.target_url,
            "spec_endpoints": self.spec_endpoints,
            "actual_endpoints": self.actual_endpoints,
            "undocumented_found": self.undocumented_found,
            "missing_found": self.missing_found,
            "schema_issues": self.schema_issues,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── SPEC vs REALITY VALIDATOR SUMMARY ─────",
            f"  Target              : {self.target_url}",
            f"  Spec endpoints      : {self.spec_endpoints}",
            f"  Actual endpoints    : {self.actual_endpoints}",
            f"  Undocumented found  : {self.undocumented_found}",
            f"  Missing from impl   : {self.missing_found}",
            f"  Schema issues       : {self.schema_issues}",
        ]
        if self.findings:
            lines.append(f"\n  Findings ({len(self.findings)}):")
            for f in self.findings:
                lines.append(f"    [{f.severity}] {f.finding_type}: {f.description[:70]}")
        else:
            lines.append("  ✅  Spec matches reality perfectly.")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


# ─────────────────────────────────────────────
# Spec Validator Engine
# ─────────────────────────────────────────────

class SpecValidator:
    """
    Validates API implementation against its OpenAPI specification:
    1. Discovers undocumented (shadow) endpoints
    2. Verifies spec endpoints exist and respond correctly
    3. Validates response schemas (types, required fields, extra fields)
    4. Checks if auth-required endpoints work without auth
    """

    def __init__(
        self,
        token: str | None = None,
        extra_headers: dict | None = None,
        timeout: int = 10,
        delay: float = 0.15,
        probe_shadow: bool = True,
    ):
        self.timeout = timeout
        self.delay = delay
        self.probe_shadow = probe_shadow

        self.session = requests.Session()
        self.session.headers["User-Agent"] = "APIGuard-SpecValidator/4.0"
        if token:
            self.session.headers["Authorization"] = token
        if extra_headers:
            self.session.headers.update(extra_headers)

        # Unauthenticated session for auth bypass testing
        self.unauth_session = requests.Session()
        self.unauth_session.headers["User-Agent"] = "APIGuard-SpecValidator/4.0"

    def scan(self, endpoints: list[Endpoint], spec: dict | None = None) -> SpecScanResult:
        t0 = time.monotonic()
        from urllib.parse import urlparse
        target = ""
        if endpoints:
            p = urlparse(endpoints[0].full_url)
            target = f"{p.scheme}://{p.netloc}"

        result = SpecScanResult(target_url=target)
        result.spec_endpoints = len(endpoints)

        # 1. Check each spec endpoint exists and validate schema
        for ep in endpoints:
            try:
                self._validate_endpoint(ep, result)
            except Exception as exc:
                result.errors.append(f"Validation error {ep.method} {ep.path}: {exc}")
            time.sleep(self.delay)

        # 2. Probe for undocumented shadow endpoints
        if self.probe_shadow and target:
            self._probe_shadow_endpoints(target, endpoints, result)

        # 3. Test auth bypass
        self._test_auth_bypass(endpoints, result)

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    def _validate_endpoint(self, ep: Endpoint, result: SpecScanResult):
        """Validate a single endpoint against its spec."""
        url = re.sub(r"\{[^}]+\}", "1", ep.full_url)
        
        try:
            if ep.method.upper() == "GET":
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            elif ep.method.upper() == "POST":
                resp = self.session.post(url, json={}, timeout=self.timeout, allow_redirects=False)
            else:
                resp = self.session.request(ep.method.upper(), url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return

        result.actual_endpoints += 1

        # Check if endpoint returns 404 (missing implementation)
        if resp.status_code == 404:
            result.missing_found += 1
            result.findings.append(SpecFinding(
                finding_type="MISSING_ENDPOINT",
                severity=SPEC_SEVERITY["MISSING_ENDPOINT"],
                endpoint=ep.full_url,
                method=ep.method,
                description=f"Endpoint documented in spec but returns 404.",
                proof=f"HTTP {resp.status_code} for {ep.method} {url}",
                remediation=SPEC_REMEDIATION["MISSING_ENDPOINT"],
            ))
            return

        # Validate response against spec's response schema
        if ep.responses:
            status_str = str(resp.status_code)
            spec_response = ep.responses.get(status_str) or ep.responses.get("200") or ep.responses.get("default")

            if not ep.responses.get(status_str) and status_str != "200":
                result.findings.append(SpecFinding(
                    finding_type="UNDOCUMENTED_STATUS",
                    severity=SPEC_SEVERITY["UNDOCUMENTED_STATUS"],
                    endpoint=ep.full_url,
                    method=ep.method,
                    description=f"Undocumented status code {resp.status_code}.",
                    proof=f"Spec documents: {list(ep.responses.keys())}. Got: {status_str}",
                    remediation=SPEC_REMEDIATION["UNDOCUMENTED_STATUS"],
                ))

            # Validate response body schema
            if spec_response and resp.text:
                try:
                    resp_json = resp.json()
                    schema = spec_response.get("schema", spec_response.get("content", {}).get("application/json", {}).get("schema", {}))
                    if schema:
                        self._validate_schema(resp_json, schema, ep, result)
                except (json.JSONDecodeError, ValueError):
                    pass

    def _validate_schema(self, data: Any, schema: dict, ep: Endpoint, result: SpecScanResult):
        """Recursively validate response data against JSON schema."""
        if not schema or not isinstance(schema, dict):
            return

        schema_type = schema.get("type", "")
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        if schema_type == "object" and isinstance(data, dict):
            # Check for extra fields
            if properties:
                extra = set(data.keys()) - set(properties.keys())
                for field_name in extra:
                    result.schema_issues += 1
                    result.findings.append(SpecFinding(
                        finding_type="EXTRA_FIELD",
                        severity=SPEC_SEVERITY["EXTRA_FIELD"],
                        endpoint=ep.full_url,
                        method=ep.method,
                        description=f"Response contains undocumented field '{field_name}'.",
                        proof=f"Field '{field_name}' not in spec properties: {list(properties.keys())[:10]}",
                        remediation=SPEC_REMEDIATION["EXTRA_FIELD"],
                    ))

            # Check for missing required fields
            for req_field in required:
                if req_field not in data:
                    result.schema_issues += 1
                    result.findings.append(SpecFinding(
                        finding_type="MISSING_FIELD",
                        severity=SPEC_SEVERITY["MISSING_FIELD"],
                        endpoint=ep.full_url,
                        method=ep.method,
                        description=f"Required field '{req_field}' missing from response.",
                        proof=f"Field '{req_field}' is required by spec but absent. Keys: {list(data.keys())[:10]}",
                        remediation=SPEC_REMEDIATION["MISSING_FIELD"],
                    ))

            # Check field types
            for field_name, field_schema in properties.items():
                if field_name in data:
                    expected_type = field_schema.get("type", "")
                    py_type = JSONSCHEMA_TYPE_MAP.get(expected_type)
                    if py_type and not isinstance(data[field_name], py_type):
                        actual_type = type(data[field_name]).__name__
                        result.schema_issues += 1
                        result.findings.append(SpecFinding(
                            finding_type="TYPE_MISMATCH",
                            severity=SPEC_SEVERITY["TYPE_MISMATCH"],
                            endpoint=ep.full_url,
                            method=ep.method,
                            description=f"Field '{field_name}': expected {expected_type}, got {actual_type}.",
                            proof=f"Spec: type={expected_type}. Actual: {actual_type} (value: {str(data[field_name])[:50]})",
                            remediation=SPEC_REMEDIATION["TYPE_MISMATCH"],
                        ))

        elif schema_type == "array" and isinstance(data, list) and data:
            items_schema = schema.get("items", {})
            if items_schema:
                self._validate_schema(data[0], items_schema, ep, result)

    def _probe_shadow_endpoints(self, base_url: str, spec_endpoints: list[Endpoint], result: SpecScanResult):
        """Probe for undocumented endpoints not in the spec."""
        spec_paths = {ep.path.rstrip("/") for ep in spec_endpoints}

        for shadow_path in SHADOW_ENDPOINTS:
            if shadow_path.rstrip("/") in spec_paths:
                continue

            url = f"{base_url}{shadow_path}"
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code not in (404, 405, 301, 308):
                    result.undocumented_found += 1
                    result.actual_endpoints += 1

                    severity = "HIGH"
                    if any(kw in shadow_path for kw in ["admin", "debug", "internal", ".env", "config", "actuator"]):
                        severity = "CRITICAL"
                    elif any(kw in shadow_path for kw in ["health", "status", "ping", "docs", "swagger"]):
                        severity = "LOW"

                    result.findings.append(SpecFinding(
                        finding_type="UNDOCUMENTED_ENDPOINT",
                        severity=severity,
                        endpoint=shadow_path,
                        method="GET",
                        description=f"Undocumented endpoint '{shadow_path}' is accessible (HTTP {resp.status_code}).",
                        proof=f"Not in spec. Status: {resp.status_code}. "
                              f"Content-Type: {resp.headers.get('content-type', 'unknown')}. "
                              f"Size: {len(resp.text)} bytes.",
                        remediation=SPEC_REMEDIATION["UNDOCUMENTED_ENDPOINT"],
                    ))

            except requests.RequestException:
                pass

            time.sleep(self.delay / 2)

    def _test_auth_bypass(self, endpoints: list[Endpoint], result: SpecScanResult):
        """Test if authenticated endpoints work without credentials."""
        auth_endpoints = [ep for ep in endpoints if ep.security]

        for ep in auth_endpoints[:10]:  # Test up to 10
            url = re.sub(r"\{[^}]+\}", "1", ep.full_url)
            try:
                resp = self.unauth_session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in (200, 201, 204):
                    result.findings.append(SpecFinding(
                        finding_type="AUTH_BYPASS",
                        severity=SPEC_SEVERITY["AUTH_BYPASS"],
                        endpoint=ep.full_url,
                        method=ep.method,
                        description=f"Authentication bypass! Spec requires auth but endpoint works without it.",
                        proof=f"Unauthenticated request returned HTTP {resp.status_code}. "
                              f"Body: {resp.text[:100]}",
                        remediation=SPEC_REMEDIATION["AUTH_BYPASS"],
                    ))
            except requests.RequestException:
                pass

            time.sleep(self.delay)

    def _safe_get(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

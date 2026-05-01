"""
APIGuard - Module 3: BFLA Scanner
===================================
Broken Function Level Authorization (OWASP API Top 10 - API5:2023)

Detects if unprivileged users can access administrative endpoints.
"""

import time
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

import requests

try:
    from module_1_parser.parser import Endpoint, Parameter
    from module_2_bola.bola_scanner import Severity
except ImportError:
    from parser import Endpoint, Parameter      # type: ignore
    from bola_scanner import Severity           # type: ignore


ADMIN_PATH_PATTERNS = [
    r"/admin", r"/internal", r"/system", r"/management",
    r"/superuser", r"/root", r"/staff", r"/config"
]


def is_admin_endpoint(ep: Endpoint) -> bool:
    """Heuristic to detect if an endpoint is administrative."""
    path_lower = ep.path.lower()
    if any(re.search(p, path_lower) for p in ADMIN_PATH_PATTERNS):
        return True
    
    tags_lower = " ".join(ep.tags).lower()
    if "admin" in tags_lower or "administration" in tags_lower:
        return True

    if ep.method.upper() == "DELETE":
        if "reset" in path_lower or "purge" in path_lower or "revoke" in path_lower:
            return True

    if ep.method.upper() in ("POST", "PUT", "PATCH"):
        if "reset" in path_lower or "purge" in path_lower or "revoke" in path_lower:
            return True

    return False


@dataclass
class BFLAFinding:
    vulnerability_type: str = "BFLA"
    severity: Severity = Severity.CRITICAL
    endpoint: str = ""
    method: str = ""
    description: str = ""
    proof: str = ""
    remediation: str = "Implement strong role-based access control (RBAC). Verify roles and permissions continually."

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    def __str__(self) -> str:
        return (
            f"\n{'='*60}\n"
            f"  VULNERABILITY DETECTED\n"
            f"{'='*60}\n"
            f"  Type      : {self.vulnerability_type}\n"
            f"  Severity  : {self.severity.value}\n"
            f"  Endpoint  : {self.method} {self.endpoint}\n"
            f"  Description: {self.description}\n"
            f"  Proof     : {self.proof}\n"
            f"  Remediation: {self.remediation}\n"
            f"{'='*60}"
        )


@dataclass
class BFLAScanResult:
    target_url: str
    admin_endpoints_found: int = 0
    total_endpoints_tested: int = 0
    vulnerable_endpoints: int = 0
    findings: list[BFLAFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "BFLA",
            "target_url": self.target_url,
            "admin_endpoints_found": self.admin_endpoints_found,
            "total_endpoints_tested": self.total_endpoints_tested,
            "vulnerable_endpoints": self.vulnerable_endpoints,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── BFLA SCAN SUMMARY ───────────────────────────────",
            f"  Target              : {self.target_url}",
            f"  Admin endpoints     : {self.admin_endpoints_found}",
            f"  Endpoints tested    : {self.total_endpoints_tested}",
            f"  Vulnerable          : {self.vulnerable_endpoints}",
            f"  Duration            : {self.scan_duration_seconds:.1f}s",
        ]
        if self.findings:
            lines.append("\n  Findings:")
            for f in self.findings:
                lines.append(f"    [{f.severity.value}] {f.method} {f.endpoint}")
        else:
            lines.append("  ✅  No BFLA vulnerabilities detected.")
        if self.errors:
            lines.append(f"\n  ⚠️  Errors ({len(self.errors)}):")
            for e in self.errors[:5]:
                lines.append(f"    {e}")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


class BFLAScanner:
    def __init__(
        self,
        low_priv_token: str,
        low_priv_username: str = "low_priv_user",
        admin_token: str | None = None,
        timeout: int = 10,
        delay_between_requests: float = 0.1,
        success_codes: tuple[int, ...] = (200, 201, 204),
    ):
        self.low_priv_token = low_priv_token
        self.low_priv_username = low_priv_username
        self.admin_token = admin_token
        self.timeout = timeout
        self.delay = delay_between_requests
        self.success_codes = success_codes
        
        self.low_session = requests.Session()
        if low_priv_token:
            self.low_session.headers.update({"Authorization": low_priv_token})
            
        if admin_token:
            self.admin_session = requests.Session()
            self.admin_session.headers.update({"Authorization": admin_token})
        else:
            self.admin_session = None

    def scan(self, endpoints: list[Endpoint]) -> BFLAScanResult:
        t0 = time.monotonic()
        result = BFLAScanResult(target_url="")
        if endpoints:
            from urllib.parse import urlparse
            parsed = urlparse(endpoints[0].full_url)
            result.target_url = f"{parsed.scheme}://{parsed.netloc}"

        admin_eps = [ep for ep in endpoints if is_admin_endpoint(ep)]
        result.admin_endpoints_found = len(admin_eps)

        for ep in admin_eps:
            try:
                finding = self._test_endpoint(ep)
                if finding:
                    result.findings.append(finding)
                    result.vulnerable_endpoints += 1
                
                # Check is deferred until here to ensure total endpoints test counts are correctly synced with BFLA
                if hasattr(self.admin_session, 'delete') or self.admin_session is None or True: 
                    result.total_endpoints_tested += 1

            except Exception as exc:
                result.errors.append(f"{ep.method} {ep.path} → {exc}")

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    def _test_endpoint(self, ep: Endpoint) -> BFLAFinding | None:
        url = re.sub(r"\{[^}]+\}", "1", ep.full_url)
        body = self._build_dummy_body(ep)

        if self.admin_session:
            resp_admin = self._request(self.admin_session, ep.method, url, body)
            time.sleep(self.delay)
            if resp_admin and resp_admin.status_code == 404:
                return None

        resp_low = self._request(self.low_session, ep.method, url, body)
        time.sleep(self.delay)
        
        if resp_low is None:
            return None

        if resp_low.status_code in self.success_codes:
            return BFLAFinding(
                severity=self._classify_severity(ep),
                endpoint=ep.full_url,
                method=ep.method,
                description=f"User '{self.low_priv_username}' successfully executed an administrative operation.",
                proof=f"{ep.method} {url} returned HTTP {resp_low.status_code} with user {self.low_priv_username}.",
            )
        return None

    def _classify_severity(self, ep: Endpoint) -> Severity:
        if ep.method.upper() == "DELETE":
            return Severity.CRITICAL
        path_lower = ep.path.lower()
        if ep.method.upper() in ("POST", "PUT", "PATCH") and ("reset" in path_lower or "purge" in path_lower):
            return Severity.CRITICAL
        return Severity.HIGH

    def _build_dummy_body(self, ep: Endpoint) -> dict | None:
        if ep.method.upper() == "GET":
            return None
        body = {}
        props = ep.request_body_schema.get("properties", {}) if ep.request_body_schema else {}
        for k, v in props.items():
            t = v.get("type", "string")
            if t == "boolean":
                body[k] = False
            elif t in ("integer", "number"):
                body[k] = 1
            else:
                body[k] = "test"
        return body

    def _request(self, session: requests.Session, method: str, url: str, body: dict | None) -> requests.Response | None:
        try:
            m = method.upper()
            if m == "GET":
                return session.get(url, timeout=self.timeout)
            elif m == "POST":
                return session.post(url, json=body or {}, timeout=self.timeout)
            elif m in ("PUT", "PATCH"):
                return session.request(m, url, json=body or {}, timeout=self.timeout)
            elif m == "DELETE":
                return session.delete(url, timeout=self.timeout)
            else:
                return session.request(m, url, timeout=self.timeout)
        except requests.RequestException:
            return None

"""
APIGuard - Module 2: BOLA Scanner
===================================
Broken Object Level Authorization (OWASP API Top 10 - API1:2023)

Detects if authenticated User A can access resources that belong to User B
by substituting object IDs in path/query parameters.
"""

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

import requests

# Allow importing Endpoint from Module 1 when running as a package,
# but also work standalone.
try:
    from module_1_parser.parser import Endpoint, Parameter
except ImportError:
    from parser import Endpoint, Parameter  # type: ignore


# ─────────────────────────────────────────────
# Result models
# ─────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class BOLAFinding:
    vulnerability_type: str = "BOLA"
    severity: Severity = Severity.CRITICAL
    endpoint: str = ""
    method: str = ""
    description: str = ""
    proof: str = ""
    status_code_a: int = 0      # response when A requests A's own resource
    status_code_b: int = 0      # response when A requests B's resource  ← VULN if 200
    response_body_b: str = ""   # snippet of the unauthorised response
    remediation: str = (
        "Validate that the object ID in the request matches the authenticated "
        "user's identity (e.g. compare token sub/user_id with path param). "
        "Never rely on client-supplied IDs alone."
    )

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
            f"  HTTP codes: User-A→own={self.status_code_a}  "
            f"User-A→other={self.status_code_b}\n"
            f"  Remediation: {self.remediation}\n"
            f"{'='*60}"
        )


@dataclass
class BOLAScanResult:
    target_url: str
    total_endpoints_tested: int = 0
    vulnerable_endpoints: int = 0
    findings: list[BOLAFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "BOLA",
            "target_url": self.target_url,
            "total_endpoints_tested": self.total_endpoints_tested,
            "vulnerable_endpoints": self.vulnerable_endpoints,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── BOLA SCAN SUMMARY ───────────────────────────────",
            f"  Target            : {self.target_url}",
            f"  Endpoints tested  : {self.total_endpoints_tested}",
            f"  Vulnerable        : {self.vulnerable_endpoints}",
            f"  Duration          : {self.scan_duration_seconds:.1f}s",
        ]
        if self.findings:
            lines.append("\n  Findings:")
            for f in self.findings:
                lines.append(f"    [{f.severity.value}] {f.method} {f.endpoint}")
        else:
            lines.append("  ✅  No BOLA vulnerabilities detected.")
        if self.errors:
            lines.append(f"\n  ⚠️  Errors ({len(self.errors)}):")
            for e in self.errors[:5]:
                lines.append(f"    {e}")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


# ─────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────

class BOLAScanner:
    """
    Usage
    -----
    scanner = BOLAScanner(
        token_user_a = "Bearer eyJ...",   # token of the authenticated test user
        id_user_a    = "123",             # the object ID that belongs to User A
        id_user_b    = "456",             # a different user/object ID (User B)
    )
    result = scanner.scan(endpoints)
    print(result.summary())
    """

    # IDs that, when substituted, are the most likely to reveal BOLA
    PROBE_ID_VARIANTS: list[str] = ["1", "2", "3", "0", "admin", "root"]

    def __init__(
        self,
        token_user_a: str,
        id_user_a: str | int,
        id_user_b: str | int,
        extra_headers: dict | None = None,
        timeout: int = 10,
        delay_between_requests: float = 0.1,
        success_codes: tuple[int, ...] = (200, 201),
    ):
        self.token_user_a = token_user_a
        self.id_user_a = str(id_user_a)
        self.id_user_b = str(id_user_b)
        self.timeout = timeout
        self.delay = delay_between_requests
        self.success_codes = success_codes
        self.session = requests.Session()
        self.session.headers.update({"Authorization": token_user_a})
        if extra_headers:
            self.session.headers.update(extra_headers)

    # ── Public API ────────────────────────────

    def scan(self, endpoints: list[Endpoint]) -> BOLAScanResult:
        """Run BOLA checks on all provided endpoints."""
        t0 = time.monotonic()
        result = BOLAScanResult(target_url="")

        # Infer target from first endpoint
        if endpoints:
            from urllib.parse import urlparse
            parsed = urlparse(endpoints[0].full_url)
            result.target_url = f"{parsed.scheme}://{parsed.netloc}"

        # Only test GET endpoints that have at least one path parameter
        candidates = [
            ep for ep in endpoints
            if ep.method in ("GET", "HEAD")
            and ep.is_resource_endpoint()
        ]

        for ep in candidates:
            try:
                finding = self._test_endpoint(ep)
                result.total_endpoints_tested += 1
                if finding:
                    result.findings.append(finding)
                    result.vulnerable_endpoints += 1
            except Exception as exc:
                result.errors.append(f"{ep.method} {ep.path} → {exc}")

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    # ── Core test logic ───────────────────────

    def _test_endpoint(self, ep: Endpoint) -> BOLAFinding | None:
        """
        1. Make a request with User A's own ID  → should be 200
        2. Make a request with User B's ID      → should be 403/404
        If step 2 returns 200 → VULNERABLE
        """
        # Build URL with user A's ID
        url_a = self._substitute_id(ep.full_url, ep.path, self.id_user_a)
        # Build URL with user B's ID
        url_b = self._substitute_id(ep.full_url, ep.path, self.id_user_b)

        if url_a == url_b:
            return None  # IDs identical → can't distinguish, skip

        resp_a = self._get(url_a)
        time.sleep(self.delay)
        resp_b = self._get(url_b)
        time.sleep(self.delay)

        if resp_a is None or resp_b is None:
            return None

        # Vulnerable: A's request was OK and B's request was also OK
        if resp_a.status_code in self.success_codes and resp_b.status_code in self.success_codes:
            snippet = resp_b.text[:300] if resp_b.text else "(empty body)"
            return BOLAFinding(
                endpoint=ep.full_url,
                method=ep.method,
                description=(
                    f"User A (id={self.id_user_a}) could access the resource "
                    f"belonging to User B (id={self.id_user_b}) without authorisation."
                ),
                proof=(
                    f"GET {url_b} returned HTTP {resp_b.status_code}. "
                    f"Response snippet: {snippet}"
                ),
                status_code_a=resp_a.status_code,
                status_code_b=resp_b.status_code,
                response_body_b=snippet,
            )
        return None

    # ── Helpers ───────────────────────────────

    def _substitute_id(self, full_url: str, path: str, new_id: str) -> str:
        """
        Replace ALL path parameters in the URL with new_id.
        e.g. https://api.example.com/users/{userId}/posts/{postId}
             → https://api.example.com/users/123/posts/123
        """
        import re
        return re.sub(r"\{[^}]+\}", new_id, full_url)

    def _get(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

    # ── Optional: blind-probe without explicit B id ──

    def probe_sequential_ids(self, endpoint: Endpoint, count: int = 5) -> BOLAScanResult:
        """
        When you don't know user B's ID, probe IDs 1..count to see if any
        return 200 with a different payload than user A's own resource.
        """
        t0 = time.monotonic()
        result = BOLAScanResult(target_url=endpoint.full_url)
        url_a = self._substitute_id(endpoint.full_url, endpoint.path, self.id_user_a)
        resp_a = self._get(url_a)
        if resp_a is None:
            result.errors.append(f"Cannot reach {url_a}")
            return result

        for probe_id in [str(i) for i in range(1, count + 1)]:
            if probe_id == self.id_user_a:
                continue
            url_b = self._substitute_id(endpoint.full_url, endpoint.path, probe_id)
            resp_b = self._get(url_b)
            time.sleep(self.delay)
            if resp_b and resp_b.status_code in self.success_codes:
                snippet = resp_b.text[:200] if resp_b.text else ""
                # Heuristic: if response is different from user A's response → different user data
                if resp_b.text != resp_a.text:
                    result.findings.append(BOLAFinding(
                        endpoint=endpoint.full_url,
                        method=endpoint.method,
                        description=f"Sequential ID probing: ID={probe_id} returned user data.",
                        proof=f"GET {url_b} → {resp_b.status_code}. Snippet: {snippet}",
                        status_code_a=resp_a.status_code,
                        status_code_b=resp_b.status_code,
                        response_body_b=snippet,
                    ))
                    result.vulnerable_endpoints += 1

        result.total_endpoints_tested = count
        result.scan_duration_seconds = time.monotonic() - t0
        return result
"""
APIGuard - Module 5: Rate Limit Scanner
=========================================
Detects whether an endpoint lacks rate limiting (OWASP API4:2023).
It sends a burst of requests and checks if the server returns HTTP 429
or if all responses are processed normally.
"""

import time
import concurrent.futures
from dataclasses import dataclass, field, asdict
from enum import Enum
import requests

try:
    from module_1_parser.parser import Endpoint
    from module_2_bola.bola_scanner import Severity
except ImportError:
    from parser import Endpoint        # type: ignore
    from bola_scanner import Severity  # type: ignore


@dataclass
class RateLimitFinding:
    vulnerability_type: str = "NO_RATE_LIMIT"
    severity: Severity = Severity.HIGH
    endpoint: str = ""
    method: str = ""
    description: str = ""
    proof: str = ""
    remediation: str = "Implement rate limiting using a token bucket or similar algorithm (e.g. 100 req/min per IP/token)."

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
class RateLimitScanResult:
    target_url: str
    total_endpoints_tested: int = 0
    vulnerable_endpoints: int = 0
    findings: list[RateLimitFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "RATE_LIMIT",
            "target_url": self.target_url,
            "total_endpoints_tested": self.total_endpoints_tested,
            "vulnerable_endpoints": self.vulnerable_endpoints,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── RATE LIMIT SCAN SUMMARY ─────────────────────────",
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
            lines.append("  ✅  Rate limits enforced.")
        if self.errors:
            lines.append(f"\n  ⚠️  Errors ({len(self.errors)}):")
            for e in self.errors[:5]:
                lines.append(f"    {e}")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


class RateLimitScanner:
    def __init__(
        self,
        token: str | None = None,
        timeout: int = 10,
        requests_to_send: int = 50,
        concurrency: int = 10,
    ):
        self.token = token
        self.timeout = timeout
        self.requests_to_send = requests_to_send
        self.concurrency = concurrency
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": token})

    def scan(self, endpoints: list[Endpoint]) -> RateLimitScanResult:
        t0 = time.monotonic()
        result = RateLimitScanResult(target_url="")
        if endpoints:
            from urllib.parse import urlparse
            parsed = urlparse(endpoints[0].full_url)
            result.target_url = f"{parsed.scheme}://{parsed.netloc}"

        test_endpoints = endpoints[:5]

        for ep in test_endpoints:
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

    def _test_endpoint(self, ep: Endpoint) -> RateLimitFinding | None:
        import re
        url = re.sub(r"\{[^}]+\}", "1", ep.full_url)

        def make_req():
            try:
                if ep.method.upper() == "GET":
                    return self.session.get(url, timeout=self.timeout)
                elif ep.method.upper() == "POST":
                    return self.session.post(url, json={}, timeout=self.timeout)
                else:
                    return self.session.get(url, timeout=self.timeout)
            except Exception:
                return None

        status_codes = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = [executor.submit(make_req) for _ in range(self.requests_to_send)]
            for f in concurrent.futures.as_completed(futures):
                resp = f.result()
                if resp:
                    status_codes.append(resp.status_code)
                else:
                    status_codes.append(0)

        if not status_codes:
            return None

        did_rate_limit = any(c == 429 for c in status_codes)
        
        if not did_rate_limit:
            successes = sum(1 for c in status_codes if c in (200, 201, 204, 400, 404, 403, 401))
            if successes >= (self.requests_to_send * 0.9): 
                return RateLimitFinding(
                    severity=Severity.HIGH,
                    endpoint=ep.full_url,
                    method=ep.method,
                    description=f"Endpoint accepted a burst of {self.requests_to_send} concurrent requests without returning HTTP 429.",
                    proof=f"Sent {self.requests_to_send} requests in {self.concurrency} concurrent threads. {successes} were processed.",
                )
        return None

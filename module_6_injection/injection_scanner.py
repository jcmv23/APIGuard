"""
APIGuard - Module 6: Injection / Secrets / CORS Scanner (Cognitive Fuzzer Edition)
===================================================================================
Detects multiple categories of input manipulation and configuration vulnerabilities
using heuristic cognitive fuzzing designed for Enterprise API security testing.

Vulnerabilities covered:
  INJ-1   SQL Injection (error-based)
  INJ-2   Mass Assignment (undocumented fields accepted)
  INJ-3   OS Command Injection (heuristic detection)
  INJ-4   SSRF (Server-Side Request Forgery)
  INJ-5   NoSQL Injection
  SEC-1   Secrets exposed in responses (API keys, tokens, passwords)
  SEC-2   Stack traces / exact error messages exposed
  CORS-1  CORS wildcard (Access-Control-Allow-Origin: *)
  CORS-2  CORS origin reflection
  CORS-3  CORS with credentials + wildcard (critical)
"""

import json
import re
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

import requests

try:
    from module_1_parser.parser import Endpoint
    from module_2_bola.bola_scanner import Severity
except ImportError:
    from parser import Endpoint        # type: ignore
    from bola_scanner import Severity  # type: ignore


# ─────────────────────────────────────────────
# Payload Vocabularies
# ─────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "'; DROP TABLE users;--",
    "1 OR 1=1",
]

CMD_PAYLOADS = [
    "; id",
    "| cat /etc/passwd",
    "& whoami",
    "`id`",
    "$(id)"
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:22",
    "file:///etc/passwd"
]

NOSQL_PAYLOADS = [
    {"$ne": 1},
    {"$gt": ""},
    {"$where": "sleep(2)"}
]

# Patterns in the response that indicate success
SQLI_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql_fetch|pg_query|sqlite3|sqliteexception|odbc_exec|"
    r"unclosed quotation|ora-\d{5}|syntax error.*sql|"
    r"you have an error in your sql|warning.*mysql|"
    r"supplied argument is not a valid mysql|"
    r"division by zero|invalid query|sqlexception|"
    r"microsoft ole db|jet database|driver.*sql server)",
    re.IGNORECASE,
)

CMD_SUCCESS_PATTERNS = re.compile(
    r"(uid=\d+\(.*\)|root:x:0:0:|www-data|root:!!)",
    re.IGNORECASE
)

SSRF_SUCCESS_PATTERNS = re.compile(
    r"(ami-id|instance-id|local-hostname|security-credentials)",
    re.IGNORECASE
)

STACK_TRACE_PATTERNS = re.compile(
    r"(traceback \(most recent call last\)|"
    r"at [a-z]+\.[a-zA-Z]+\(.*\.java:\d+\)|"
    r"system\.web\.|exception in thread|"
    r"stacktrace:|stack_trace|error_detail|"
    r"at [A-Za-z.]+\(.*\))",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────
# Heuristic Mappings for Cognitive Fuzzing
# ─────────────────────────────────────────────

PARAM_HEURISTICS = {
    "ssrf": ["url", "uri", "host", "domain", "proxy", "callback", "redirect", "webhook"],
    "cmd":  ["cmd", "exec", "file", "path", "dir", "command", "system", "script"],
    "nosql": ["username", "password", "user", "id", "session", "email", "query"]
}

EXTRA_FIELDS_TO_INJECT = {
    "role": "admin",
    "is_admin": True,
    "admin": True,
    "permission": "superuser",
    "status": "active"
}

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key",    re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE)),
    ("AWS Secret Key",    re.compile(r"[0-9a-zA-Z/+]{40}", re.IGNORECASE)),
    ("Stripe Live Key",   re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("JWT Token",         re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")),
    ("Generic API Key",   re.compile(r"(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?", re.IGNORECASE)),
    ("Bearer Token",      re.compile(r"bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)),
    ("Private Key",       re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----")),
]

EVIL_ORIGIN = "https://evil.attacker.com"


# ─────────────────────────────────────────────
# Result models
# ─────────────────────────────────────────────

class InjFindingType(str, Enum):
    SQL_INJECTION       = "SQL_INJECTION"
    OS_COMMAND_INJECTION= "OS_COMMAND_INJECTION"
    SSRF_VULNERABILITY  = "SSRF_VULNERABILITY"
    NOSQL_INJECTION     = "NOSQL_INJECTION"
    MASS_ASSIGNMENT     = "MASS_ASSIGNMENT"
    EXPOSED_SECRET      = "EXPOSED_SECRET"
    ERROR_DISCLOSURE    = "ERROR_DISCLOSURE"
    CORS_WILDCARD       = "CORS_WILDCARD"
    CORS_REFLECTION     = "CORS_REFLECTION"
    CORS_CREDENTIALS    = "CORS_CREDENTIALS"

FINDING_SEVERITY: dict[InjFindingType, Severity] = {
    InjFindingType.SQL_INJECTION:        Severity.CRITICAL,
    InjFindingType.OS_COMMAND_INJECTION: Severity.CRITICAL,
    InjFindingType.SSRF_VULNERABILITY:   Severity.HIGH,
    InjFindingType.NOSQL_INJECTION:      Severity.CRITICAL,
    InjFindingType.MASS_ASSIGNMENT:      Severity.HIGH,
    InjFindingType.EXPOSED_SECRET:       Severity.CRITICAL,
    InjFindingType.ERROR_DISCLOSURE:     Severity.MEDIUM,
    InjFindingType.CORS_WILDCARD:        Severity.MEDIUM,
    InjFindingType.CORS_REFLECTION:      Severity.HIGH,
    InjFindingType.CORS_CREDENTIALS:     Severity.CRITICAL,
}

FINDING_REMEDIATION: dict[InjFindingType, str] = {
    InjFindingType.SQL_INJECTION:        "Use prepared statements / parameterized queries.",
    InjFindingType.OS_COMMAND_INJECTION: "Avoid passing user input directly to system shells. Use sterile OS APIs instead.",
    InjFindingType.SSRF_VULNERABILITY:   "Validate URLs against a strict whitelist. Disable metadata endpoints on the host environment.",
    InjFindingType.NOSQL_INJECTION:      "Sanitize inputs to ensure they are interpreted as explicit scalar values (e.g., strings) and not query operators.",
    InjFindingType.MASS_ASSIGNMENT:      "Use explicit whitelists (DTOs) for object assignment mapping.",
    InjFindingType.EXPOSED_SECRET:       "Never return secrets or API keys in response payloads. Rotate immediately.",
    InjFindingType.ERROR_DISCLOSURE:     "Implement global exception handlers to obscure stack traces from end users.",
    InjFindingType.CORS_WILDCARD:        "Replace wildcard CORS origins with explicit domains.",
    InjFindingType.CORS_REFLECTION:      "Do not blindly reflect the Origin header. Validate against an allowed origins list.",
    InjFindingType.CORS_CREDENTIALS:     "CRITICAL: Never combine Access-Control-Allow-Credentials: true with a wildcard or reflected origin.",
}


@dataclass
class InjFinding:
    finding_type: InjFindingType
    severity: Severity
    endpoint: str
    method: str
    description: str
    proof: str
    remediation: str
    payload_used: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["finding_type"] = self.finding_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class InjScanResult:
    target_url: str
    total_endpoints_tested: int = 0
    vulnerable_endpoints: int = 0
    findings: list[InjFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "COGNITIVE_FUZZER",
            "target_url": self.target_url,
            "total_endpoints_tested": self.total_endpoints_tested,
            "vulnerable_endpoints": self.vulnerable_endpoints,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── COGNITIVE FUZZER SUMMARY ─────────────",
            f"  Target            : {self.target_url}",
            f"  Endpoints tested  : {self.total_endpoints_tested}",
            f"  Vulnerable        : {self.vulnerable_endpoints}",
            f"  Duration          : {self.scan_duration_seconds:.1f}s",
        ]
        if self.findings:
            lines.append("\n  Findings:")
            for f in self.findings:
                lines.append(f"    [{f.severity.value}] {f.finding_type.value} @ {f.method} {f.endpoint}")
        else:
            lines.append("  ✅  No Injection/Secrets/CORS vulnerabilities detected.")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


# ─────────────────────────────────────────────
# Cognitive Scanner Engine
# ─────────────────────────────────────────────

class InjectionScanner:
    def __init__(
        self,
        token: str | None = None,
        extra_headers: dict | None = None,
        timeout: int = 10,
        delay: float = 0.1,
    ):
        self.token = token
        self.timeout = timeout
        self.delay = delay

        self.session = requests.Session()
        if token:
            self.session.headers["Authorization"] = token
        if extra_headers:
            self.session.headers.update(extra_headers)

    def scan(self, endpoints: list[Endpoint]) -> InjScanResult:
        t0 = time.monotonic()
        from urllib.parse import urlparse
        target = ""
        if endpoints:
            p = urlparse(endpoints[0].full_url)
            target = f"{p.scheme}://{p.netloc}"

        result = InjScanResult(target_url=target)
        seen_cors = False

        for ep in endpoints:
            try:
                ep_findings: list[InjFinding] = []

                # Core Generic Fuzzing
                ep_findings.extend(self._check_sqli(ep))
                
                # Semantic / Cognitive Fuzzing based on parameters
                ep_findings.extend(self._cognitive_fuzz(ep))

                if ep.method.upper() in ("POST", "PUT", "PATCH"):
                    ep_findings.extend(self._check_mass_assignment(ep))
                    
                ep_findings.extend(self._check_secrets(ep))
                
                if not seen_cors:
                    cors_findings = self._check_cors(ep)
                    ep_findings.extend(cors_findings)
                    if cors_findings:
                        seen_cors = True

                result.total_endpoints_tested += 1
                if ep_findings:
                    result.findings.extend(ep_findings)
                    result.vulnerable_endpoints += 1

            except Exception as exc:
                result.errors.append(f"{ep.method} {ep.path} → {exc}")

            time.sleep(self.delay)

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    # ── Cognitive Mutational Fuzzing ─────────────────────────

    def _cognitive_fuzz(self, ep: Endpoint) -> list[InjFinding]:
        findings: list[InjFinding] = []
        base_url = re.sub(r"\{[^}]+\}", "1", ep.full_url)

        # Build parameters
        query_params = ep.query_params() if hasattr(ep, "query_params") else [p for p in ep.parameters if p.location == "query"]
        body_props = ep.request_body_schema.get("properties", {}) if ep.request_body_schema else {}

        # Scan Query Params and Body structure for semantic hints
        for param_list, is_body in [(query_params, False), (body_props.keys(), True)]:
            for param in param_list:
                p_name = param.name.lower() if not is_body else param.lower()

                # Rule 1: SSRF
                if any(h in p_name for h in PARAM_HEURISTICS["ssrf"]):
                    for payload in SSRF_PAYLOADS:
                        resp = self._fire_payload(ep, base_url, param.name if not is_body else param, payload, is_body)
                        if resp and SSRF_SUCCESS_PATTERNS.search(resp.text):
                            findings.append(InjFinding(
                                finding_type=InjFindingType.SSRF_VULNERABILITY,
                                severity=FINDING_SEVERITY[InjFindingType.SSRF_VULNERABILITY],
                                endpoint=ep.full_url,
                                method=ep.method,
                                description=f"Heuristic Parameter '{p_name}' successfully exploited with SSRF payload.",
                                proof=f"AWS Metadata or Localhost data extracted: {resp.text[:100]}",
                                remediation=FINDING_REMEDIATION[InjFindingType.SSRF_VULNERABILITY],
                                payload_used=payload,
                            ))
                            break

                # Rule 2: OS Command Injection
                if any(h in p_name for h in PARAM_HEURISTICS["cmd"]):
                    for payload in CMD_PAYLOADS:
                        resp = self._fire_payload(ep, base_url, param.name if not is_body else param, payload, is_body)
                        if resp and CMD_SUCCESS_PATTERNS.search(resp.text) or (resp and "Executed" in resp.text):
                            findings.append(InjFinding(
                                finding_type=InjFindingType.OS_COMMAND_INJECTION,
                                severity=FINDING_SEVERITY[InjFindingType.OS_COMMAND_INJECTION],
                                endpoint=ep.full_url,
                                method=ep.method,
                                description=f"Heuristic Parameter '{p_name}' is vulnerable to Server-Side Command Injection.",
                                proof=f"Root/system metadata or execution confirmation returned: {resp.text[:100]}",
                                remediation=FINDING_REMEDIATION[InjFindingType.OS_COMMAND_INJECTION],
                                payload_used=payload,
                            ))
                            break

                # Rule 3: NoSQL Injection
                if any(h in p_name for h in PARAM_HEURISTICS["nosql"]) and is_body:
                    for payload in NOSQL_PAYLOADS:
                        resp = self._fire_payload(ep, base_url, param, payload, True)
                        if resp and resp.status_code in (200, 201) and "token" in resp.text.lower():
                            findings.append(InjFinding(
                                finding_type=InjFindingType.NOSQL_INJECTION,
                                severity=FINDING_SEVERITY[InjFindingType.NOSQL_INJECTION],
                                endpoint=ep.full_url,
                                method=ep.method,
                                description=f"Semantic detection found NoSQL logical injection bypass via parameter '{p_name}'.",
                                proof=f"Successfully authenticated or bypassed logic using NoSQL operator: HTTP {resp.status_code}.",
                                remediation=FINDING_REMEDIATION[InjFindingType.NOSQL_INJECTION],
                                payload_used=json.dumps(payload),
                            ))
                            break

        return findings

    def _fire_payload(self, ep: Endpoint, base_url: str, param_name: str, payload: Any, is_body: bool) -> requests.Response | None:
        if not is_body:
            test_url = f"{base_url}?{param_name}={requests.utils.quote(str(payload))}"
            if ep.method.upper() == "GET":
                return self._get(test_url)
            else:
                return self._post(test_url, ep.method, {})
        else:
            body = {param_name: payload}
            return self._post(base_url, ep.method, body)


    # ── SQL Injection ─────────────────────────

    def _check_sqli(self, ep: Endpoint) -> list[InjFinding]:
        findings: list[InjFinding] = []
        params = ep.query_params() if hasattr(ep, "query_params") else [p for p in ep.parameters if p.location == "query"]
        if not params and ep.method.upper() == "GET":
            return findings

        base_url = re.sub(r"\{[^}]+\}", "1", ep.full_url)
        baseline = self._get(base_url)
        if baseline is None:
            return findings

        for payload in SQLI_PAYLOADS:
            if ep.method.upper() == "GET":
                for param in params:
                    test_url = f"{base_url}?{param.name}={requests.utils.quote(payload)}"
                    resp = self._get(test_url)
                    if resp and self._looks_like_sqli(resp, baseline):
                        findings.append(InjFinding(
                            finding_type=InjFindingType.SQL_INJECTION,
                            severity=FINDING_SEVERITY[InjFindingType.SQL_INJECTION],
                            endpoint=ep.full_url,
                            method=ep.method,
                            description=f"Parameter '{param.name}' is highly likely vulnerable to SQL Injection.",
                            proof=f"Payload: {payload!r} → Error/State changed.",
                            remediation=FINDING_REMEDIATION[InjFindingType.SQL_INJECTION],
                            payload_used=payload,
                        ))
                        return findings 
            elif ep.method.upper() in ("POST", "PUT", "PATCH"):
                body = {"q": payload}
                resp = self._post(base_url, ep.method, body)
                if resp and self._looks_like_sqli(resp, baseline):
                    findings.append(InjFinding(
                        finding_type=InjFindingType.SQL_INJECTION,
                        severity=FINDING_SEVERITY[InjFindingType.SQL_INJECTION],
                        endpoint=ep.full_url,
                        method=ep.method,
                        description="Request body is highly likely vulnerable to SQL Injection.",
                        proof=f"Payload: {payload!r} triggered SQL logic.",
                        remediation=FINDING_REMEDIATION[InjFindingType.SQL_INJECTION],
                        payload_used=payload,
                    ))
                    return findings
        return findings

    def _looks_like_sqli(self, resp: requests.Response, baseline: requests.Response) -> bool:
        if SQLI_ERROR_PATTERNS.search(resp.text):
            return True
        if baseline.status_code == 200 and resp.status_code == 500:
            return True
        return False

    # ── Mass Assignment ───────────────────────

    def _check_mass_assignment(self, ep: Endpoint) -> list[InjFinding]:
        findings: list[InjFinding] = []
        url = re.sub(r"\{[^}]+\}", "1", ep.full_url)
        injected_body = {"q": "test", **EXTRA_FIELDS_TO_INJECT}
        resp_injected = self._post(url, ep.method, injected_body)
        
        if resp_injected is None:
            return findings

        if resp_injected.status_code in (200, 201):
            try:
                resp_json = resp_injected.json()
                for key in EXTRA_FIELDS_TO_INJECT:
                    if self._key_in_json(key, resp_json):
                        findings.append(InjFinding(
                            finding_type=InjFindingType.MASS_ASSIGNMENT,
                            severity=FINDING_SEVERITY[InjFindingType.MASS_ASSIGNMENT],
                            endpoint=ep.full_url,
                            method=ep.method,
                            description=f"Undocumented field '{key}' was aggressively bound by Mass Assignment.",
                            proof=f"Injected field '{key}' reflected back by the server.",
                            remediation=FINDING_REMEDIATION[InjFindingType.MASS_ASSIGNMENT],
                            payload_used=json.dumps({key: EXTRA_FIELDS_TO_INJECT[key]}),
                        ))
                        break
            except Exception:
                pass
        return findings

    def _key_in_json(self, key: str, obj: Any, depth: int = 0) -> bool:
        if depth > 4:
            return False
        if isinstance(obj, dict):
            if key in obj: return True
            return any(self._key_in_json(key, v, depth + 1) for v in obj.values())
        if isinstance(obj, list):
            return any(self._key_in_json(key, item, depth + 1) for item in obj[:5])
        return False

    # ── Secrets & Leaks ───────────────────────

    def _check_secrets(self, ep: Endpoint) -> list[InjFinding]:
        findings: list[InjFinding] = []
        url = re.sub(r"\{[^}]+\}", "1", ep.full_url)
        resp = self._get(url)
        if not resp or resp.status_code not in (200, 201):
            return findings

        for label, pattern in SECRET_PATTERNS:
            match = pattern.search(resp.text)
            if match:
                findings.append(InjFinding(
                    finding_type=InjFindingType.EXPOSED_SECRET,
                    severity=FINDING_SEVERITY[InjFindingType.EXPOSED_SECRET],
                    endpoint=ep.full_url,
                    method=ep.method,
                    description=f"{label} leakage detected in the HTTP Response payload.",
                    proof=f"Identified Pattern '{label}': {match.group(0)[:80]}",
                    remediation=FINDING_REMEDIATION[InjFindingType.EXPOSED_SECRET],
                ))
                break 

        if not findings and STACK_TRACE_PATTERNS.search(resp.text):
            findings.append(InjFinding(
                finding_type=InjFindingType.ERROR_DISCLOSURE,
                severity=FINDING_SEVERITY[InjFindingType.ERROR_DISCLOSURE],
                endpoint=ep.full_url,
                method=ep.method,
                description="The endpoint leaked highly detailed stack traces or debug parameters to the client.",
                proof=f"Response stack trace leak snippet: {resp.text[:100]}",
                remediation=FINDING_REMEDIATION[InjFindingType.ERROR_DISCLOSURE],
            ))
        return findings

    # ── CORS ──────────────────────────────────

    def _check_cors(self, ep: Endpoint) -> list[InjFinding]:
        findings: list[InjFinding] = []
        url = re.sub(r"\{[^}]+\}", "1", ep.full_url)

        try:
            resp = self.session.options(url, headers={"Origin": EVIL_ORIGIN}, timeout=self.timeout)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if not acao:
                resp = self.session.get(url, headers={"Origin": EVIL_ORIGIN}, timeout=self.timeout)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        except requests.RequestException:
            return findings

        if not acao: return findings

        if acac == "true" and (acao == "*" or acao == EVIL_ORIGIN):
            findings.append(InjFinding(
                finding_type=InjFindingType.CORS_CREDENTIALS,
                severity=FINDING_SEVERITY[InjFindingType.CORS_CREDENTIALS],
                endpoint=ep.full_url,
                method="OPTIONS",
                description="CORS allows credentials from ANY origin. High exploitability.",
                proof=f"ACAO: {acao}, ACAC: {acac}",
                remediation=FINDING_REMEDIATION[InjFindingType.CORS_CREDENTIALS],
            ))
        elif acao == EVIL_ORIGIN:
            findings.append(InjFinding(
                finding_type=InjFindingType.CORS_REFLECTION,
                severity=FINDING_SEVERITY[InjFindingType.CORS_REFLECTION],
                endpoint=ep.full_url,
                method="OPTIONS",
                description=f"Server reflects ANY injected Origin exactly in ACAO.",
                proof=f"ACAO: {acao}",
                remediation=FINDING_REMEDIATION[InjFindingType.CORS_REFLECTION],
            ))
        elif acao == "*":
            findings.append(InjFinding(
                finding_type=InjFindingType.CORS_WILDCARD,
                severity=FINDING_SEVERITY[InjFindingType.CORS_WILDCARD],
                endpoint=ep.full_url,
                method="OPTIONS",
                description="Wildcard CORS enabled. Allows universal origin access.",
                proof=f"ACAO: *",
                remediation=FINDING_REMEDIATION[InjFindingType.CORS_WILDCARD],
            ))
        return findings

    # ── Helpers ──────────────────────────────

    def _get(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

    def _post(self, url: str, method: str, body: dict) -> requests.Response | None:
        try:
            m = method.upper()
            if m == "POST": return self.session.post(url, json=body, timeout=self.timeout)
            elif m == "PUT": return self.session.put(url, json=body, timeout=self.timeout)
            elif m == "PATCH": return self.session.patch(url, json=body, timeout=self.timeout)
        except requests.RequestException:
            return None
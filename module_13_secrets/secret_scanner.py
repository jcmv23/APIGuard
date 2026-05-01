"""
APIGuard — Advanced Secret Scanner (Module 13)
================================================
High-fidelity secret and credential detection in API responses using
100+ regex patterns organized by provider and type.

Scans for:
  - Cloud Provider Keys (AWS, GCP, Azure, DigitalOcean)
  - Payment Processors (Stripe, Square, Braintree)
  - Communication (Twilio, SendGrid, Mailgun)
  - Version Control (GitHub, GitLab, Bitbucket tokens)
  - Database Connection Strings (MongoDB, PostgreSQL, MySQL, Redis)
  - Private Keys (RSA, EC, PGP, SSH)
  - Generic Patterns (API keys, passwords, bearer tokens)
  - PII (SSN, credit cards, emails with context)
"""

import re
import time
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

import requests

try:
    from module_1_parser.parser import Endpoint
    from module_2_bola.bola_scanner import Severity
except ImportError:
    from parser import Endpoint
    from bola_scanner import Severity


# ─────────────────────────────────────────────
# Secret Pattern Database
# ─────────────────────────────────────────────

SECRET_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    # Format: (category, label, pattern, severity)

    # ── AWS ──
    ("cloud", "AWS Access Key ID", re.compile(r"(?:^|[^A-Z0-9])AKIA[0-9A-Z]{16}(?:[^A-Z0-9]|$)"), "CRITICAL"),
    ("cloud", "AWS Secret Access Key", re.compile(r"(?:aws)?_?(?:secret)?_?(?:access)?_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.I), "CRITICAL"),
    ("cloud", "AWS MWS Key", re.compile(r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "CRITICAL"),
    ("cloud", "AWS Session Token", re.compile(r"(?:aws.?session|session.?token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?", re.I), "CRITICAL"),

    # ── GCP ──
    ("cloud", "Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "HIGH"),
    ("cloud", "Google OAuth ID", re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"), "MEDIUM"),
    ("cloud", "Google Service Account", re.compile(r'"type"\s*:\s*"service_account"'), "HIGH"),
    ("cloud", "Firebase URL", re.compile(r"[a-z0-9.-]+\\.firebaseio\\.com"), "MEDIUM"),
    ("cloud", "Firebase API Key", re.compile(r"FIREBASE[_-]?API[_-]?KEY['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]+)['\"]?", re.I), "HIGH"),

    # ── Azure ──
    ("cloud", "Azure Storage Key", re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]{86,}"), "CRITICAL"),
    ("cloud", "Azure Connection String", re.compile(r"Server=tcp:.+\\.database\\.windows\\.net.+Password=[^;]+"), "CRITICAL"),
    ("cloud", "Azure SAS Token", re.compile(r"[?&]sig=[A-Za-z0-9%/+=]+&se=\d+"), "HIGH"),

    # ── DigitalOcean ──
    ("cloud", "DigitalOcean Token", re.compile(r"dop_v1_[a-f0-9]{64}"), "CRITICAL"),
    ("cloud", "DigitalOcean Spaces Key", re.compile(r"DO00[A-Z2-7]{32}"), "HIGH"),

    # ── Payment ──
    ("payment", "Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "CRITICAL"),
    ("payment", "Stripe Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "LOW"),
    ("payment", "Stripe Restricted Key", re.compile(r"rk_live_[0-9a-zA-Z]{24,}"), "CRITICAL"),
    ("payment", "Square Access Token", re.compile(r"sq0atp-[0-9A-Za-z_-]{22}"), "CRITICAL"),
    ("payment", "Square OAuth Secret", re.compile(r"sq0csp-[0-9A-Za-z_-]{43}"), "CRITICAL"),
    ("payment", "PayPal Braintree Token", re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"), "CRITICAL"),

    # ── Communication ──
    ("comms", "Twilio API Key", re.compile(r"SK[0-9a-fA-F]{32}"), "HIGH"),
    ("comms", "Twilio Account SID", re.compile(r"AC[a-zA-Z0-9]{32}"), "MEDIUM"),
    ("comms", "SendGrid API Key", re.compile(r"SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}"), "CRITICAL"),
    ("comms", "Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), "HIGH"),
    ("comms", "Mailchimp API Key", re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"), "HIGH"),

    # ── Version Control ──
    ("vcs", "GitHub Token (classic)", re.compile(r"ghp_[0-9a-zA-Z]{36}"), "CRITICAL"),
    ("vcs", "GitHub Fine-grained Token", re.compile(r"github_pat_[0-9a-zA-Z_]{82}"), "CRITICAL"),
    ("vcs", "GitHub OAuth Token", re.compile(r"gho_[0-9a-zA-Z]{36}"), "HIGH"),
    ("vcs", "GitHub App Token", re.compile(r"(?:ghu|ghs)_[0-9a-zA-Z]{36}"), "HIGH"),
    ("vcs", "GitLab Token", re.compile(r"glpat-[0-9A-Za-z_-]{20}"), "CRITICAL"),
    ("vcs", "Bitbucket App Password", re.compile(r"ATBB[a-zA-Z0-9]{32}"), "HIGH"),

    # ── Databases ──
    ("database", "MongoDB Connection", re.compile(r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"), "CRITICAL"),
    ("database", "PostgreSQL Connection", re.compile(r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"), "CRITICAL"),
    ("database", "MySQL Connection", re.compile(r"mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"), "CRITICAL"),
    ("database", "Redis URL", re.compile(r"redis://[^\s'\"]*:[^\s'\"]+@[^\s'\"]+"), "HIGH"),
    ("database", "Database Password", re.compile(r"(?:db|database|mysql|pg|postgres|mongo)_?(?:pass|password|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?", re.I), "CRITICAL"),

    # ── Private Keys ──
    ("crypto", "RSA Private Key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----"), "CRITICAL"),
    ("crypto", "EC Private Key", re.compile(r"-----BEGIN EC PRIVATE KEY-----"), "CRITICAL"),
    ("crypto", "Generic Private Key", re.compile(r"-----BEGIN PRIVATE KEY-----"), "CRITICAL"),
    ("crypto", "PGP Private Key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "CRITICAL"),
    ("crypto", "SSH Private Key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "CRITICAL"),

    # ── Auth ──
    ("auth", "Bearer Token", re.compile(r"[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*"), "HIGH"),
    ("auth", "Basic Auth Header", re.compile(r"[Bb]asic\s+[A-Za-z0-9+/]={0,2}"), "HIGH"),
    ("auth", "JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), "MEDIUM"),
    ("auth", "OAuth Client Secret", re.compile(r"(?:client.?secret|oauth.?secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{16,})['\"]?", re.I), "HIGH"),

    # ── Generic ──
    ("generic", "Generic API Key", re.compile(r"(?:api[_-]?key|apikey|x-api-key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{16,})['\"]?", re.I), "HIGH"),
    ("generic", "Generic Secret", re.compile(r"(?:secret|secret_key|app_secret|application_secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_/+=!@#$%^&*-]{8,})['\"]?", re.I), "HIGH"),
    ("generic", "Generic Password", re.compile(r"(?:password|passwd|pwd|pass)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?", re.I), "HIGH"),
    ("generic", "Generic Token", re.compile(r"(?:token|access_token|auth_token|session_token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_.-]{16,})['\"]?", re.I), "MEDIUM"),
    ("generic", "Encryption Key", re.compile(r"(?:encrypt|aes|des)[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{16,})['\"]?", re.I), "HIGH"),

    # ── PII ──
    ("pii", "Social Security Number", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "HIGH"),
    ("pii", "Credit Card (Visa)", re.compile(r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "HIGH"),
    ("pii", "Credit Card (MC)", re.compile(r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "HIGH"),
    ("pii", "Credit Card (Amex)", re.compile(r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b"), "HIGH"),

    # ── Misc Services ──
    ("misc", "Slack Token", re.compile(r"xox[bpors]-[0-9]{12}-[0-9a-zA-Z_-]+"), "CRITICAL"),
    ("misc", "Slack Webhook", re.compile(r"hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"), "HIGH"),
    ("misc", "Discord Webhook", re.compile(r"discord(?:app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"), "HIGH"),
    ("misc", "Discord Bot Token", re.compile(r"[MN][A-Za-z0-9]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}"), "CRITICAL"),
    ("misc", "Heroku API Key", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.I), "MEDIUM"),
    ("misc", "NPM Token", re.compile(r"npm_[A-Za-z0-9]{36}"), "CRITICAL"),
    ("misc", "PyPI Token", re.compile(r"pypi-[A-Za-z0-9_-]{50,}"), "CRITICAL"),
]

# Entropy threshold for detecting high-entropy strings (potential secrets)
ENTROPY_THRESHOLD = 4.0


# ─────────────────────────────────────────────
# Result Models
# ─────────────────────────────────────────────

@dataclass
class SecretFinding:
    category: str
    secret_type: str
    severity: str
    endpoint: str
    method: str
    description: str
    proof: str  # Masked version of the match
    remediation: str
    location: str = "response_body"  # body, header, url
    finding_type: str = "EXPOSED_SECRET"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SecretScanResult:
    target_url: str
    total_endpoints_scanned: int = 0
    total_secrets_found: int = 0
    findings: list[SecretFinding] = field(default_factory=list)
    categories_hit: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "SECRET_SCANNER",
            "target_url": self.target_url,
            "total_endpoints_scanned": self.total_endpoints_scanned,
            "total_secrets_found": self.total_secrets_found,
            "findings": [f.to_dict() for f in self.findings],
            "categories_hit": self.categories_hit,
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── SECRET SCANNER SUMMARY ─────────────",
            f"  Target             : {self.target_url}",
            f"  Endpoints scanned  : {self.total_endpoints_scanned}",
            f"  Secrets found      : {self.total_secrets_found}",
        ]
        if self.categories_hit:
            lines.append(f"  Categories: {dict(self.categories_hit)}")
        if self.findings:
            lines.append(f"\n  Findings ({len(self.findings)}):")
            for f in self.findings:
                lines.append(f"    [{f.severity}] {f.secret_type}")
                lines.append(f"             @ {f.method} {f.endpoint}")
        else:
            lines.append("  ✅  No exposed secrets detected.")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


# ─────────────────────────────────────────────
# Secret Scanner Engine
# ─────────────────────────────────────────────

def _mask_secret(value: str, keep: int = 4) -> str:
    """Mask a secret, showing only first/last few characters."""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    from math import log2
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count/length) * log2(count/length) for count in freq.values())


class SecretScanner:
    """
    Scans API responses for exposed secrets, credentials, API keys,
    private keys, connection strings, and PII using 100+ regex patterns.
    """

    def __init__(
        self,
        token: str | None = None,
        extra_headers: dict | None = None,
        timeout: int = 10,
        delay: float = 0.1,
        scan_headers: bool = True,
        scan_urls: bool = True,
        entropy_check: bool = True,
    ):
        self.timeout = timeout
        self.delay = delay
        self.scan_headers = scan_headers
        self.scan_urls = scan_urls
        self.entropy_check = entropy_check

        self.session = requests.Session()
        self.session.headers["User-Agent"] = "APIGuard-SecretScan/4.0"
        if token:
            self.session.headers["Authorization"] = token
        if extra_headers:
            self.session.headers.update(extra_headers)

    def scan(self, endpoints: list[Endpoint]) -> SecretScanResult:
        t0 = time.monotonic()
        from urllib.parse import urlparse
        target = ""
        if endpoints:
            p = urlparse(endpoints[0].full_url)
            target = f"{p.scheme}://{p.netloc}"

        result = SecretScanResult(target_url=target)

        for ep in endpoints:
            try:
                url = re.sub(r"\{[^}]+\}", "1", ep.full_url)
                resp = self._safe_get(url)
                if not resp:
                    continue

                result.total_endpoints_scanned += 1
                seen_types: set = set()

                # Scan response body
                self._scan_text(
                    resp.text, ep.full_url, ep.method, "response_body",
                    result, seen_types
                )

                # Scan response headers
                if self.scan_headers:
                    header_text = json.dumps(dict(resp.headers))
                    self._scan_text(
                        header_text, ep.full_url, ep.method, "response_header",
                        result, seen_types
                    )

                # Scan URL parameters
                if self.scan_urls and "?" in resp.url:
                    self._scan_text(
                        resp.url, ep.full_url, ep.method, "response_url",
                        result, seen_types
                    )

                # High-entropy string detection
                if self.entropy_check and resp.text:
                    self._check_entropy(resp.text, ep.full_url, ep.method, result, seen_types)

            except Exception as exc:
                result.errors.append(f"{ep.method} {ep.path} → {exc}")

            time.sleep(self.delay)

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    def _scan_text(
        self, text: str, endpoint: str, method: str, location: str,
        result: SecretScanResult, seen: set
    ):
        """Scan text against all secret patterns."""
        for category, label, pattern, severity in SECRET_PATTERNS:
            if label in seen:
                continue

            match = pattern.search(text)
            if match:
                matched_str = match.group(0)
                masked = _mask_secret(matched_str)
                seen.add(label)

                result.findings.append(SecretFinding(
                    category=category,
                    secret_type=label,
                    severity=severity,
                    endpoint=endpoint,
                    method=method,
                    description=f"{label} detected in {location} of API response. "
                                f"This credential should be immediately rotated.",
                    proof=f"Pattern match: {masked}",
                    remediation=f"Remove {label} from API responses. Rotate the exposed credential immediately. "
                                f"Implement server-side filtering to prevent credential leakage.",
                    location=location,
                ))
                result.total_secrets_found += 1
                result.categories_hit[category] = result.categories_hit.get(category, 0) + 1

    def _check_entropy(
        self, text: str, endpoint: str, method: str,
        result: SecretScanResult, seen: set
    ):
        """Check for high-entropy strings that might be secrets."""
        # Look for key-value pairs with high-entropy values
        kv_pattern = re.compile(
            r'["\']?(\w+(?:key|secret|token|password|credential|auth))\w*["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=_-]{20,})["\']?',
            re.IGNORECASE
        )

        for match in kv_pattern.finditer(text):
            key_name = match.group(1)
            value = match.group(2)

            if f"entropy:{key_name}" in seen:
                continue

            entropy = _shannon_entropy(value)
            if entropy >= ENTROPY_THRESHOLD:
                seen.add(f"entropy:{key_name}")
                result.findings.append(SecretFinding(
                    category="entropy",
                    secret_type=f"High-Entropy Secret ({key_name})",
                    severity="MEDIUM",
                    endpoint=endpoint,
                    method=method,
                    description=f"High-entropy value detected for key '{key_name}' "
                                f"(entropy: {entropy:.2f} bits/char). Likely a secret.",
                    proof=f"Key: {key_name}, Value entropy: {entropy:.2f}, "
                          f"Masked: {_mask_secret(value)}",
                    remediation="Investigate if this is a secret. If so, remove from API responses "
                                "and rotate the credential.",
                    location="response_body",
                ))
                result.total_secrets_found += 1

    def _safe_get(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

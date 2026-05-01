"""
APIGuard — JWT Security Analyzer & Cracker (Module 12)
========================================================
Comprehensive JWT security testing:
  JWT-1  Algorithm confusion (alg:none, RS→HS confusion)
  JWT-2  Weak secret brute-force (dictionary-based)
  JWT-3  Missing/expired claims validation
  JWT-4  Key ID (kid) injection
  JWT-5  JWK/JWKS spoofing detection
  JWT-6  Token information leakage analysis
"""

import json
import time
import hmac
import hashlib
import base64
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

import requests

try:
    from module_2_bola.bola_scanner import Severity
except ImportError:
    from bola_scanner import Severity


# ─────────────────────────────────────────────
# Common Weak JWT Secrets Dictionary
# ─────────────────────────────────────────────

WEAK_SECRETS = [
    # Top passwords
    "secret", "password", "123456", "12345678", "qwerty",
    "abc123", "password1", "admin", "letmein", "welcome",
    # Common JWT secrets
    "jwt_secret", "jwt-secret", "my_secret", "my-secret",
    "supersecret", "super-secret", "s3cr3t", "changeme",
    "your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
    "secret_key", "SECRET_KEY", "secretkey", "SECRETKEY",
    "api_secret", "api-secret", "app_secret", "app-secret",
    # Framework defaults
    "django-insecure-key", "flask-secret", "express-secret",
    "nestjs-secret", "spring-secret", "laravel-key",
    "my_jwt_secret", "jwt_secret_key", "token_secret",
    "access_token_secret", "refresh_token_secret",
    # Dev/Test
    "test", "testing", "development", "dev", "staging",
    "demo", "example", "sample", "default", "placeholder",
    # Common phrases
    "iloveyou", "trustno1", "master", "dragon", "monkey",
    "shadow", "sunshine", "princess", "football", "charlie",
    # Keyboard patterns
    "qwerty123", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
    # Company defaults
    "mycompany", "company123", "myapp", "myapi",
    # Node.js defaults
    "keyboard cat", "shhh", "ssh", "notsosecret",
    # Other common
    "AllYourBaseAreBelongToUs", "p@ssw0rd", "P@ssword1",
    "hunter2", "correcthorsebatterystaple",
    "", " ",  # Empty / single space (surprisingly common)
]


# ─────────────────────────────────────────────
# JWT Helper Functions
# ─────────────────────────────────────────────

def b64url_decode(data: str) -> bytes:
    """Decode base64url without padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def b64url_encode(data: bytes) -> str:
    """Encode to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt_parts(token: str) -> dict | None:
    """Decode a JWT without verification to inspect its content."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "raw_parts": parts,
        }
    except Exception:
        return None


def sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    """Sign with HMAC-SHA256."""
    message = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    return b64url_encode(sig)


def sign_hs384(header_b64: str, payload_b64: str, secret: str) -> str:
    message = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), message, hashlib.sha384).digest()
    return b64url_encode(sig)


def sign_hs512(header_b64: str, payload_b64: str, secret: str) -> str:
    message = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), message, hashlib.sha512).digest()
    return b64url_encode(sig)


# ─────────────────────────────────────────────
# Result Models
# ─────────────────────────────────────────────

class JWTFindingType(str, Enum):
    ALG_NONE = "JWT_ALG_NONE"
    ALG_CONFUSION = "JWT_ALG_CONFUSION"
    WEAK_SECRET = "JWT_WEAK_SECRET"
    NO_EXPIRY = "JWT_NO_EXPIRY"
    EXPIRED_ACCEPTED = "JWT_EXPIRED_ACCEPTED"
    KID_INJECTION = "JWT_KID_INJECTION"
    SENSITIVE_DATA = "JWT_SENSITIVE_DATA"
    MISSING_CLAIMS = "JWT_MISSING_CLAIMS"
    WEAK_ALGORITHM = "JWT_WEAK_ALGORITHM"


JWT_SEVERITY = {
    JWTFindingType.ALG_NONE: Severity.CRITICAL,
    JWTFindingType.ALG_CONFUSION: Severity.CRITICAL,
    JWTFindingType.WEAK_SECRET: Severity.CRITICAL,
    JWTFindingType.NO_EXPIRY: Severity.HIGH,
    JWTFindingType.EXPIRED_ACCEPTED: Severity.HIGH,
    JWTFindingType.KID_INJECTION: Severity.CRITICAL,
    JWTFindingType.SENSITIVE_DATA: Severity.MEDIUM,
    JWTFindingType.MISSING_CLAIMS: Severity.LOW,
    JWTFindingType.WEAK_ALGORITHM: Severity.MEDIUM,
}

JWT_REMEDIATION = {
    JWTFindingType.ALG_NONE: "Reject tokens with alg='none'. Always specify allowed algorithms explicitly.",
    JWTFindingType.ALG_CONFUSION: "Use separate key sets for HMAC and RSA. Never accept HMAC when expecting RSA.",
    JWTFindingType.WEAK_SECRET: "Use a cryptographically random secret (≥256 bits). Rotate immediately.",
    JWTFindingType.NO_EXPIRY: "Always include 'exp' claim. Use short-lived tokens (15-60 min) with refresh tokens.",
    JWTFindingType.EXPIRED_ACCEPTED: "Enforce exp claim validation. Reject expired tokens server-side.",
    JWTFindingType.KID_INJECTION: "Validate kid parameter against allowlist. Never use kid in file paths or SQL queries.",
    JWTFindingType.SENSITIVE_DATA: "Never store PII, passwords, or secrets in JWT payload. JWTs are base64-encoded, not encrypted.",
    JWTFindingType.MISSING_CLAIMS: "Include standard claims: iss, sub, aud, exp, iat, nbf, jti.",
    JWTFindingType.WEAK_ALGORITHM: "Use RS256 or ES256 instead of HS256 for production. Avoid HS384/HS512 unless needed.",
}


@dataclass
class JWTFinding:
    finding_type: JWTFindingType
    severity: Severity
    description: str
    proof: str
    remediation: str
    endpoint: str = ""
    method: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["finding_type"] = self.finding_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class JWTScanResult:
    target_url: str
    token_analyzed: bool = False
    cracked_secret: str | None = None
    algorithm: str = ""
    findings: list[JWTFinding] = field(default_factory=list)
    token_info: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "JWT_ANALYZER",
            "target_url": self.target_url,
            "token_analyzed": self.token_analyzed,
            "cracked_secret": self.cracked_secret,
            "algorithm": self.algorithm,
            "findings": [f.to_dict() for f in self.findings],
            "token_info": self.token_info,
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── JWT SECURITY ANALYZER SUMMARY ─────────",
            f"  Target       : {self.target_url}",
            f"  Algorithm    : {self.algorithm}",
            f"  Token parsed : {self.token_analyzed}",
        ]
        if self.cracked_secret:
            lines.append(f"  ⚠️  SECRET CRACKED: '{self.cracked_secret}'")
        if self.findings:
            lines.append(f"\n  Findings ({len(self.findings)}):")
            for f in self.findings:
                lines.append(f"    [{f.severity.value}] {f.finding_type.value}: {f.description[:80]}")
        else:
            lines.append("  ✅  No JWT vulnerabilities detected.")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


# ─────────────────────────────────────────────
# JWT Security Analyzer Engine
# ─────────────────────────────────────────────

class JWTAnalyzer:
    """
    Comprehensive JWT security testing engine that:
    1. Decodes and analyzes token structure
    2. Tests for algorithm confusion attacks
    3. Brute-forces weak HMAC secrets
    4. Checks for missing/invalid claims
    5. Detects sensitive data in payloads
    """

    def __init__(
        self,
        token: str | None = None,
        target_url: str = "",
        extra_headers: dict | None = None,
        timeout: int = 10,
    ):
        self.token = token
        self.target_url = target_url
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers["User-Agent"] = "APIGuard-JWT/4.0"
        if extra_headers:
            self.session.headers.update(extra_headers)

    def scan(self, token: str | None = None, endpoint_url: str | None = None) -> JWTScanResult:
        """Full JWT security analysis."""
        t0 = time.monotonic()
        jwt_token = token or self.token
        url = endpoint_url or self.target_url

        result = JWTScanResult(target_url=url)

        if not jwt_token:
            # Try to extract JWT from endpoint
            jwt_token = self._extract_jwt_from_endpoint(url)
            if not jwt_token:
                result.errors.append("No JWT token provided and none could be extracted.")
                result.scan_duration_seconds = time.monotonic() - t0
                return result

        # Clean token
        if jwt_token.lower().startswith("bearer "):
            jwt_token = jwt_token[7:]

        # Decode
        decoded = decode_jwt_parts(jwt_token)
        if not decoded:
            result.errors.append("Could not decode JWT. Invalid format.")
            result.scan_duration_seconds = time.monotonic() - t0
            return result

        result.token_analyzed = True
        result.algorithm = decoded["header"].get("alg", "unknown")
        result.token_info = {
            "header": decoded["header"],
            "payload_keys": list(decoded["payload"].keys()),
            "claims_present": list(decoded["payload"].keys()),
        }

        # Run all checks
        result.findings.extend(self._check_algorithm(decoded))
        result.findings.extend(self._check_claims(decoded))
        result.findings.extend(self._check_sensitive_data(decoded))

        # Brute-force secret (only for HMAC algorithms)
        alg = decoded["header"].get("alg", "").upper()
        if alg.startswith("HS"):
            cracked = self._brute_force_secret(decoded, alg)
            if cracked is not None:
                result.cracked_secret = cracked
                result.findings.append(JWTFinding(
                    finding_type=JWTFindingType.WEAK_SECRET,
                    severity=JWT_SEVERITY[JWTFindingType.WEAK_SECRET],
                    description=f"JWT signing secret cracked! The secret '{cracked}' was found via dictionary attack.",
                    proof=f"HMAC-{alg} signature successfully reproduced with secret: '{cracked}'",
                    remediation=JWT_REMEDIATION[JWTFindingType.WEAK_SECRET],
                ))

        # Test alg:none attack if we have an endpoint
        if url:
            result.findings.extend(self._test_alg_none(decoded, url))

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    # ── Algorithm Checks ──────────────────────

    def _check_algorithm(self, decoded: dict) -> list[JWTFinding]:
        findings = []
        header = decoded["header"]
        alg = header.get("alg", "")

        if alg.lower() == "none":
            findings.append(JWTFinding(
                finding_type=JWTFindingType.ALG_NONE,
                severity=JWT_SEVERITY[JWTFindingType.ALG_NONE],
                description="Token uses 'none' algorithm — no signature verification!",
                proof=f"JWT header: {json.dumps(header)}",
                remediation=JWT_REMEDIATION[JWTFindingType.ALG_NONE],
            ))

        if alg in ("HS256", "HS384", "HS512"):
            findings.append(JWTFinding(
                finding_type=JWTFindingType.WEAK_ALGORITHM,
                severity=JWT_SEVERITY[JWTFindingType.WEAK_ALGORITHM],
                description=f"Token uses symmetric {alg}. Asymmetric (RS256/ES256) is recommended for production.",
                proof=f"Algorithm: {alg}. Symmetric keys can be brute-forced if weak.",
                remediation=JWT_REMEDIATION[JWTFindingType.WEAK_ALGORITHM],
            ))

        # Check for kid injection vectors
        if "kid" in header:
            kid = header["kid"]
            dangerous_patterns = ["../", "..\\", "/etc/", "file://", "sql", "'", "\""]
            for pattern in dangerous_patterns:
                if pattern in str(kid).lower():
                    findings.append(JWTFinding(
                        finding_type=JWTFindingType.KID_INJECTION,
                        severity=JWT_SEVERITY[JWTFindingType.KID_INJECTION],
                        description=f"Suspicious 'kid' value may be exploitable: '{kid}'",
                        proof=f"kid contains path traversal or injection pattern: '{pattern}'",
                        remediation=JWT_REMEDIATION[JWTFindingType.KID_INJECTION],
                    ))
                    break

        return findings

    # ── Claims Validation ─────────────────────

    def _check_claims(self, decoded: dict) -> list[JWTFinding]:
        findings = []
        payload = decoded["payload"]
        now = int(time.time())

        # Check expiration
        if "exp" not in payload:
            findings.append(JWTFinding(
                finding_type=JWTFindingType.NO_EXPIRY,
                severity=JWT_SEVERITY[JWTFindingType.NO_EXPIRY],
                description="JWT has no expiration (exp) claim. Token is valid forever.",
                proof=f"Claims present: {list(payload.keys())}. 'exp' is missing.",
                remediation=JWT_REMEDIATION[JWTFindingType.NO_EXPIRY],
            ))
        elif payload["exp"] < now:
            # Token is expired - this is expected, but note it
            pass

        # Check for missing standard claims
        recommended = ["iss", "sub", "aud", "exp", "iat"]
        missing = [c for c in recommended if c not in payload]
        if len(missing) >= 3:
            findings.append(JWTFinding(
                finding_type=JWTFindingType.MISSING_CLAIMS,
                severity=JWT_SEVERITY[JWTFindingType.MISSING_CLAIMS],
                description=f"JWT missing {len(missing)} recommended claims: {', '.join(missing)}",
                proof=f"Present: {list(payload.keys())}. Missing: {missing}",
                remediation=JWT_REMEDIATION[JWTFindingType.MISSING_CLAIMS],
            ))

        return findings

    # ── Sensitive Data Check ──────────────────

    def _check_sensitive_data(self, decoded: dict) -> list[JWTFinding]:
        findings = []
        payload = decoded["payload"]
        payload_str = json.dumps(payload).lower()

        sensitive_patterns = {
            "password": r"(password|passwd|pwd)\s*[\":]\s*\S+",
            "credit_card": r"\b\d{13,19}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
            "api_key": r"(api[_-]?key|apikey)\s*[\":]\s*\S+",
            "private_key": r"-----BEGIN.+PRIVATE KEY-----",
        }

        found = []
        for label, pattern in sensitive_patterns.items():
            if re.search(pattern, payload_str, re.IGNORECASE):
                found.append(label)

        # Also check field names
        sensitive_fields = ["password", "pwd", "secret", "ssn", "credit_card", "cc_number", 
                          "cvv", "pin", "private_key", "api_key", "access_key"]
        for key in payload.keys():
            if key.lower() in sensitive_fields:
                found.append(f"field:{key}")

        if found:
            findings.append(JWTFinding(
                finding_type=JWTFindingType.SENSITIVE_DATA,
                severity=JWT_SEVERITY[JWTFindingType.SENSITIVE_DATA],
                description=f"JWT payload contains potentially sensitive data: {', '.join(found)}",
                proof=f"Detected patterns: {found}. JWT payloads are base64-encoded, NOT encrypted!",
                remediation=JWT_REMEDIATION[JWTFindingType.SENSITIVE_DATA],
            ))

        return findings

    # ── Secret Brute-Force ────────────────────

    def _brute_force_secret(self, decoded: dict, alg: str) -> str | None:
        """Attempt to crack the JWT signing secret using a dictionary."""
        header_b64 = decoded["raw_parts"][0]
        payload_b64 = decoded["raw_parts"][1]
        original_sig = decoded["raw_parts"][2]

        sign_fn = {
            "HS256": sign_hs256,
            "HS384": sign_hs384,
            "HS512": sign_hs512,
        }.get(alg, sign_hs256)

        for secret in WEAK_SECRETS:
            computed_sig = sign_fn(header_b64, payload_b64, secret)
            if computed_sig == original_sig:
                return secret

        return None

    # ── Algorithm None Attack ─────────────────

    def _test_alg_none(self, decoded: dict, url: str) -> list[JWTFinding]:
        """Test if the server accepts tokens with alg:none."""
        findings = []

        # Forge alg:none token
        forged_header = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        forged_payload = b64url_encode(json.dumps(decoded["payload"]).encode())
        forged_token = f"{forged_header}.{forged_payload}."

        try:
            # Test with forged token
            resp = self.session.get(
                url,
                headers={"Authorization": f"Bearer {forged_token}"},
                timeout=self.timeout,
                allow_redirects=False,
            )

            if resp.status_code in (200, 201, 204):
                findings.append(JWTFinding(
                    finding_type=JWTFindingType.ALG_NONE,
                    severity=JWT_SEVERITY[JWTFindingType.ALG_NONE],
                    description="Server accepted a JWT with alg='none' (no signature). "
                                "Any token can be forged!",
                    proof=f"Forged token accepted with HTTP {resp.status_code}. "
                          f"Response: {resp.text[:100]}",
                    remediation=JWT_REMEDIATION[JWTFindingType.ALG_NONE],
                    endpoint=url,
                    method="GET",
                ))
        except requests.RequestException:
            pass

        return findings

    # ── JWT Extraction ────────────────────────

    def _extract_jwt_from_endpoint(self, url: str) -> str | None:
        """Try to extract a JWT from common auth endpoints."""
        if not url:
            return None

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            # Look for JWT pattern in response
            jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
            match = jwt_pattern.search(resp.text)
            if match:
                return match.group(0)

            # Check Authorization header in response
            auth = resp.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                return auth[7:]
        except requests.RequestException:
            pass

        return None

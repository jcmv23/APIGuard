"""
APIGuard - Module 4: Auth/JWT Scanner
=======================================
Detecta problemas de autenticación y validación de tokens JWT.

Vulnerabilidades cubiertas:
  AUTH-1  Endpoint sin autenticación que retorna datos sensibles
  AUTH-2  JWT sin campo exp (nunca expira)
  AUTH-3  JWT con exp muy lejano (>24h)
  AUTH-4  JWT con algoritmo 'none' aceptado
  AUTH-5  JWT firmado con secret débil (diccionario)
  AUTH-6  API key / secret expuesto en response headers o body
  AUTH-7  Token aceptado después de su fecha de expiración
"""

import base64
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
    from parser import Endpoint          # type: ignore
    from bola_scanner import Severity    # type: ignore

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

# Common weak JWT secrets to brute-force
WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "test",
    "changeme", "supersecret", "jwt_secret", "mysecret", "key",
    "private", "token", "access", "auth", "api_secret", "letmein",
    "abc123", "pass", "root", "topsecret", "s3cr3t", "hack",
]

# Response header names that may leak secrets
SENSITIVE_HEADERS = re.compile(
    r"(x-api-key|x-secret|x-token|x-access-token|authorization|"
    r"x-auth-token|x-internal-token|api-key|apikey)",
    re.IGNORECASE,
)

# JSON body keys that may contain exposed secrets
SENSITIVE_BODY_KEYS = re.compile(
    r"(apikey|api_key|secret|accesstoken|access_token|refreshtoken|"
    r"refresh_token|privatekey|private_key|clientsecret|client_secret|"
    r"password|passwd|credentials|masterkey)",
    re.IGNORECASE,
)

# Patterns that look like real token values (not placeholders)
TOKEN_VALUE_PATTERN = re.compile(
    r"(eyJ[A-Za-z0-9_-]{10,}|sk_live_[A-Za-z0-9]{10,}|"
    r"pk_live_[A-Za-z0-9]{10,}|[A-Za-z0-9]{32,})"
)


# ─────────────────────────────────────────────
# Result models
# ─────────────────────────────────────────────

class AuthFindingType(str, Enum):
    MISSING_AUTH         = "MISSING_AUTH"
    JWT_NO_EXPIRY        = "JWT_NO_EXPIRY"
    JWT_LONG_EXPIRY      = "JWT_LONG_EXPIRY"
    JWT_ALG_NONE         = "JWT_ALG_NONE"
    JWT_WEAK_SECRET      = "JWT_WEAK_SECRET"
    EXPOSED_SECRET       = "EXPOSED_SECRET"
    EXPIRED_TOKEN_ACCEPTED = "EXPIRED_TOKEN_ACCEPTED"


FINDING_SEVERITY: dict[AuthFindingType, Severity] = {
    AuthFindingType.MISSING_AUTH:           Severity.CRITICAL,
    AuthFindingType.JWT_NO_EXPIRY:          Severity.HIGH,
    AuthFindingType.JWT_LONG_EXPIRY:        Severity.MEDIUM,
    AuthFindingType.JWT_ALG_NONE:           Severity.CRITICAL,
    AuthFindingType.JWT_WEAK_SECRET:        Severity.CRITICAL,
    AuthFindingType.EXPOSED_SECRET:         Severity.HIGH,
    AuthFindingType.EXPIRED_TOKEN_ACCEPTED: Severity.CRITICAL,
}

FINDING_REMEDIATION: dict[AuthFindingType, str] = {
    AuthFindingType.MISSING_AUTH:
        "Requerir autenticación (Bearer token / API key) en todos los endpoints que retornen datos.",
    AuthFindingType.JWT_NO_EXPIRY:
        "Incluir claim 'exp' en el JWT. Tiempo de expiración recomendado: 15-60 minutos.",
    AuthFindingType.JWT_LONG_EXPIRY:
        "Reducir el tiempo de expiración del JWT a máximo 24 horas para access tokens.",
    AuthFindingType.JWT_ALG_NONE:
        "Rechazar tokens con alg='none'. Validar explícitamente el algoritmo esperado (ej: HS256).",
    AuthFindingType.JWT_WEAK_SECRET:
        "Usar un secret de al menos 256 bits generado criptográficamente. Nunca usar palabras comunes.",
    AuthFindingType.EXPOSED_SECRET:
        "Nunca retornar API keys, tokens o secrets en responses. Usar variables de entorno y vaults.",
    AuthFindingType.EXPIRED_TOKEN_ACCEPTED:
        "Validar que el claim 'exp' del JWT sea mayor que el timestamp actual en cada request.",
}


@dataclass
class AuthFinding:
    finding_type: AuthFindingType
    severity: Severity
    endpoint: str
    method: str
    description: str
    proof: str
    remediation: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["finding_type"] = self.finding_type.value
        d["severity"] = self.severity.value
        return d

    def __str__(self) -> str:
        return (
            f"\n{'='*60}\n"
            f"  VULNERABILITY DETECTED\n"
            f"{'='*60}\n"
            f"  Type       : {self.finding_type.value}\n"
            f"  Severity   : {self.severity.value}\n"
            f"  Endpoint   : {self.method} {self.endpoint}\n"
            f"  Description: {self.description}\n"
            f"  Proof      : {self.proof}\n"
            f"  Remediation: {self.remediation}\n"
            f"{'='*60}"
        )


@dataclass
class AuthScanResult:
    target_url: str
    total_endpoints_tested: int = 0
    vulnerable_endpoints: int = 0
    findings: list[AuthFinding] = field(default_factory=list)
    jwt_analysis: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "AUTH_JWT",
            "target_url": self.target_url,
            "total_endpoints_tested": self.total_endpoints_tested,
            "vulnerable_endpoints": self.vulnerable_endpoints,
            "findings": [f.to_dict() for f in self.findings],
            "jwt_analysis": self.jwt_analysis,
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        by_sev: dict[str, list[AuthFinding]] = {}
        for f in self.findings:
            by_sev.setdefault(f.severity.value, []).append(f)

        lines = [
            "\n─── AUTH/JWT SCAN SUMMARY ───────────────────────────",
            f"  Target            : {self.target_url}",
            f"  Endpoints tested  : {self.total_endpoints_tested}",
            f"  Vulnerable        : {self.vulnerable_endpoints}",
            f"  Duration          : {self.scan_duration_seconds:.1f}s",
        ]
        if self.jwt_analysis:
            lines.append(f"  JWT analysis      : {self.jwt_analysis}")
        if self.findings:
            lines.append("\n  Findings:")
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                for f in by_sev.get(sev, []):
                    lines.append(f"    [{sev}] {f.finding_type.value} @ {f.method} {f.endpoint}")
        else:
            lines.append("  ✅  No Auth/JWT vulnerabilities detected.")
        if self.errors:
            lines.append(f"\n  ⚠️  Errors ({len(self.errors)}):")
            for e in self.errors[:5]:
                lines.append(f"    {e}")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


# ─────────────────────────────────────────────
# JWT utilities (no external lib needed)
# ─────────────────────────────────────────────

def _b64_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt_unsafe(token: str) -> tuple[dict, dict] | None:
    """Decode header and payload WITHOUT signature verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header  = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload
    except Exception:
        return None


def sign_jwt_hs256(header: dict, payload: dict, secret: str) -> str:
    """Create a valid HS256 JWT with the given secret."""
    import hmac, hashlib
    def _enc(d: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(d, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    h = _enc(header)
    p = _enc(payload)
    sig_bytes = hmac.new(
        secret.encode(), f"{h}.{p}".encode(), hashlib.sha256
    ).digest()
    sig = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"


def make_alg_none_token(payload: dict) -> str:
    """Create a JWT with alg=none and empty signature."""
    header = {"alg": "none", "typ": "JWT"}
    h = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{h}.{p}."


# ─────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────

class AuthScanner:
    """
    Usage
    -----
    scanner = AuthScanner(
        valid_token = "Bearer eyJ...",   # a working JWT for the test user
    )
    result = scanner.scan(endpoints)
    print(result.summary())
    """

    def __init__(
        self,
        valid_token: str | None = None,
        extra_headers: dict | None = None,
        timeout: int = 10,
        delay: float = 0.1,
        weak_secrets: list[str] | None = None,
        max_acceptable_exp_hours: float = 24.0,
    ):
        self.valid_token = valid_token
        self.timeout = timeout
        self.delay = delay
        self.weak_secrets = weak_secrets or WEAK_SECRETS
        self.max_acceptable_exp_hours = max_acceptable_exp_hours

        self.session = requests.Session()
        if extra_headers:
            self.session.headers.update(extra_headers)

    # ── Public API ────────────────────────────

    def scan(self, endpoints: list[Endpoint]) -> AuthScanResult:
        t0 = time.monotonic()
        from urllib.parse import urlparse
        target = ""
        if endpoints:
            p = urlparse(endpoints[0].full_url)
            target = f"{p.scheme}://{p.netloc}"

        result = AuthScanResult(target_url=target)

        # 1. Analyse the provided JWT
        if self.valid_token:
            result.jwt_analysis = self._analyse_jwt(self.valid_token)
            jwt_findings = self._check_jwt_properties(
                self.valid_token, result.jwt_analysis, endpoints
            )
            result.findings.extend(jwt_findings)

        # 2. Per-endpoint checks
        for ep in endpoints:
            try:
                ep_findings = self._check_endpoint(ep)
                result.total_endpoints_tested += 1
                result.findings.extend(ep_findings)
            except Exception as exc:
                result.errors.append(f"{ep.method} {ep.path} → {exc}")
            time.sleep(self.delay)

        result.vulnerable_endpoints = len({f.endpoint for f in result.findings})
        result.scan_duration_seconds = time.monotonic() - t0
        return result

    # ── JWT analysis ──────────────────────────

    def _analyse_jwt(self, token: str) -> dict:
        raw = token.replace("Bearer ", "").strip()
        decoded = decode_jwt_unsafe(raw)
        if not decoded:
            return {"valid_jwt": False}

        header, payload = decoded
        now = time.time()
        exp = payload.get("exp")
        iat = payload.get("iat")

        analysis = {
            "valid_jwt": True,
            "algorithm": header.get("alg", "unknown"),
            "has_exp": exp is not None,
            "has_iat": iat is not None,
            "has_sub": "sub" in payload or "user_id" in payload,
            "exp_timestamp": exp,
            "already_expired": (exp is not None and exp < now),
            "exp_hours_from_now": round((exp - now) / 3600, 1) if exp else None,
            "claims": list(payload.keys()),
        }
        return analysis

    def _check_jwt_properties(
        self, token: str, analysis: dict, endpoints: list[Endpoint]
    ) -> list[AuthFinding]:
        findings: list[AuthFinding] = []
        raw = token.replace("Bearer ", "").strip()
        decoded = decode_jwt_unsafe(raw)
        if not decoded or not analysis.get("valid_jwt"):
            return findings

        header, payload = decoded
        representative_ep = endpoints[0].full_url if endpoints else "N/A"
        representative_method = endpoints[0].method if endpoints else "N/A"

        def _make(ftype: AuthFindingType, desc: str, proof: str) -> AuthFinding:
            return AuthFinding(
                finding_type=ftype,
                severity=FINDING_SEVERITY[ftype],
                endpoint=representative_ep,
                method=representative_method,
                description=desc,
                proof=proof,
                remediation=FINDING_REMEDIATION[ftype],
            )

        # AUTH-2: No exp
        if not analysis["has_exp"]:
            findings.append(_make(
                AuthFindingType.JWT_NO_EXPIRY,
                "El JWT no contiene el claim 'exp'. El token nunca expira.",
                f"JWT payload keys: {analysis['claims']} — 'exp' ausente.",
            ))

        # AUTH-3: exp muy lejano
        elif analysis["exp_hours_from_now"] and analysis["exp_hours_from_now"] > self.max_acceptable_exp_hours:
            findings.append(_make(
                AuthFindingType.JWT_LONG_EXPIRY,
                f"El JWT expira en {analysis['exp_hours_from_now']:.0f}h "
                f"(máximo recomendado: {self.max_acceptable_exp_hours:.0f}h).",
                f"exp={analysis['exp_timestamp']} → {analysis['exp_hours_from_now']}h desde ahora.",
            ))

        # AUTH-4: alg none
        if header.get("alg", "").lower() in ("none", ""):
            findings.append(_make(
                AuthFindingType.JWT_ALG_NONE,
                "El JWT usa algoritmo 'none', sin firma criptográfica.",
                f"JWT header: {header}",
            ))

        # AUTH-5: weak secret (only for HS*)
        alg = header.get("alg", "")
        if alg.startswith("HS"):
            cracked = self._brute_force_secret(header, payload, raw)
            if cracked:
                findings.append(_make(
                    AuthFindingType.JWT_WEAK_SECRET,
                    f"El secret del JWT fue crackeado por diccionario: '{cracked}'",
                    f"JWT firmado con secret='{cracked}' (alg={alg}).",
                ))

        return findings

    def _brute_force_secret(self, header: dict, payload: dict, original_token: str) -> str | None:
        """Try to reproduce the original signature with common secrets."""
        import hmac, hashlib
        parts = original_token.split(".")
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        original_sig = parts[2]
        # Pad for base64
        padded = original_sig + "=" * (4 - len(original_sig) % 4)
        try:
            original_sig_bytes = base64.urlsafe_b64decode(padded)
        except Exception:
            return None

        alg = header.get("alg", "HS256")
        hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
        if not hash_fn:
            return None

        for secret in self.weak_secrets:
            candidate = hmac.new(secret.encode(), signing_input, hash_fn).digest()
            if hmac.compare_digest(candidate, original_sig_bytes):
                return secret
        return None

    # ── Per-endpoint checks ───────────────────

    def _check_endpoint(self, ep: Endpoint) -> list[AuthFinding]:
        findings: list[AuthFinding] = []
        url = re.sub(r"\{[^}]+\}", "1", ep.full_url)

        # AUTH-1: Missing auth — call WITHOUT token
        resp_no_auth = self._get_no_auth(url, ep.method)
        if resp_no_auth and resp_no_auth.status_code in (200, 201):
            # Heuristic: does the response look like it contains real data?
            if self._looks_like_data_response(resp_no_auth):
                findings.append(AuthFinding(
                    finding_type=AuthFindingType.MISSING_AUTH,
                    severity=FINDING_SEVERITY[AuthFindingType.MISSING_AUTH],
                    endpoint=ep.full_url,
                    method=ep.method,
                    description="El endpoint retorna datos sin requerir autenticación.",
                    proof=f"{ep.method} {url} sin token → HTTP {resp_no_auth.status_code}. "
                          f"Snippet: {resp_no_auth.text[:200]}",
                    remediation=FINDING_REMEDIATION[AuthFindingType.MISSING_AUTH],
                ))

        # AUTH-4: alg:none accepted — send a token with alg=none
        if self.valid_token and ep.requires_auth:
            raw = self.valid_token.replace("Bearer ", "").strip()
            decoded = decode_jwt_unsafe(raw)
            if decoded:
                _, payload = decoded
                none_token = make_alg_none_token(payload)
                resp_none = self._get_with_token(url, ep.method, f"Bearer {none_token}")
                if resp_none and resp_none.status_code in (200, 201):
                    findings.append(AuthFinding(
                        finding_type=AuthFindingType.JWT_ALG_NONE,
                        severity=FINDING_SEVERITY[AuthFindingType.JWT_ALG_NONE],
                        endpoint=ep.full_url,
                        method=ep.method,
                        description="El servidor aceptó un JWT con alg='none' (sin firma).",
                        proof=f"Token alg:none enviado → HTTP {resp_none.status_code}.",
                        remediation=FINDING_REMEDIATION[AuthFindingType.JWT_ALG_NONE],
                    ))

        # AUTH-7: expired token accepted
        if self.valid_token and ep.requires_auth:
            raw = self.valid_token.replace("Bearer ", "").strip()
            decoded = decode_jwt_unsafe(raw)
            if decoded:
                header, payload = decoded
                expired_payload = {**payload, "exp": int(time.time()) - 3600}
                alg = header.get("alg", "")
                # Only test if we can re-sign (weak secret known) or alg is none
                # For this check we just modify exp and send — server may still accept if not validated
                if alg.lower() == "none" or not alg:
                    expired_token = make_alg_none_token(expired_payload)
                    resp_expired = self._get_with_token(url, ep.method, f"Bearer {expired_token}")
                    if resp_expired and resp_expired.status_code in (200, 201):
                        findings.append(AuthFinding(
                            finding_type=AuthFindingType.EXPIRED_TOKEN_ACCEPTED,
                            severity=FINDING_SEVERITY[AuthFindingType.EXPIRED_TOKEN_ACCEPTED],
                            endpoint=ep.full_url,
                            method=ep.method,
                            description="El servidor aceptó un JWT expirado.",
                            proof=f"Token con exp en el pasado → HTTP {resp_expired.status_code}.",
                            remediation=FINDING_REMEDIATION[AuthFindingType.EXPIRED_TOKEN_ACCEPTED],
                        ))

        # AUTH-6: exposed secrets in response
        if resp_no_auth and resp_no_auth.status_code == 200:
            secret_findings = self._check_exposed_secrets(ep, resp_no_auth)
            findings.extend(secret_findings)
        elif self.valid_token:
            resp_auth = self._get_with_token(url, ep.method, self.valid_token)
            if resp_auth and resp_auth.status_code == 200:
                secret_findings = self._check_exposed_secrets(ep, resp_auth)
                findings.extend(secret_findings)

        return findings

    def _check_exposed_secrets(self, ep: Endpoint, resp: requests.Response) -> list[AuthFinding]:
        findings = []

        # Check response headers
        for header_name, header_value in resp.headers.items():
            if SENSITIVE_HEADERS.match(header_name):
                if TOKEN_VALUE_PATTERN.search(header_value):
                    findings.append(AuthFinding(
                        finding_type=AuthFindingType.EXPOSED_SECRET,
                        severity=FINDING_SEVERITY[AuthFindingType.EXPOSED_SECRET],
                        endpoint=ep.full_url,
                        method=ep.method,
                        description=f"Header de respuesta '{header_name}' contiene un valor que parece un secret/token.",
                        proof=f"Response header: {header_name}: {header_value[:80]}",
                        remediation=FINDING_REMEDIATION[AuthFindingType.EXPOSED_SECRET],
                    ))

        # Check response body (JSON)
        try:
            body = resp.json()
            self._scan_json_for_secrets(body, ep, findings)
        except Exception:
            pass

        return findings

    def _scan_json_for_secrets(
        self, obj: Any, ep: Endpoint, findings: list[AuthFinding], depth: int = 0
    ) -> None:
        if depth > 5:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if SENSITIVE_BODY_KEYS.search(str(k)) and isinstance(v, str):
                    if TOKEN_VALUE_PATTERN.search(v):
                        findings.append(AuthFinding(
                            finding_type=AuthFindingType.EXPOSED_SECRET,
                            severity=FINDING_SEVERITY[AuthFindingType.EXPOSED_SECRET],
                            endpoint=ep.full_url,
                            method=ep.method,
                            description=f"Campo '{k}' en response body contiene un valor que parece un secret.",
                            proof=f"Response body key '{k}': '{v[:80]}'",
                            remediation=FINDING_REMEDIATION[AuthFindingType.EXPOSED_SECRET],
                        ))
                else:
                    self._scan_json_for_secrets(v, ep, findings, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:10]:
                self._scan_json_for_secrets(item, ep, findings, depth + 1)

    # ── HTTP helpers ──────────────────────────

    def _get_no_auth(self, url: str, method: str) -> requests.Response | None:
        return self._request(self.session, method, url, token=None)

    def _get_with_token(self, url: str, method: str, token: str) -> requests.Response | None:
        return self._request(self.session, method, url, token=token)

    def _request(
        self, session: requests.Session, method: str, url: str, token: str | None
    ) -> requests.Response | None:
        headers = {}
        if token:
            headers["Authorization"] = token
        else:
            # Explicitly remove any stored Authorization header
            headers["Authorization"] = ""
        try:
            m = method.upper()
            kwargs = dict(timeout=self.timeout, headers=headers, allow_redirects=False)
            if m == "GET":
                return session.get(url, **kwargs)
            elif m == "POST":
                return session.post(url, json={}, **kwargs)
            elif m in ("PUT", "PATCH"):
                return session.request(m, url, json={}, **kwargs)
            elif m == "DELETE":
                return session.delete(url, **kwargs)
            else:
                return session.request(m, url, **kwargs)
        except requests.RequestException:
            return None

    @staticmethod
    def _looks_like_data_response(resp: requests.Response) -> bool:
        """Heuristic: is this a real data payload (not a 200 OK status page)?"""
        ct = resp.headers.get("Content-Type", "")
        if "application/json" in ct:
            try:
                body = resp.json()
                # Non-empty JSON object or array → likely real data
                return bool(body)
            except Exception:
                pass
        # Minimum size heuristic for non-JSON
        return len(resp.content) > 100
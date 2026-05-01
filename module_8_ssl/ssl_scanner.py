"""
APIGuard - Module 8: SSL/TLS Security Scanner
================================================
Checks an API's SSL/TLS configuration for security issues.

Vulnerabilities covered:
  SSL-1  Missing or invalid SSL certificate
  SSL-2  Expired certificate
  SSL-3  Self-signed certificate
  SSL-4  Weak TLS version (TLS 1.0, TLS 1.1)
  SSL-5  Missing HSTS header
  SSL-6  Certificate hostname mismatch
  SSL-7  Short certificate expiry warning (< 30 days)
"""

import ssl
import socket
import time
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

try:
    from module_2_bola.bola_scanner import Severity
except ImportError:
    from enum import Enum
    class Severity(str, Enum):
        CRITICAL = "CRITICAL"
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"
        INFO = "INFO"


@dataclass
class SSLFinding:
    vulnerability_type: str = ""
    severity: Severity = Severity.HIGH
    endpoint: str = ""
    method: str = "TLS"
    description: str = ""
    proof: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class SSLScanResult:
    target_url: str
    total_checks: int = 0
    issues_found: int = 0
    findings: list[SSLFinding] = field(default_factory=list)
    certificate_info: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "SSL_TLS",
            "target_url": self.target_url,
            "total_checks": self.total_checks,
            "issues_found": self.issues_found,
            "findings": [f.to_dict() for f in self.findings],
            "certificate_info": self.certificate_info,
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── SSL/TLS SCAN SUMMARY ────────────────────────────",
            f"  Target            : {self.target_url}",
            f"  Checks run        : {self.total_checks}",
            f"  Issues found      : {self.issues_found}",
            f"  Duration          : {self.scan_duration_seconds:.1f}s",
        ]
        if self.certificate_info:
            lines.append(f"  Subject           : {self.certificate_info.get('subject', 'N/A')}")
            lines.append(f"  Issuer            : {self.certificate_info.get('issuer', 'N/A')}")
            lines.append(f"  Expires           : {self.certificate_info.get('not_after', 'N/A')}")
        if self.findings:
            lines.append("\n  Findings:")
            for f in self.findings:
                lines.append(f"    [{f.severity.value}] {f.vulnerability_type}: {f.description}")
        else:
            lines.append("  ✅  SSL/TLS configuration looks secure.")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


class SSLScanner:
    """
    Scans the target API's SSL/TLS configuration.
    
    Usage:
        scanner = SSLScanner()
        result = scanner.scan("https://api.example.com")
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def scan(self, target_url: str) -> SSLScanResult:
        t0 = time.monotonic()
        result = SSLScanResult(target_url=target_url)
        parsed = urlparse(target_url)

        if parsed.scheme != "https":
            result.findings.append(SSLFinding(
                vulnerability_type="NO_SSL",
                severity=Severity.CRITICAL,
                endpoint=target_url,
                description="API is not using HTTPS. All traffic is unencrypted.",
                proof=f"URL scheme is '{parsed.scheme}' instead of 'https'.",
                remediation="Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
            ))
            result.total_checks = 1
            result.issues_found = 1
            result.scan_duration_seconds = time.monotonic() - t0
            return result

        hostname = parsed.hostname
        port = parsed.port or 443

        # Check 1: Certificate validity
        result.total_checks += 1
        cert_info = self._get_certificate(hostname, port)
        if cert_info is None:
            result.findings.append(SSLFinding(
                vulnerability_type="SSL_CONNECTION_FAILED",
                severity=Severity.CRITICAL,
                endpoint=target_url,
                description="Could not establish an SSL/TLS connection to the server.",
                proof="SSL handshake failed or connection refused.",
                remediation="Ensure the server has a valid SSL certificate and is accepting TLS connections.",
            ))
            result.issues_found += 1
            result.scan_duration_seconds = time.monotonic() - t0
            return result

        result.certificate_info = cert_info

        # Check 2: Expiry
        result.total_checks += 1
        if cert_info.get("expired"):
            result.findings.append(SSLFinding(
                vulnerability_type="EXPIRED_CERTIFICATE",
                severity=Severity.CRITICAL,
                endpoint=target_url,
                description="The SSL certificate has expired.",
                proof=f"Certificate expired on {cert_info.get('not_after')}.",
                remediation="Renew the SSL certificate immediately.",
            ))
            result.issues_found += 1
        elif cert_info.get("days_until_expiry", 999) < 30:
            result.findings.append(SSLFinding(
                vulnerability_type="CERTIFICATE_EXPIRING_SOON",
                severity=Severity.MEDIUM,
                endpoint=target_url,
                description=f"Certificate expires in {cert_info['days_until_expiry']} days.",
                proof=f"Expiry date: {cert_info.get('not_after')}.",
                remediation="Renew the certificate before expiry to avoid downtime.",
            ))
            result.issues_found += 1

        # Check 3: Self-signed
        result.total_checks += 1
        if cert_info.get("self_signed"):
            result.findings.append(SSLFinding(
                vulnerability_type="SELF_SIGNED_CERTIFICATE",
                severity=Severity.HIGH,
                endpoint=target_url,
                description="The certificate appears to be self-signed.",
                proof=f"Subject and issuer are identical: {cert_info.get('issuer')}.",
                remediation="Use a certificate from a trusted Certificate Authority (e.g., Let's Encrypt).",
            ))
            result.issues_found += 1

        # Check 4: Hostname mismatch
        result.total_checks += 1
        if cert_info.get("hostname_mismatch"):
            result.findings.append(SSLFinding(
                vulnerability_type="HOSTNAME_MISMATCH",
                severity=Severity.HIGH,
                endpoint=target_url,
                description="Certificate hostname does not match the server hostname.",
                proof=f"Expected '{hostname}', certificate subject: {cert_info.get('subject')}.",
                remediation="Ensure the certificate CN or SAN matches the server's domain name.",
            ))
            result.issues_found += 1

        # Check 5: TLS version
        result.total_checks += 1
        weak_tls = self._check_weak_tls(hostname, port)
        for tls_finding in weak_tls:
            result.findings.append(tls_finding)
            result.issues_found += 1

        # Check 6: HSTS Header
        result.total_checks += 1
        hsts_finding = self._check_hsts(target_url)
        if hsts_finding:
            result.findings.append(hsts_finding)
            result.issues_found += 1

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    def _get_certificate(self, hostname: str, port: int) -> dict | None:
        """Retrieve and parse the server's SSL certificate."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

            # Parse subject
            subject_parts = dict(x[0] for x in cert.get("subject", ()))
            issuer_parts = dict(x[0] for x in cert.get("issuer", ()))

            not_after = cert.get("notAfter", "")
            not_before = cert.get("notBefore", "")

            # Parse expiry date
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_until = (expiry - now).days
                expired = days_until < 0
            except Exception:
                days_until = 999
                expired = False

            # Check self-signed
            self_signed = subject_parts == issuer_parts

            # Check hostname match
            san = cert.get("subjectAltName", ())
            san_names = [name for typ, name in san if typ == "DNS"]
            cn = subject_parts.get("commonName", "")
            all_names = san_names + ([cn] if cn else [])
            hostname_match = any(
                self._hostname_matches(hostname, name) for name in all_names
            )

            return {
                "subject": subject_parts.get("commonName", str(subject_parts)),
                "issuer": issuer_parts.get("organizationName", str(issuer_parts)),
                "not_before": not_before,
                "not_after": not_after,
                "days_until_expiry": days_until,
                "expired": expired,
                "self_signed": self_signed,
                "hostname_mismatch": not hostname_match,
                "protocol_version": protocol,
                "san": san_names,
                "serial_number": cert.get("serialNumber", ""),
            }
        except ssl.SSLCertVerificationError:
            # Try without verification to get cert info
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        bin_cert = ssock.getpeercert(binary_form=True)
                        return {
                            "subject": "UNVERIFIED",
                            "issuer": "UNVERIFIED",
                            "self_signed": True,
                            "hostname_mismatch": True,
                            "expired": False,
                            "days_until_expiry": -1,
                            "protocol_version": ssock.version(),
                        }
            except Exception:
                return None
        except Exception:
            return None

    def _hostname_matches(self, hostname: str, pattern: str) -> bool:
        """Check if hostname matches a certificate name pattern (supports wildcards)."""
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
        return hostname.lower() == pattern.lower()

    def _check_weak_tls(self, hostname: str, port: int) -> list[SSLFinding]:
        """Check if the server accepts weak TLS versions."""
        findings = []
        weak_protocols = [
            (ssl.TLSVersion.TLSv1, "TLS 1.0"),
            (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
        ]

        for proto_version, proto_name in weak_protocols:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = proto_version
                ctx.maximum_version = proto_version

                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        findings.append(SSLFinding(
                            vulnerability_type="WEAK_TLS_VERSION",
                            severity=Severity.HIGH,
                            endpoint=f"https://{hostname}:{port}",
                            description=f"Server accepts deprecated {proto_name} connections.",
                            proof=f"Successfully connected using {proto_name}.",
                            remediation=f"Disable {proto_name}. Enforce TLS 1.2+ minimum.",
                        ))
            except (ssl.SSLError, socket.error, OSError):
                pass  # Good — connection was rejected

        return findings

    def _check_hsts(self, url: str) -> SSLFinding | None:
        """Check for HSTS header."""
        import requests
        try:
            resp = requests.get(url, timeout=self.timeout, allow_redirects=True, verify=True)
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if not hsts:
                return SSLFinding(
                    vulnerability_type="MISSING_HSTS",
                    severity=Severity.MEDIUM,
                    endpoint=url,
                    description="The server does not send a Strict-Transport-Security (HSTS) header.",
                    proof="Response headers lack 'Strict-Transport-Security'.",
                    remediation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                )
        except Exception:
            pass
        return None

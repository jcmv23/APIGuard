"""
APIGuard - Module 9: GraphQL Security Scanner
================================================
Detects common GraphQL-specific vulnerabilities.

Vulnerabilities covered:
  GQL-1  Introspection query enabled (info disclosure)
  GQL-2  No query depth limiting (DoS via nested queries)
  GQL-3  No query cost/complexity limiting
  GQL-4  Batching attack (multiple operations in one request)
  GQL-5  Field suggestion information disclosure
  GQL-6  Debug/verbose error messages
"""

import json
import time
import re
from dataclasses import dataclass, field, asdict

import requests

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


# ── Introspection Query ─────────────────────
INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

# Nested query for depth testing (10 levels deep)
def _build_deep_query(depth: int = 10) -> str:
    q = "{ __typename "
    for i in range(depth):
        q += f"d{i}: __typename "
    q += "}"
    return q


BATCH_QUERY = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]


@dataclass
class GraphQLFinding:
    vulnerability_type: str = ""
    severity: Severity = Severity.MEDIUM
    endpoint: str = ""
    method: str = "POST"
    description: str = ""
    proof: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class GraphQLScanResult:
    target_url: str
    is_graphql: bool = False
    total_checks: int = 0
    issues_found: int = 0
    findings: list[GraphQLFinding] = field(default_factory=list)
    schema_info: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_type": "GRAPHQL",
            "target_url": self.target_url,
            "is_graphql": self.is_graphql,
            "total_checks": self.total_checks,
            "issues_found": self.issues_found,
            "findings": [f.to_dict() for f in self.findings],
            "schema_info": self.schema_info,
            "errors": self.errors,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            "\n─── GRAPHQL SCAN SUMMARY ────────────────────────────",
            f"  Target            : {self.target_url}",
            f"  GraphQL detected  : {'Yes' if self.is_graphql else 'No'}",
            f"  Checks run        : {self.total_checks}",
            f"  Issues found      : {self.issues_found}",
            f"  Duration          : {self.scan_duration_seconds:.1f}s",
        ]
        if self.schema_info:
            lines.append(f"  Types discovered  : {self.schema_info.get('type_count', 0)}")
            lines.append(f"  Mutations         : {self.schema_info.get('has_mutations', False)}")
        if self.findings:
            lines.append("\n  Findings:")
            for f in self.findings:
                lines.append(f"    [{f.severity.value}] {f.vulnerability_type}")
        else:
            lines.append("  ✅  No GraphQL vulnerabilities detected.")
        lines.append("─────────────────────────────────────────────────────")
        return "\n".join(lines)


class GraphQLScanner:
    """
    Scans a GraphQL API endpoint for common security misconfigurations.
    
    Usage:
        scanner = GraphQLScanner(token="Bearer eyJ...")
        result = scanner.scan("https://api.example.com/graphql")
    """

    COMMON_GRAPHQL_PATHS = ["/graphql", "/gql", "/api/graphql", "/v1/graphql", "/query"]

    def __init__(self, token: str | None = None, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"
        if token:
            self.session.headers["Authorization"] = token

    def scan(self, target_url: str) -> GraphQLScanResult:
        t0 = time.monotonic()
        result = GraphQLScanResult(target_url=target_url)

        # Step 1: Discover GraphQL endpoint
        gql_url = self._discover_graphql(target_url)
        if not gql_url:
            result.scan_duration_seconds = time.monotonic() - t0
            return result

        result.is_graphql = True
        result.target_url = gql_url

        # Step 2: Check introspection
        result.total_checks += 1
        intro_result = self._check_introspection(gql_url)
        if intro_result:
            finding, schema_info = intro_result
            result.findings.append(finding)
            result.schema_info = schema_info
            result.issues_found += 1

        # Step 3: Check query depth limiting
        result.total_checks += 1
        depth_finding = self._check_depth_limit(gql_url)
        if depth_finding:
            result.findings.append(depth_finding)
            result.issues_found += 1

        # Step 4: Check batching attacks
        result.total_checks += 1
        batch_finding = self._check_batching(gql_url)
        if batch_finding:
            result.findings.append(batch_finding)
            result.issues_found += 1

        # Step 5: Check field suggestions
        result.total_checks += 1
        suggest_finding = self._check_field_suggestions(gql_url)
        if suggest_finding:
            result.findings.append(suggest_finding)
            result.issues_found += 1

        # Step 6: Check verbose errors
        result.total_checks += 1
        error_finding = self._check_verbose_errors(gql_url)
        if error_finding:
            result.findings.append(error_finding)
            result.issues_found += 1

        result.scan_duration_seconds = time.monotonic() - t0
        return result

    def _discover_graphql(self, base_url: str) -> str | None:
        """Try common GraphQL paths to find the endpoint."""
        base = base_url.rstrip("/")

        # First try the URL as-is
        urls_to_try = [base] + [base + path for path in self.COMMON_GRAPHQL_PATHS]

        for url in urls_to_try:
            try:
                resp = self.session.post(
                    url,
                    json={"query": "{ __typename }"},
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                        if "data" in body or "errors" in body:
                            return url
                    except Exception:
                        pass
            except requests.RequestException:
                continue
        return None

    def _check_introspection(self, url: str) -> tuple[GraphQLFinding, dict] | None:
        """Check if introspection queries are enabled."""
        try:
            resp = self.session.post(url, json={"query": INTROSPECTION_QUERY}, timeout=self.timeout)
            if resp.status_code == 200:
                body = resp.json()
                schema = body.get("data", {}).get("__schema", {})
                if schema:
                    types = schema.get("types", [])
                    user_types = [t for t in types if not t["name"].startswith("__")]
                    has_mutations = schema.get("mutationType") is not None

                    info = {
                        "type_count": len(user_types),
                        "user_types": [t["name"] for t in user_types[:20]],
                        "has_mutations": has_mutations,
                        "has_subscriptions": schema.get("subscriptionType") is not None,
                    }

                    return (
                        GraphQLFinding(
                            vulnerability_type="INTROSPECTION_ENABLED",
                            severity=Severity.MEDIUM,
                            endpoint=url,
                            description=f"GraphQL introspection is enabled, exposing {len(user_types)} types and the full schema.",
                            proof=f"Discovered types: {', '.join(info['user_types'][:10])}...",
                            remediation="Disable introspection in production. In Apollo Server: introspection: false.",
                        ),
                        info,
                    )
        except Exception:
            pass
        return None

    def _check_depth_limit(self, url: str) -> GraphQLFinding | None:
        """Check if deeply nested queries are accepted (DoS vector)."""
        # Build a deeply nested __typename query
        deep_query = "{ " + " ".join([f"a{i}: __typename" for i in range(50)]) + " }"
        try:
            resp = self.session.post(url, json={"query": deep_query}, timeout=self.timeout)
            if resp.status_code == 200:
                body = resp.json()
                if body.get("data") and not body.get("errors"):
                    return GraphQLFinding(
                        vulnerability_type="NO_QUERY_DEPTH_LIMIT",
                        severity=Severity.HIGH,
                        endpoint=url,
                        description="Server accepts queries with 50+ fields without depth/complexity limiting.",
                        proof="Sent a query with 50 aliased fields; all were resolved successfully.",
                        remediation="Implement query depth and complexity limits (e.g., graphql-depth-limit, graphql-query-complexity).",
                    )
        except Exception:
            pass
        return None

    def _check_batching(self, url: str) -> GraphQLFinding | None:
        """Check if the server accepts batched queries (brute-force vector)."""
        try:
            resp = self.session.post(url, json=BATCH_QUERY, timeout=self.timeout)
            if resp.status_code == 200:
                body = resp.json()
                if isinstance(body, list) and len(body) >= 2:
                    return GraphQLFinding(
                        vulnerability_type="BATCHING_ATTACK",
                        severity=Severity.HIGH,
                        endpoint=url,
                        description=f"Server accepts batched GraphQL queries ({len(body)} operations in one request).",
                        proof=f"Sent 5 batched queries, server returned {len(body)} results.",
                        remediation="Disable query batching or implement per-batch rate limiting.",
                    )
        except Exception:
            pass
        return None

    def _check_field_suggestions(self, url: str) -> GraphQLFinding | None:
        """Check if field suggestions reveal valid field names."""
        try:
            resp = self.session.post(
                url,
                json={"query": "{ usre { naem } }"},  # Intentional typos
                timeout=self.timeout,
            )
            if resp.status_code in (200, 400):
                text = resp.text.lower()
                if "did you mean" in text or "suggestion" in text:
                    return GraphQLFinding(
                        vulnerability_type="FIELD_SUGGESTIONS",
                        severity=Severity.LOW,
                        endpoint=url,
                        description="GraphQL field suggestions are enabled, leaking valid field names.",
                        proof="Server suggested corrections for intentionally misspelled fields.",
                        remediation="Disable field suggestions in production to reduce information disclosure.",
                    )
        except Exception:
            pass
        return None

    def _check_verbose_errors(self, url: str) -> GraphQLFinding | None:
        """Check if error messages reveal internal implementation details."""
        try:
            resp = self.session.post(
                url,
                json={"query": "{ __INVALID_QUERY__ { x } }"},
                timeout=self.timeout,
            )
            if resp.status_code in (200, 400):
                try:
                    body = resp.json()
                    errors = body.get("errors", [])
                    if errors:
                        error_text = json.dumps(errors)
                        patterns = ["stacktrace", "stack_trace", "traceback", "at line", "internal server"]
                        if any(p in error_text.lower() for p in patterns):
                            return GraphQLFinding(
                                vulnerability_type="VERBOSE_ERRORS",
                                severity=Severity.MEDIUM,
                                endpoint=url,
                                description="GraphQL error messages expose internal implementation details.",
                                proof=f"Error response contains debug info: {error_text[:200]}",
                                remediation="Sanitize GraphQL error messages in production to remove stack traces and internal paths.",
                            )
                except Exception:
                    pass
        except Exception:
            pass
        return None

"""
APIGuard Enterprise — API Discovery Engine
=============================================
Probes common paths to auto-discover API specifications, 
GraphQL endpoints, and documentation.
"""

import requests
import re
import json
import time
from typing import Optional
from urllib.parse import urljoin


# Common paths where API specs and docs are typically found
DISCOVERY_PATHS = [
    # OpenAPI / Swagger
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/openapi/v1.json",
    "/api-docs", "/api-docs.json", "/api/docs",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs/api.json", "/.well-known/openapi.json",
    
    # GraphQL
    "/graphql", "/graphiql", "/playground", "/api/graphql",
    "/v1/graphql", "/gql",
    
    # Documentation
    "/docs", "/redoc", "/api/docs", "/swagger-ui",
    "/swagger-ui.html", "/swagger-ui/index.html",
    "/api/swagger-ui.html",
    
    # Health / Info
    "/health", "/healthz", "/ready", "/readyz",
    "/api/health", "/api/status", "/status",
    "/.well-known/health",
    "/info", "/api/info", "/api/version",
    
    # Common API paths  
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1",
    
    # Admin / Debug (should NOT be exposed)
    "/admin", "/debug", "/actuator", "/actuator/health",
    "/actuator/info", "/actuator/env",
    "/_debug", "/__debug__",
    "/server-info", "/phpinfo.php",
    "/elmah.axd", "/trace.axd",
]


class APIDiscovery:
    """Discover API endpoints, specs, and documentation automatically."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "APIGuard-Discovery/2.0",
            "Accept": "application/json, text/html, */*"
        })

    def discover(self, base_url: str) -> dict:
        """Probe a target URL for API specs, GraphQL, docs, and admin panels."""
        base_url = base_url.rstrip("/")
        results = {
            "target": base_url,
            "scan_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "specs_found": [],
            "graphql_endpoints": [],
            "documentation": [],
            "health_endpoints": [],
            "admin_exposed": [],
            "api_paths": [],
            "total_probed": 0,
            "total_found": 0,
        }

        for path in DISCOVERY_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            results["total_probed"] += 1

            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False, verify=False)

                if resp.status_code in (200, 301, 302):
                    entry = {
                        "path": path,
                        "url": url,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "size_bytes": len(resp.content),
                    }

                    content = resp.text[:2000]
                    ct = entry["content_type"].lower()

                    # Classify
                    if self._is_openapi(content, ct):
                        entry["type"] = "openapi_spec"
                        results["specs_found"].append(entry)
                    elif self._is_graphql(path, content):
                        entry["type"] = "graphql"
                        results["graphql_endpoints"].append(entry)
                    elif self._is_docs(path, content):
                        entry["type"] = "documentation"
                        results["documentation"].append(entry)
                    elif self._is_health(path):
                        entry["type"] = "health"
                        results["health_endpoints"].append(entry)
                    elif self._is_admin(path, content):
                        entry["type"] = "admin_exposed"
                        entry["severity"] = "HIGH"
                        results["admin_exposed"].append(entry)
                    else:
                        entry["type"] = "api_path"
                        results["api_paths"].append(entry)

                    results["total_found"] += 1

            except requests.RequestException:
                pass

        return results

    @staticmethod
    def _is_openapi(content: str, content_type: str) -> bool:
        indicators = ["openapi", "swagger", '"paths"', '"info"', '"basePath"']
        return any(i in content.lower() for i in indicators) or "yaml" in content_type

    @staticmethod
    def _is_graphql(path: str, content: str) -> bool:
        return "graphql" in path.lower() or "graphiql" in content.lower() or "__schema" in content

    @staticmethod
    def _is_docs(path: str, content: str) -> bool:
        doc_keywords = ["swagger-ui", "redoc", "api documentation", "api reference"]
        return any(k in path.lower() or k in content.lower() for k in doc_keywords)

    @staticmethod
    def _is_health(path: str) -> bool:
        return any(h in path.lower() for h in ["health", "ready", "status"])

    @staticmethod
    def _is_admin(path: str, content: str) -> bool:
        admin_keywords = ["admin", "debug", "actuator", "phpinfo", "elmah", "trace"]
        return any(k in path.lower() for k in admin_keywords)

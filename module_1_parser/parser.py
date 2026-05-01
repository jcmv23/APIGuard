"""
APIGuard - Module 1: OpenAPI/Swagger Parser
============================================
Parses an OpenAPI 3.0 or Swagger 2.0 spec (from URL or file) and
returns a normalized list of endpoints ready for the scanners.
"""

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import yaml


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class Parameter:
    name: str
    location: str          # path | query | header | body | cookie
    required: bool
    param_type: str        # string | integer | boolean | object | array
    param_format: str      # int64 | date-time | uuid | password …
    example: Any = None


@dataclass
class Endpoint:
    method: str            # GET POST PUT PATCH DELETE …
    path: str              # /api/users/{id}
    full_url: str          # https://api.example.com/api/users/{id}
    summary: str
    tags: list[str]
    parameters: list[Parameter] = field(default_factory=list)
    request_body_schema: dict = field(default_factory=dict)
    response_schema: dict = field(default_factory=dict)
    requires_auth: bool = False
    security_schemes: list[str] = field(default_factory=list)

    # Convenience helpers
    def path_params(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == "path"]

    def query_params(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == "query"]

    def is_resource_endpoint(self) -> bool:
        """True if path contains a variable – likely returns a specific object."""
        return bool(re.search(r"\{[^}]+\}", self.path))

    def looks_like_admin(self) -> bool:
        """True if path/tags suggest elevated-privilege operations."""
        admin_patterns = [
            r"/admin", r"/internal", r"/system", r"/management",
            r"/superuser", r"/root", r"/staff"
        ]
        combined = (self.path + " " + " ".join(self.tags)).lower()
        if any(re.search(p, combined) for p in admin_patterns):
            return True
        sensitive_methods = {"DELETE", "PURGE"}
        if self.method.upper() in sensitive_methods:
            return True
        sensitive_words = ["reset", "purge", "delete", "revoke", "ban", "disable"]
        path_lower = self.path.lower()
        return any(w in path_lower for w in sensitive_words)


# ─────────────────────────────────────────────
# Core parser
# ─────────────────────────────────────────────

class OpenAPIParser:
    """
    Accepts a base API URL and/or a raw spec (dict / YAML string / file path)
    and produces a list of Endpoint objects.
    """

    DISCOVERY_PATHS = [
        "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
        "/api-docs", "/api/openapi.json", "/api/swagger.json",
        "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
        "/docs/openapi.json",
    ]

    def __init__(self, base_url: str = "", spec=None, timeout: int = 10):
        self.timeout = timeout
        self._raw_spec: dict = {}
        self._spec_version: str = "unknown"
        self.endpoints: list[Endpoint] = []
        
        # If user passed a spec URL as the base URL, treat it as spec, and derive true base_url later
        if spec is None and base_url and (base_url.endswith(".json") or base_url.endswith(".yaml") or "swagger" in base_url.lower() or "openapi" in base_url.lower()):
            if base_url.startswith("http"):
                spec = base_url
                base_url = "" # Reset to allow derivation from spec

        self.base_url = base_url.rstrip("/") if base_url else ""

        if spec is not None:
            self._raw_spec = self._load_spec(spec)
        elif self.base_url:
            self._raw_spec = self._discover_spec(self.base_url)

    # ── Loading ────────────────────────────────

    def _load_spec(self, spec) -> dict:
        if isinstance(spec, dict):
            return spec
        if isinstance(spec, str):
            # Is it a URL?
            if spec.startswith("http://") or spec.startswith("https://"):
                import requests
                try:
                    r = requests.get(spec, timeout=self.timeout)
                    r.raise_for_status()
                    try:
                        return r.json()
                    except json.JSONDecodeError:
                        return yaml.safe_load(r.text)
                except requests.RequestException as e:
                    raise ValueError(f"Failed to fetch spec from URL: {e}")
            
            # File path?
            try:
                with open(spec, "r", encoding="utf-8") as fh:
                    return yaml.safe_load(fh)
            except (FileNotFoundError, OSError):
                pass
            # Raw text (YAML or JSON)
            try:
                parsed = yaml.safe_load(spec)
                if isinstance(parsed, dict):
                    return parsed
            except yaml.YAMLError:
                pass
            try:
                parsed = json.loads(spec)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
        raise ValueError(f"Cannot load spec from: {type(spec)}")

    def _discover_spec(self, base_url: str) -> dict:
        # Check the base URL itself in case it is the spec
        urls = [base_url] + [base_url.rstrip("/") + path for path in self.DISCOVERY_PATHS]
        
        for url in urls:
            try:
                r = requests.get(url, timeout=self.timeout)
                if r.status_code == 200 and r.content:
                    try:
                        parsed = r.json()
                        if "openapi" in parsed or "swagger" in parsed:
                            return parsed
                    except Exception:
                        pass
                    try:
                        parsed = yaml.safe_load(r.text)
                        if isinstance(parsed, dict) and ("openapi" in parsed or "swagger" in parsed):
                            return parsed
                    except Exception:
                        pass
            except requests.RequestException:
                continue
        # No spec found — return empty dict to allow probe-based scanning
        return {}

    # ── Parsing ────────────────────────────────

    def parse(self) -> list[Endpoint]:
        """Parse the raw spec and return the list of Endpoint objects.
        If no spec is available, probe the base URL for common API endpoints."""
        if not self._raw_spec:
            # No spec found — probe the target to discover endpoints dynamically
            if self.base_url:
                self.endpoints = self._probe_endpoints(self.base_url)
                self._spec_version = "probed"
                return self.endpoints
            raise RuntimeError("No spec loaded and no base URL provided.")

        # Detect version
        if "openapi" in self._raw_spec:
            self._spec_version = self._raw_spec["openapi"]
            self.endpoints = self._parse_openapi3()
        elif "swagger" in self._raw_spec:
            self._spec_version = self._raw_spec["swagger"]
            self.endpoints = self._parse_swagger2()
        else:
            raise ValueError("Unrecognised spec format (missing 'openapi' or 'swagger' key).")

        return self.endpoints

    # ── OpenAPI 3.x ───────────────────────────

    def _parse_openapi3(self) -> list[Endpoint]:
        spec = self._raw_spec
        endpoints: list[Endpoint] = []

        # Resolve base URL from servers[] if not provided
        if not self.base_url:
            servers = spec.get("servers", [])
            if servers:
                self.base_url = servers[0].get("url", "").rstrip("/")

        global_security = spec.get("security", [])
        security_schemes = list(spec.get("components", {}).get("securitySchemes", {}).keys())

        for path, path_item in spec.get("paths", {}).items():
            path_level_params = self._parse_params_v3(
                path_item.get("parameters", []), spec
            )
            for method, operation in path_item.items():
                if method.upper() not in {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"}:
                    continue
                if not isinstance(operation, dict):
                    continue

                op_security = operation.get("security", global_security)
                requires_auth = bool(op_security)

                op_params = self._parse_params_v3(
                    operation.get("parameters", []), spec
                )
                # path-level params are defaults; operation-level override
                merged_params = {p.name: p for p in path_level_params}
                merged_params.update({p.name: p for p in op_params})

                req_body_schema = {}
                if "requestBody" in operation:
                    req_body_schema = self._extract_schema_v3(
                        operation["requestBody"], spec
                    )

                resp_schema = {}
                responses = operation.get("responses", {})
                for code in ("200", "201", "default"):
                    if code in responses:
                        resp_schema = self._extract_response_schema_v3(
                            responses[code], spec
                        )
                        break

                endpoint = Endpoint(
                    method=method.upper(),
                    path=path,
                    full_url=self.base_url + path,
                    summary=operation.get("summary", operation.get("operationId", "")),
                    tags=operation.get("tags", []),
                    parameters=list(merged_params.values()),
                    request_body_schema=req_body_schema,
                    response_schema=resp_schema,
                    requires_auth=requires_auth,
                    security_schemes=security_schemes if requires_auth else [],
                )
                endpoints.append(endpoint)

        return endpoints

    def _parse_params_v3(self, params: list, spec: dict) -> list[Parameter]:
        result = []
        for p in params:
            p = self._resolve_ref(p, spec)
            schema = p.get("schema", {})
            result.append(Parameter(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                required=p.get("required", False),
                param_type=schema.get("type", "string"),
                param_format=schema.get("format", ""),
                example=p.get("example", schema.get("example")),
            ))
        return result

    def _extract_schema_v3(self, request_body: dict, spec: dict) -> dict:
        content = request_body.get("content", {})
        for media_type in ("application/json", "application/x-www-form-urlencoded"):
            if media_type in content:
                schema = content[media_type].get("schema", {})
                return self._resolve_ref(schema, spec)
        return {}

    def _extract_response_schema_v3(self, response: dict, spec: dict) -> dict:
        content = response.get("content", {})
        if "application/json" in content:
            schema = content["application/json"].get("schema", {})
            return self._resolve_ref(schema, spec)
        return {}

    # ── Swagger 2.x ───────────────────────────

    def _parse_swagger2(self) -> list[Endpoint]:
        spec = self._raw_spec
        endpoints: list[Endpoint] = []

        if not self.base_url:
            host = spec.get("host", "")
            scheme = (spec.get("schemes") or ["https"])[0]
            base_path = spec.get("basePath", "")
            if host:
                self.base_url = f"{scheme}://{host}{base_path}"

        global_security = spec.get("security", [])
        security_defs = list(spec.get("securityDefinitions", {}).keys())

        for path, path_item in spec.get("paths", {}).items():
            path_level_params = self._parse_params_v2(
                path_item.get("parameters", []), spec
            )
            for method, operation in path_item.items():
                if method.upper() not in {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"}:
                    continue
                if not isinstance(operation, dict):
                    continue

                op_security = operation.get("security", global_security)
                requires_auth = bool(op_security)

                op_params = self._parse_params_v2(
                    operation.get("parameters", []), spec
                )
                merged_params = {p.name: p for p in path_level_params}
                merged_params.update({p.name: p for p in op_params})

                # body param
                req_body_schema = {}
                body_params = [p for p in merged_params.values() if p.location == "body"]
                if body_params:
                    req_body_schema = {"type": "object", "body_param": body_params[0].name}

                resp_schema = {}
                for code in ("200", "201", "default"):
                    resp = operation.get("responses", {}).get(code, {})
                    if resp:
                        schema = resp.get("schema", {})
                        resp_schema = self._resolve_ref(schema, spec)
                        break

                endpoint = Endpoint(
                    method=method.upper(),
                    path=path,
                    full_url=self.base_url + path,
                    summary=operation.get("summary", operation.get("operationId", "")),
                    tags=operation.get("tags", []),
                    parameters=[p for p in merged_params.values() if p.location != "body"],
                    request_body_schema=req_body_schema,
                    response_schema=resp_schema,
                    requires_auth=requires_auth,
                    security_schemes=security_defs if requires_auth else [],
                )
                endpoints.append(endpoint)

        return endpoints

    def _parse_params_v2(self, params: list, spec: dict) -> list[Parameter]:
        result = []
        for p in params:
            p = self._resolve_ref(p, spec)
            result.append(Parameter(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                required=p.get("required", False),
                param_type=p.get("type", "string"),
                param_format=p.get("format", ""),
                example=None,
            ))
        return result

    # ── Helpers ────────────────────────────────

    def _resolve_ref(self, obj: dict, spec: dict) -> dict:
        """Follow a single $ref and return the resolved dict."""
        if not isinstance(obj, dict):
            return obj
        ref = obj.get("$ref")
        if not ref:
            return obj
        parts = ref.lstrip("#/").split("/")
        result = spec
        for part in parts:
            result = result.get(part, {})
        return result

    # ── Probe-based discovery (no spec needed) ──

    PROBE_PATHS = [
        # Common REST patterns
        "/", "/api", "/api/v1", "/api/v2",
        "/users", "/api/users", "/api/v1/users",
        "/posts", "/api/posts", "/api/v1/posts",
        "/products", "/api/products",
        "/items", "/api/items",
        "/auth", "/api/auth", "/auth/login", "/api/auth/login",
        "/login", "/register", "/api/login", "/api/register",
        "/todos", "/comments", "/albums", "/photos",
        "/categories", "/orders", "/carts",
        "/health", "/status", "/info", "/version",
        # Specific resource IDs
        "/users/1", "/posts/1", "/products/1", "/todos/1", "/comments/1",
        "/api/users/1", "/api/posts/1",
    ]

    def _probe_endpoints(self, base_url: str) -> list[Endpoint]:
        """Probe common API paths to discover working endpoints."""
        found: list[Endpoint] = []
        session = requests.Session()
        session.headers.update({"User-Agent": "APIGuard/2.0", "Accept": "application/json"})

        for path in self.PROBE_PATHS:
            url = base_url.rstrip("/") + path
            try:
                r = session.get(url, timeout=self.timeout, allow_redirects=False)
                if r.status_code in (200, 201, 301, 302):
                    ct = r.headers.get("Content-Type", "")
                    is_api = "json" in ct or "xml" in ct or "text/plain" in ct
                    if is_api or r.status_code in (301, 302):
                        found.append(Endpoint(
                            method="GET",
                            path=path,
                            full_url=url,
                            summary=f"Probed: {r.status_code} ({ct.split(';')[0]})",
                            tags=["probed"],
                            parameters=[],
                            requires_auth=False,
                        ))
            except requests.RequestException:
                continue

        # Also try POST/PUT/DELETE on discovered resource paths
        for ep in list(found):
            if any(p in ep.path for p in ["/users", "/posts", "/products", "/items", "/todos", "/carts", "/orders"]):
                if not ep.path.endswith(("1", "2", "3")):
                    for method in ["POST"]:
                        found.append(Endpoint(
                            method=method,
                            path=ep.path,
                            full_url=ep.full_url,
                            summary=f"Inferred {method} (from GET probe)",
                            tags=["probed", "inferred"],
                            parameters=[],
                            requires_auth=False,
                        ))
                else:
                    for method in ["PUT", "DELETE"]:
                        found.append(Endpoint(
                            method=method,
                            path=ep.path,
                            full_url=ep.full_url,
                            summary=f"Inferred {method} (from resource probe)",
                            tags=["probed", "inferred"],
                            parameters=[],
                            requires_auth=False,
                        ))

        return found

    # ── Export ────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "spec_version": self._spec_version,
            "total_endpoints": len(self.endpoints),
            "endpoints": [asdict(ep) for ep in self.endpoints],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def summary(self) -> str:
        lines = [
            f"Base URL      : {self.base_url}",
            f"Spec version  : {self._spec_version}",
            f"Total endpoints: {len(self.endpoints)}",
            "",
        ]
        for ep in self.endpoints:
            auth_flag = "🔒" if ep.requires_auth else "🔓"
            lines.append(f"  {auth_flag} {ep.method:<7} {ep.full_url}")
        return "\n".join(lines)